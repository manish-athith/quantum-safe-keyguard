"""Train and export the contextual multi-task LSTM detector."""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from quantum_keyguard.detection.contextual_lstm import ContextualLSTMDetector
from quantum_keyguard.domain.enums import Algorithm, AuditAction, EventOutcome, Role

PAD = "<PAD>"
START = "<START>"
UNKNOWN = "<UNKNOWN>"
NONE = "<NONE>"
SEQUENCE_WEIGHT = 0.4
ATTACK_WEIGHT = 0.6


@dataclass(frozen=True)
class ContextualTrainingConfig:
    sessions_path: Path = Path("data/processed/sessions.jsonl")
    output_path: Path = Path("artifacts/contextual_lstm_detector.json")
    epochs: int = 8
    batch_size: int = 256
    action_embedding_size: int = 16
    role_embedding_size: int = 5
    algorithm_embedding_size: int = 5
    outcome_embedding_size: int = 4
    hidden_size: int = 32
    learning_rate: float = 0.008
    anomaly_loss_weight: float = 0.7
    seed: int = 20_261_017


def _vocabularies() -> dict[str, list[str]]:
    return {
        "action": [PAD, START, UNKNOWN] + sorted(item.value for item in AuditAction),
        "role": [UNKNOWN] + sorted(item.value for item in Role),
        "algorithm": [NONE, UNKNOWN] + sorted(item.value for item in Algorithm),
        "outcome": [START, UNKNOWN] + sorted(item.value for item in EventOutcome),
    }


def _metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, float | int]:
    predictions = [int(score >= threshold) for score in scores]
    tp = sum(prediction == 1 and label == 1 for prediction, label in zip(predictions, labels, strict=True))
    tn = sum(prediction == 0 and label == 0 for prediction, label in zip(predictions, labels, strict=True))
    fp = sum(prediction == 1 and label == 0 for prediction, label in zip(predictions, labels, strict=True))
    fn = sum(prediction == 0 and label == 1 for prediction, label in zip(predictions, labels, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "accuracy": (tp + tn) / len(labels) if labels else 0.0,
        "balanced_accuracy": (recall + specificity) / 2.0,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def _choose_threshold(labels: Sequence[int], scores: Sequence[float]) -> tuple[float, dict[str, float | int]]:
    ordered = sorted(set(float(score) for score in scores))
    stride = max(1, len(ordered) // 500)
    candidates = [max(0.0, ordered[0] - 1e-9)]
    candidates.extend(ordered[index] for index in range(0, len(ordered), stride))
    candidates.append(min(1.0, ordered[-1] + 1e-9))
    ranked: list[tuple[float, float, float, float, dict[str, float | int]]] = []
    for threshold in candidates:
        result = _metrics(labels, scores, threshold)
        ranked.append(
            (
                float(result["f1"]),
                -float(result["false_positive_rate"]),
                float(result["recall"]),
                -threshold,
                result,
            )
        )
    best = max(ranked)
    return -best[3], best[4]


def _roc_auc(labels: Sequence[int], scores: Sequence[float]) -> float:
    pairs = sorted(zip(scores, labels, strict=True), key=lambda item: item[0])
    positive = sum(labels)
    negative = len(labels) - positive
    if not positive or not negative:
        return 0.0
    rank_sum = 0.0
    index = 0
    while index < len(pairs):
        end = index + 1
        while end < len(pairs) and pairs[end][0] == pairs[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in pairs[index:end])
        index = end
    return (rank_sum - positive * (positive + 1) / 2.0) / (positive * negative)


def _average_precision(labels: Sequence[int], scores: Sequence[float]) -> float:
    positive = sum(labels)
    if not positive:
        return 0.0
    true_positive = 0
    precision_sum = 0.0
    for rank, (_, label) in enumerate(
        sorted(zip(scores, labels, strict=True), key=lambda item: item[0], reverse=True),
        start=1,
    ):
        if label:
            true_positive += 1
            precision_sum += true_positive / rank
    return precision_sum / positive


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if not rows:
        raise ValueError("session dataset is empty")
    return rows


def train_and_export(config: ContextualTrainingConfig) -> dict[str, Any]:
    try:
        import torch
        from torch import nn
        from torch.nn import functional as functional
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError as error:
        raise RuntimeError("PyTorch is required for contextual training on the laptop") from error

    random.seed(config.seed)
    torch.manual_seed(config.seed)
    torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))
    torch.use_deterministic_algorithms(True)

    rows = _load_rows(config.sessions_path)
    vocabularies = _vocabularies()
    indices = {
        name: {token: index for index, token in enumerate(values)}
        for name, values in vocabularies.items()
    }
    maximum_length = max(len(row["actions"]) for row in rows)
    interval_log_scale = math.log1p(300.0)

    def encode(selected: Sequence[dict[str, Any]]) -> tuple[Any, ...]:
        previous_actions: list[list[int]] = []
        roles: list[list[int]] = []
        algorithms: list[list[int]] = []
        previous_outcomes: list[list[int]] = []
        numeric_features: list[list[list[float]]] = []
        targets: list[list[int]] = []
        anomaly_targets: list[list[float]] = []
        lengths: list[int] = []
        labels: list[int] = []

        for row in selected:
            actions = [str(item) for item in row["actions"]]
            length = len(actions)
            if not length:
                raise ValueError("session actions cannot be empty")
            lengths.append(length)
            label = int(row["label"] == "anomalous")
            labels.append(label)
            role_index = indices["role"].get(str(row["role"]), indices["role"][UNKNOWN])
            hours = row["hours"]
            intervals = row["interval_seconds"]
            devices = row["is_new_device"]
            row_algorithms = row["algorithms"]
            outcomes = [str(item) for item in row["outcomes"]]
            if not all(len(items) == length for items in (hours, intervals, devices, row_algorithms, outcomes)):
                raise ValueError("context features must align with actions")

            action_input = [indices["action"][START]]
            action_input.extend(
                indices["action"].get(action, indices["action"][UNKNOWN])
                for action in actions[:-1]
            )
            outcome_input = [indices["outcome"][START]]
            outcome_input.extend(
                indices["outcome"].get(outcome, indices["outcome"][UNKNOWN])
                for outcome in outcomes[:-1]
            )
            algorithm_input = [
                indices["algorithm"].get(
                    str(algorithm) if algorithm is not None else NONE,
                    indices["algorithm"][UNKNOWN],
                )
                for algorithm in row_algorithms
            ]
            denied_count = 0
            numbers: list[list[float]] = []
            for position in range(length):
                hour = int(hours[position]) % 24
                numbers.append(
                    [
                        math.sin(2.0 * math.pi * hour / 24.0),
                        math.cos(2.0 * math.pi * hour / 24.0),
                        min(math.log1p(max(0.0, float(intervals[position]))) / interval_log_scale, 2.0),
                        1.0 if bool(devices[position]) else 0.0,
                        min(denied_count / 5.0, 1.0),
                        min((position + 1) / maximum_length, 1.0),
                    ]
                )
                if outcomes[position] in {"denied", "failed"}:
                    denied_count += 1

            onset = row.get("attack_start_index")
            anomaly_row = [
                1.0 if label and onset is not None and position >= int(onset) else 0.0
                for position in range(length)
            ]
            padding = maximum_length - length
            previous_actions.append(action_input + [indices["action"][PAD]] * padding)
            roles.append([role_index] * length + [indices["role"][UNKNOWN]] * padding)
            algorithms.append(algorithm_input + [indices["algorithm"][NONE]] * padding)
            previous_outcomes.append(outcome_input + [indices["outcome"][START]] * padding)
            numeric_features.append(numbers + [[0.0] * 6 for _ in range(padding)])
            targets.append(
                [indices["action"].get(action, indices["action"][UNKNOWN]) for action in actions]
                + [-100] * padding
            )
            anomaly_targets.append(anomaly_row + [0.0] * padding)

        return (
            torch.tensor(previous_actions, dtype=torch.long),
            torch.tensor(roles, dtype=torch.long),
            torch.tensor(algorithms, dtype=torch.long),
            torch.tensor(previous_outcomes, dtype=torch.long),
            torch.tensor(numeric_features, dtype=torch.float32),
            torch.tensor(targets, dtype=torch.long),
            torch.tensor(anomaly_targets, dtype=torch.float32),
            torch.tensor(lengths, dtype=torch.long),
            torch.tensor(labels, dtype=torch.long),
        )

    class ContextualLSTM(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.action_embedding = nn.Embedding(
                len(vocabularies["action"]), config.action_embedding_size
            )
            self.role_embedding = nn.Embedding(
                len(vocabularies["role"]), config.role_embedding_size
            )
            self.algorithm_embedding = nn.Embedding(
                len(vocabularies["algorithm"]), config.algorithm_embedding_size
            )
            self.outcome_embedding = nn.Embedding(
                len(vocabularies["outcome"]), config.outcome_embedding_size
            )
            input_size = (
                config.action_embedding_size
                + config.role_embedding_size
                + config.algorithm_embedding_size
                + config.outcome_embedding_size
                + 6
            )
            self.lstm = nn.LSTM(input_size, config.hidden_size, batch_first=True)
            self.next_action = nn.Linear(config.hidden_size, len(vocabularies["action"]))
            self.anomaly = nn.Linear(config.hidden_size, 1)

        def forward(self, batch: tuple[Any, ...]) -> tuple[Any, Any]:
            action_input, role_input, algorithm_input, outcome_input, numeric = batch[:5]
            features = torch.cat(
                (
                    self.action_embedding(action_input),
                    self.role_embedding(role_input),
                    self.algorithm_embedding(algorithm_input),
                    self.outcome_embedding(outcome_input),
                    numeric,
                ),
                dim=-1,
            )
            hidden, _ = self.lstm(features)
            return self.next_action(hidden), self.anomaly(hidden).squeeze(-1)

    training_rows = [row for row in rows if row["split"] == "train"]
    validation_rows = [row for row in rows if row["split"] == "validation"]
    test_rows = [row for row in rows if row["split"] == "test"]
    training_tensors = encode(training_rows)
    positive_steps = float(training_tensors[6].sum())
    valid_steps = float(training_tensors[5].ne(-100).sum())
    negative_steps = valid_steps - positive_steps
    positive_weight = min(max(negative_steps / max(positive_steps, 1.0), 1.0), 8.0)

    model = ContextualLSTM()
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate, weight_decay=1e-4)
    loader = DataLoader(
        TensorDataset(*training_tensors),
        batch_size=config.batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(config.seed),
    )
    epoch_losses: list[float] = []
    for _ in range(config.epochs):
        model.train()
        total_loss = 0.0
        batches = 0
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            action_logits, anomaly_logits = model(batch)
            targets = batch[5]
            labels = batch[8]
            valid = targets.ne(-100)
            normal_steps = valid & labels.eq(0).unsqueeze(1)
            action_losses = functional.cross_entropy(
                action_logits.reshape(-1, len(vocabularies["action"])),
                targets.clamp_min(0).reshape(-1),
                reduction="none",
            ).reshape_as(targets)
            next_action_loss = (action_losses * normal_steps).sum() / normal_steps.sum().clamp_min(1)
            anomaly_losses = functional.binary_cross_entropy_with_logits(
                anomaly_logits,
                batch[6],
                reduction="none",
                pos_weight=torch.tensor(positive_weight),
            )
            anomaly_loss = (anomaly_losses * valid).sum() / valid.sum().clamp_min(1)
            loss = next_action_loss + config.anomaly_loss_weight * anomaly_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            total_loss += float(loss.detach())
            batches += 1
        epoch_losses.append(total_loss / max(batches, 1))

    def torch_components(selected: Sequence[dict[str, Any]]) -> tuple[list[float], list[float]]:
        tensors = encode(selected)
        scoring_loader = DataLoader(TensorDataset(*tensors), batch_size=512, shuffle=False)
        sequence_scores: list[float] = []
        attack_probabilities: list[float] = []
        model.eval()
        with torch.no_grad():
            for batch in scoring_loader:
                action_logits, anomaly_logits = model(batch)
                targets = batch[5]
                valid = targets.ne(-100)
                log_probabilities = torch.log_softmax(action_logits, dim=-1)
                token_nll = -log_probabilities.gather(
                    -1, targets.clamp_min(0).unsqueeze(-1)
                ).squeeze(-1)
                nll = (token_nll * valid).sum(dim=1) / valid.sum(dim=1)
                final_logits = anomaly_logits.gather(1, (batch[7] - 1).unsqueeze(1)).squeeze(1)
                sequence_scores.extend(float(value) for value in nll)
                attack_probabilities.extend(float(value) for value in torch.sigmoid(final_logits))
        return sequence_scores, attack_probabilities

    validation_labels = [int(row["label"] == "anomalous") for row in validation_rows]
    validation_nll, validation_attack = torch_components(validation_rows)
    nll_threshold, _ = _choose_threshold(validation_labels, validation_nll)
    normal_nll = [
        score for score, label in zip(validation_nll, validation_labels, strict=True) if not label
    ]
    risk_scale = max(statistics.pstdev(normal_nll), 0.05)

    def combine(nll_values: Sequence[float], attack_values: Sequence[float]) -> list[float]:
        return [
            SEQUENCE_WEIGHT * (1.0 / (1.0 + math.exp(-(nll - nll_threshold) / risk_scale)))
            + ATTACK_WEIGHT * attack
            for nll, attack in zip(nll_values, attack_values, strict=True)
        ]

    validation_scores = combine(validation_nll, validation_attack)
    decision_threshold, validation_metrics = _choose_threshold(
        validation_labels, validation_scores
    )
    validation_metrics["roc_auc"] = _roc_auc(validation_labels, validation_scores)
    validation_metrics["average_precision"] = _average_precision(validation_labels, validation_scores)

    test_labels = [int(row["label"] == "anomalous") for row in test_rows]
    test_nll, test_attack = torch_components(test_rows)
    test_scores = combine(test_nll, test_attack)
    test_metrics = _metrics(test_labels, test_scores, decision_threshold)
    test_metrics["roc_auc"] = _roc_auc(test_labels, test_scores)
    test_metrics["average_precision"] = _average_precision(test_labels, test_scores)

    payload: dict[str, Any] = {
        "format_version": 2,
        "model_type": "contextual_lstm_multitask",
        "model_name": "keyguard-contextual-lstm-v2",
        "vocabularies": vocabularies,
        "tokens": {
            "start_action": START,
            "unknown_action": UNKNOWN,
            "unknown_role": UNKNOWN,
            "none_algorithm": NONE,
            "unknown_algorithm": UNKNOWN,
            "start_outcome": START,
            "unknown_outcome": UNKNOWN,
        },
        "feature_scaling": {"interval_log_scale": interval_log_scale},
        "feature_names": [
            "previous_action",
            "role",
            "requested_algorithm",
            "previous_outcome",
            "hour_sin",
            "hour_cos",
            "log_interval",
            "is_new_device",
            "recent_denied_or_failed_count",
            "sequence_position",
        ],
        "embeddings": {
            "action": model.action_embedding.weight.detach().tolist(),
            "role": model.role_embedding.weight.detach().tolist(),
            "algorithm": model.algorithm_embedding.weight.detach().tolist(),
            "outcome": model.outcome_embedding.weight.detach().tolist(),
        },
        "hidden_size": config.hidden_size,
        "lstm": {
            "weight_ih": model.lstm.weight_ih_l0.detach().tolist(),
            "weight_hh": model.lstm.weight_hh_l0.detach().tolist(),
            "bias_ih": model.lstm.bias_ih_l0.detach().tolist(),
            "bias_hh": model.lstm.bias_hh_l0.detach().tolist(),
        },
        "next_action_output": {
            "weight": model.next_action.weight.detach().tolist(),
            "bias": model.next_action.bias.detach().tolist(),
        },
        "anomaly_output": {
            "weight": model.anomaly.weight.detach()[0].tolist(),
            "bias": float(model.anomaly.bias.detach()[0]),
        },
        "nll_threshold": nll_threshold,
        "risk_scale": risk_scale,
        "sequence_weight": SEQUENCE_WEIGHT,
        "attack_weight": ATTACK_WEIGHT,
        "decision_threshold": decision_threshold,
        "training": {
            "seed": config.seed,
            "epochs": config.epochs,
            "training_sessions": len(training_rows),
            "training_normal_sessions": sum(row["label"] == "normal" for row in training_rows),
            "training_anomalous_sessions": sum(row["label"] == "anomalous" for row in training_rows),
            "final_loss": epoch_losses[-1],
            "maximum_sequence_length": maximum_length,
            "positive_step_weight": positive_weight,
        },
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }

    portable = ContextualLSTMDetector(payload)
    maximum_difference = 0.0
    for index, row in enumerate(validation_rows[:100]):
        portable_nll, portable_attack, portable_combined = portable.component_scores(row)
        maximum_difference = max(
            maximum_difference,
            abs(portable_nll - validation_nll[index]),
            abs(portable_attack - validation_attack[index]),
            abs(portable_combined - validation_scores[index]),
        )
    if maximum_difference > 1e-5:
        raise RuntimeError(f"portable contextual inference differs by {maximum_difference}")
    payload["portable_verification_max_difference"] = maximum_difference

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = config.output_path.with_suffix(config.output_path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as model_file:
        json.dump(payload, model_file, sort_keys=True, separators=(",", ":"))
        model_file.write("\n")
    temporary_path.replace(config.output_path)

    return {
        "model_path": str(config.output_path),
        "final_loss": epoch_losses[-1],
        "decision_threshold": decision_threshold,
        "portable_verification_max_difference": maximum_difference,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }


def parse_args(arguments: Iterator[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=Path, default=Path("data/processed/sessions.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/contextual_lstm_detector.json"))
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--seed", type=int, default=20_261_017)
    return parser.parse_args(arguments)


def main() -> None:
    arguments = parse_args()
    result = train_and_export(
        ContextualTrainingConfig(
            sessions_path=arguments.sessions,
            output_path=arguments.output,
            epochs=arguments.epochs,
            batch_size=arguments.batch_size,
            seed=arguments.seed,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
