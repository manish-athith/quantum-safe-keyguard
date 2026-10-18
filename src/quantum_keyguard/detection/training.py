"""Train, evaluate, export, and verify the small action-sequence LSTM."""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from quantum_keyguard.domain.enums import AuditAction
from quantum_keyguard.detection.portable_lstm import PortableLSTMDetector

PAD_TOKEN = "<PAD>"
START_TOKEN = "<START>"
UNKNOWN_TOKEN = "<UNKNOWN>"


@dataclass(frozen=True)
class TrainingConfig:
    sessions_path: Path
    output_path: Path
    epochs: int = 12
    batch_size: int = 128
    embedding_size: int = 16
    hidden_size: int = 24
    learning_rate: float = 0.01
    seed: int = 20_261_017


def _load_sessions(path: Path) -> list[dict[str, Any]]:
    sessions = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if not sessions:
        raise ValueError("session dataset is empty")
    return sessions


def _vocabulary() -> list[str]:
    return [PAD_TOKEN, START_TOKEN, UNKNOWN_TOKEN] + sorted(
        action.value for action in AuditAction
    )


def _metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, float | int]:
    predictions = [int(score >= threshold) for score in scores]
    true_positive = sum(p == 1 and y == 1 for p, y in zip(predictions, labels, strict=True))
    true_negative = sum(p == 0 and y == 0 for p, y in zip(predictions, labels, strict=True))
    false_positive = sum(p == 1 and y == 0 for p, y in zip(predictions, labels, strict=True))
    false_negative = sum(p == 0 and y == 1 for p, y in zip(predictions, labels, strict=True))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    return {
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
    }


def _choose_threshold(labels: Sequence[int], scores: Sequence[float]) -> tuple[float, dict[str, float | int]]:
    ordered = sorted(set(scores))
    candidates = [ordered[0] - 1e-9]
    candidates.extend((left + right) / 2 for left, right in zip(ordered, ordered[1:]))
    candidates.append(ordered[-1] + 1e-9)
    ranked: list[tuple[float, float, float, dict[str, float | int]]] = []
    for threshold in candidates:
        result = _metrics(labels, scores, threshold)
        ranked.append(
            (
                float(result["f1"]),
                -float(result["false_positive_rate"]),
                -threshold,
                result,
            )
        )
    best = max(ranked)
    return -best[2], best[3]


def train_and_export(config: TrainingConfig) -> dict[str, Any]:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError as error:
        raise RuntimeError(
            "PyTorch is required for training; install requirements-ml.txt on the laptop"
        ) from error

    random.seed(config.seed)
    torch.manual_seed(config.seed)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)

    sessions = _load_sessions(config.sessions_path)
    vocabulary = _vocabulary()
    token_to_index = {token: index for index, token in enumerate(vocabulary)}
    pad_index = token_to_index[PAD_TOKEN]
    start_index = token_to_index[START_TOKEN]
    unknown_index = token_to_index[UNKNOWN_TOKEN]
    maximum_length = max(len(session["actions"]) for session in sessions)

    training_sessions = [
        session
        for session in sessions
        if session["split"] == "train" and session["label"] == "normal"
    ]

    def tensors_for(rows: Sequence[dict[str, Any]]) -> tuple[Any, Any]:
        inputs: list[list[int]] = []
        targets: list[list[int]] = []
        for row in rows:
            actions = [token_to_index.get(action, unknown_index) for action in row["actions"]]
            input_tokens = [start_index] + actions[:-1]
            padding = maximum_length - len(actions)
            inputs.append(input_tokens + [pad_index] * padding)
            targets.append(actions + [-100] * padding)
        return torch.tensor(inputs, dtype=torch.long), torch.tensor(targets, dtype=torch.long)

    train_inputs, train_targets = tensors_for(training_sessions)

    class NextActionLSTM(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(len(vocabulary), config.embedding_size)
            self.lstm = nn.LSTM(config.embedding_size, config.hidden_size, batch_first=True)
            self.output = nn.Linear(config.hidden_size, len(vocabulary))

        def forward(self, inputs: Any) -> Any:
            embedded = self.embedding(inputs)
            hidden, _ = self.lstm(embedded)
            return self.output(hidden)

    model = NextActionLSTM()
    optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate)
    loss_function = nn.CrossEntropyLoss(ignore_index=-100)
    loader_generator = torch.Generator().manual_seed(config.seed)
    loader = DataLoader(
        TensorDataset(train_inputs, train_targets),
        batch_size=config.batch_size,
        shuffle=True,
        generator=loader_generator,
    )

    model.train()
    epoch_losses: list[float] = []
    for _ in range(config.epochs):
        total_loss = 0.0
        batches = 0
        for batch_inputs, batch_targets in loader:
            optimizer.zero_grad(set_to_none=True)
            logits = model(batch_inputs)
            loss = loss_function(logits.reshape(-1, len(vocabulary)), batch_targets.reshape(-1))
            loss.backward()
            optimizer.step()
            total_loss += float(loss.detach())
            batches += 1
        epoch_losses.append(total_loss / batches)

    def torch_scores(rows: Sequence[dict[str, Any]]) -> list[float]:
        if not rows:
            return []
        inputs, targets = tensors_for(rows)
        model.eval()
        with torch.no_grad():
            logits = model(inputs)
            log_probabilities = torch.log_softmax(logits, dim=-1)
            safe_targets = targets.clamp_min(0)
            token_nll = -log_probabilities.gather(-1, safe_targets.unsqueeze(-1)).squeeze(-1)
            mask = targets.ne(-100)
            sequence_nll = (token_nll * mask).sum(dim=1) / mask.sum(dim=1)
        return [float(value) for value in sequence_nll]

    validation = [session for session in sessions if session["split"] == "validation"]
    validation_labels = [int(session["label"] == "anomalous") for session in validation]
    validation_scores = torch_scores(validation)
    threshold, validation_metrics = _choose_threshold(validation_labels, validation_scores)
    validation_normal_scores = [
        score
        for score, label in zip(validation_scores, validation_labels, strict=True)
        if label == 0
    ]
    risk_scale = max(statistics.pstdev(validation_normal_scores), 0.05)

    test = [session for session in sessions if session["split"] == "test"]
    test_labels = [int(session["label"] == "anomalous") for session in test]
    test_scores = torch_scores(test)
    test_metrics = _metrics(test_labels, test_scores, threshold)

    export: dict[str, Any] = {
        "format_version": 1,
        "model_type": "lstm_next_action",
        "model_name": "keyguard-lstm-v1",
        "vocabulary": vocabulary,
        "start_token": START_TOKEN,
        "unknown_token": UNKNOWN_TOKEN,
        "embedding_size": config.embedding_size,
        "hidden_size": config.hidden_size,
        "embedding": model.embedding.weight.detach().tolist(),
        "lstm": {
            "weight_ih": model.lstm.weight_ih_l0.detach().tolist(),
            "weight_hh": model.lstm.weight_hh_l0.detach().tolist(),
            "bias_ih": model.lstm.bias_ih_l0.detach().tolist(),
            "bias_hh": model.lstm.bias_hh_l0.detach().tolist(),
        },
        "output": {
            "weight": model.output.weight.detach().tolist(),
            "bias": model.output.bias.detach().tolist(),
        },
        "threshold_raw_nll": threshold,
        "risk_scale": risk_scale,
        "training": {
            "seed": config.seed,
            "epochs": config.epochs,
            "training_sessions": len(training_sessions),
            "final_loss": epoch_losses[-1],
            "maximum_sequence_length": maximum_length,
        },
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }

    portable = PortableLSTMDetector(export)
    verification_rows = validation[:100]
    portable_scores = [portable.raw_score(row["actions"]) for row in verification_rows]
    reference_scores = torch_scores(verification_rows)
    maximum_difference = max(
        abs(portable_score - reference_score)
        for portable_score, reference_score in zip(
            portable_scores, reference_scores, strict=True
        )
    )
    if maximum_difference > 1e-5:
        raise RuntimeError(
            f"portable inference differs from PyTorch by {maximum_difference}"
        )
    export["portable_verification_max_difference"] = maximum_difference

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = config.output_path.with_suffix(config.output_path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as model_file:
        json.dump(export, model_file, sort_keys=True, separators=(",", ":"))
        model_file.write("\n")
    temporary_path.replace(config.output_path)

    return {
        "model_path": str(config.output_path),
        "final_loss": epoch_losses[-1],
        "threshold_raw_nll": threshold,
        "portable_verification_max_difference": maximum_difference,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }


def parse_args(arguments: Iterator[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sessions", type=Path, default=Path("data/processed/sessions.jsonl")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/lstm_detector.json")
    )
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--seed", type=int, default=20_261_017)
    return parser.parse_args(arguments)


def main() -> None:
    args = parse_args()
    result = train_and_export(
        TrainingConfig(
            sessions_path=args.sessions,
            output_path=args.output,
            epochs=args.epochs,
            batch_size=args.batch_size,
            seed=args.seed,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

