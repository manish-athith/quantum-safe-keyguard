"""Dependency-free contextual multi-task LSTM inference for LinuxONE s390x."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

from quantum_keyguard.detection.contracts import RiskAssessment


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exponential = math.exp(value)
    return exponential / (1.0 + exponential)


def _matrix_vector(
    matrix: list[list[float]], vector: list[float], bias: list[float]
) -> list[float]:
    return [
        bias_value + sum(weight * item for weight, item in zip(row, vector, strict=True))
        for row, bias_value in zip(matrix, bias, strict=True)
    ]


class ContextualLSTMDetector:
    """Score ordered actions with role, timing, device, algorithm, and outcome context."""

    NUMERIC_FEATURE_COUNT = 6

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("format_version") != 2:
            raise ValueError("unsupported contextual detector format")
        if payload.get("model_type") != "contextual_lstm_multitask":
            raise ValueError("unsupported contextual detector type")

        self.model_name = str(payload["model_name"])
        self.vocabularies = {
            name: [str(item) for item in values]
            for name, values in payload["vocabularies"].items()
        }
        self.indices = {
            name: {token: index for index, token in enumerate(values)}
            for name, values in self.vocabularies.items()
        }
        self.tokens = {name: str(value) for name, value in payload["tokens"].items()}
        self.embeddings = {
            name: self._float_matrix(value)
            for name, value in payload["embeddings"].items()
        }
        self.hidden_size = int(payload["hidden_size"])
        self.weight_ih = self._float_matrix(payload["lstm"]["weight_ih"])
        self.weight_hh = self._float_matrix(payload["lstm"]["weight_hh"])
        self.bias_ih = self._float_vector(payload["lstm"]["bias_ih"])
        self.bias_hh = self._float_vector(payload["lstm"]["bias_hh"])
        self.action_output_weight = self._float_matrix(
            payload["next_action_output"]["weight"]
        )
        self.action_output_bias = self._float_vector(
            payload["next_action_output"]["bias"]
        )
        self.anomaly_output_weight = self._float_vector(
            payload["anomaly_output"]["weight"]
        )
        self.anomaly_output_bias = float(payload["anomaly_output"]["bias"])
        self.nll_threshold = float(payload["nll_threshold"])
        self.risk_scale = max(float(payload["risk_scale"]), 1e-6)
        self.sequence_weight = float(payload["sequence_weight"])
        self.attack_weight = float(payload["attack_weight"])
        self.threshold = float(payload["decision_threshold"])
        self.interval_log_scale = float(payload["feature_scaling"]["interval_log_scale"])
        self.maximum_sequence_length = int(payload["training"]["maximum_sequence_length"])
        self._validate_shapes()

    @classmethod
    def from_file(cls, path: str | Path) -> "ContextualLSTMDetector":
        with Path(path).open("r", encoding="utf-8") as model_file:
            return cls(json.load(model_file))

    @staticmethod
    def _float_vector(value: object) -> list[float]:
        if not isinstance(value, list):
            raise ValueError("expected a numeric vector")
        return [float(item) for item in value]

    @classmethod
    def _float_matrix(cls, value: object) -> list[list[float]]:
        if not isinstance(value, list):
            raise ValueError("expected a numeric matrix")
        return [cls._float_vector(row) for row in value]

    def _validate_shapes(self) -> None:
        for name in ("action", "role", "algorithm", "outcome"):
            if name not in self.vocabularies or name not in self.embeddings:
                raise ValueError(f"missing {name} vocabulary or embedding")
            if len(self.vocabularies[name]) != len(self.embeddings[name]):
                raise ValueError(f"{name} embedding vocabulary shape mismatch")

        input_width = sum(len(matrix[0]) for matrix in self.embeddings.values())
        input_width += self.NUMERIC_FEATURE_COUNT
        if len(self.weight_ih) != 4 * self.hidden_size:
            raise ValueError("input LSTM height mismatch")
        if any(len(row) != input_width for row in self.weight_ih):
            raise ValueError("input LSTM width mismatch")
        if len(self.weight_hh) != 4 * self.hidden_size or any(
            len(row) != self.hidden_size for row in self.weight_hh
        ):
            raise ValueError("hidden LSTM shape mismatch")
        if len(self.bias_ih) != 4 * self.hidden_size or len(self.bias_hh) != 4 * self.hidden_size:
            raise ValueError("LSTM bias shape mismatch")
        if len(self.action_output_weight) != len(self.vocabularies["action"]):
            raise ValueError("next-action output shape mismatch")
        if any(len(row) != self.hidden_size for row in self.action_output_weight):
            raise ValueError("next-action output width mismatch")
        if len(self.action_output_bias) != len(self.vocabularies["action"]):
            raise ValueError("next-action bias shape mismatch")
        if len(self.anomaly_output_weight) != self.hidden_size:
            raise ValueError("anomaly output shape mismatch")
        if not math.isclose(self.sequence_weight + self.attack_weight, 1.0, abs_tol=1e-9):
            raise ValueError("risk component weights must sum to one")

    def _index(self, vocabulary: str, token: object, fallback: str) -> int:
        return self.indices[vocabulary].get(str(token), self.indices[vocabulary][fallback])

    @staticmethod
    def _aligned_list(
        session: Mapping[str, Any], name: str, length: int, default: object
    ) -> list[Any]:
        value = session.get(name)
        if value is None:
            return [default] * length
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise ValueError(f"{name} must be a sequence")
        result = list(value)
        if len(result) != length:
            raise ValueError(f"{name} must align with actions")
        return result

    def component_scores(self, session: Mapping[str, Any]) -> tuple[float, float, float]:
        actions = self._aligned_list(session, "actions", len(session.get("actions", [])), "")
        if not actions:
            raise ValueError("at least one action is required")
        length = len(actions)
        hours = self._aligned_list(session, "hours", length, 12)
        intervals = self._aligned_list(session, "interval_seconds", length, 30)
        devices = self._aligned_list(session, "is_new_device", length, False)
        algorithms = self._aligned_list(session, "algorithms", length, None)
        outcomes = self._aligned_list(session, "outcomes", length, "allowed")
        role = str(session.get("role", "viewer"))

        hidden = [0.0] * self.hidden_size
        cell = [0.0] * self.hidden_size
        previous_action = self.tokens["start_action"]
        previous_outcome = self.tokens["start_outcome"]
        denied_count = 0
        total_nll = 0.0

        for position, action in enumerate(actions):
            action_index = self._index(
                "action", previous_action, self.tokens["unknown_action"]
            )
            role_index = self._index("role", role, self.tokens["unknown_role"])
            algorithm_token = algorithms[position] or self.tokens["none_algorithm"]
            algorithm_index = self._index(
                "algorithm", algorithm_token, self.tokens["unknown_algorithm"]
            )
            outcome_index = self._index(
                "outcome", previous_outcome, self.tokens["unknown_outcome"]
            )
            hour = int(hours[position]) % 24
            interval = max(0.0, float(intervals[position]))
            numeric = [
                math.sin(2.0 * math.pi * hour / 24.0),
                math.cos(2.0 * math.pi * hour / 24.0),
                min(math.log1p(interval) / self.interval_log_scale, 2.0),
                1.0 if bool(devices[position]) else 0.0,
                min(denied_count / 5.0, 1.0),
                min((position + 1) / self.maximum_sequence_length, 1.0),
            ]
            vector = (
                self.embeddings["action"][action_index]
                + self.embeddings["role"][role_index]
                + self.embeddings["algorithm"][algorithm_index]
                + self.embeddings["outcome"][outcome_index]
                + numeric
            )
            input_gates = _matrix_vector(self.weight_ih, vector, self.bias_ih)
            hidden_gates = _matrix_vector(self.weight_hh, hidden, self.bias_hh)
            gates = [left + right for left, right in zip(input_gates, hidden_gates, strict=True)]
            i_gate = [_sigmoid(value) for value in gates[: self.hidden_size]]
            f_gate = [_sigmoid(value) for value in gates[self.hidden_size : 2 * self.hidden_size]]
            g_gate = [math.tanh(value) for value in gates[2 * self.hidden_size : 3 * self.hidden_size]]
            o_gate = [_sigmoid(value) for value in gates[3 * self.hidden_size :]]
            cell = [
                forget * old + incoming * candidate
                for forget, old, incoming, candidate in zip(
                    f_gate, cell, i_gate, g_gate, strict=True
                )
            ]
            hidden = [output * math.tanh(value) for output, value in zip(o_gate, cell, strict=True)]

            logits = _matrix_vector(
                self.action_output_weight, hidden, self.action_output_bias
            )
            target_index = self._index(
                "action", action, self.tokens["unknown_action"]
            )
            maximum = max(logits)
            log_sum_exp = maximum + math.log(sum(math.exp(item - maximum) for item in logits))
            total_nll += log_sum_exp - logits[target_index]
            previous_action = str(action)
            previous_outcome = str(outcomes[position])
            if previous_outcome in {"denied", "failed"}:
                denied_count += 1

        sequence_nll = total_nll / length
        sequence_risk = _sigmoid((sequence_nll - self.nll_threshold) / self.risk_scale)
        attack_logit = self.anomaly_output_bias + sum(
            weight * value
            for weight, value in zip(self.anomaly_output_weight, hidden, strict=True)
        )
        attack_probability = _sigmoid(attack_logit)
        combined = self.sequence_weight * sequence_risk + self.attack_weight * attack_probability
        return sequence_nll, attack_probability, combined

    def score_session(self, session: Mapping[str, Any]) -> RiskAssessment:
        sequence_nll, attack_probability, combined = self.component_scores(session)
        anomalous = combined >= self.threshold
        signals: list[str] = []
        if sequence_nll >= self.nll_threshold:
            signals.append("unfamiliar_action_sequence")
        if attack_probability >= 0.5:
            signals.append("contextual_attack_pattern")
        if not signals:
            signals.append("behavior_within_learned_baseline")
        return RiskAssessment(
            model_name=self.model_name,
            raw_score=combined,
            risk_score=combined,
            threshold=self.threshold,
            is_anomalous=anomalous,
            signals=tuple(signals),
        )

    def score(self, actions: Sequence[str]) -> RiskAssessment:
        """Backward-compatible scoring with neutral context; APIs should use score_session."""
        return self.score_session({"actions": list(actions)})
