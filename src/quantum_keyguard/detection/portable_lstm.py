"""Small standard-library LSTM inference runtime for LinuxONE s390x."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Sequence

from quantum_keyguard.detection.contracts import RiskAssessment


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponential = math.exp(-value)
        return 1.0 / (1.0 + exponential)
    exponential = math.exp(value)
    return exponential / (1.0 + exponential)


def _matrix_vector(
    matrix: list[list[float]], vector: list[float], bias: list[float]
) -> list[float]:
    return [
        bias_value + sum(weight * item for weight, item in zip(row, vector, strict=True))
        for row, bias_value in zip(matrix, bias, strict=True)
    ]


class PortableLSTMDetector:
    """Execute exported PyTorch LSTM weights without importing PyTorch."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("format_version") != 1:
            raise ValueError("unsupported detector format")
        if payload.get("model_type") != "lstm_next_action":
            raise ValueError("unsupported detector type")

        self.model_name = str(payload["model_name"])
        self.vocabulary = [str(token) for token in payload["vocabulary"]]
        self.token_to_index = {token: index for index, token in enumerate(self.vocabulary)}
        self.start_token = str(payload["start_token"])
        self.unknown_token = str(payload["unknown_token"])
        self.embedding = self._float_matrix(payload["embedding"])
        self.weight_ih = self._float_matrix(payload["lstm"]["weight_ih"])
        self.weight_hh = self._float_matrix(payload["lstm"]["weight_hh"])
        self.bias_ih = self._float_vector(payload["lstm"]["bias_ih"])
        self.bias_hh = self._float_vector(payload["lstm"]["bias_hh"])
        self.output_weight = self._float_matrix(payload["output"]["weight"])
        self.output_bias = self._float_vector(payload["output"]["bias"])
        self.hidden_size = int(payload["hidden_size"])
        self.threshold = float(payload["threshold_raw_nll"])
        self.risk_scale = max(float(payload["risk_scale"]), 1e-6)
        self._validate_shapes()

    @classmethod
    def from_file(cls, path: str | Path) -> "PortableLSTMDetector":
        with Path(path).open("r", encoding="utf-8") as model_file:
            payload = json.load(model_file)
        return cls(payload)

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
        vocabulary_size = len(self.vocabulary)
        if self.start_token not in self.token_to_index:
            raise ValueError("start token is absent from vocabulary")
        if self.unknown_token not in self.token_to_index:
            raise ValueError("unknown token is absent from vocabulary")
        if len(self.embedding) != vocabulary_size:
            raise ValueError("embedding vocabulary shape mismatch")
        if len(self.weight_ih) != 4 * self.hidden_size:
            raise ValueError("input LSTM weight shape mismatch")
        if len(self.weight_hh) != 4 * self.hidden_size:
            raise ValueError("hidden LSTM weight shape mismatch")
        if any(len(row) != self.hidden_size for row in self.weight_hh):
            raise ValueError("hidden LSTM matrix width mismatch")
        if len(self.bias_ih) != 4 * self.hidden_size:
            raise ValueError("input LSTM bias shape mismatch")
        if len(self.bias_hh) != 4 * self.hidden_size:
            raise ValueError("hidden LSTM bias shape mismatch")
        if len(self.output_weight) != vocabulary_size:
            raise ValueError("output vocabulary shape mismatch")
        if any(len(row) != self.hidden_size for row in self.output_weight):
            raise ValueError("output matrix width mismatch")
        if len(self.output_bias) != vocabulary_size:
            raise ValueError("output bias shape mismatch")

    def raw_score(self, actions: Sequence[str]) -> float:
        """Return mean next-action negative log likelihood."""
        if not actions:
            raise ValueError("at least one action is required")

        hidden = [0.0] * self.hidden_size
        cell = [0.0] * self.hidden_size
        previous_token = self.start_token
        total_nll = 0.0

        for action in actions:
            input_index = self.token_to_index.get(
                previous_token, self.token_to_index[self.unknown_token]
            )
            target_index = self.token_to_index.get(action, self.token_to_index[self.unknown_token])
            embedded = self.embedding[input_index]
            input_gates = _matrix_vector(
                self.weight_ih, embedded, self.bias_ih
            )
            hidden_gates = _matrix_vector(
                self.weight_hh, hidden, self.bias_hh
            )
            gates = [
                input_value + hidden_value
                for input_value, hidden_value in zip(
                    input_gates, hidden_gates, strict=True
                )
            ]
            i_gate = [_sigmoid(value) for value in gates[: self.hidden_size]]
            f_gate = [
                _sigmoid(value)
                for value in gates[self.hidden_size : 2 * self.hidden_size]
            ]
            g_gate = [
                math.tanh(value)
                for value in gates[2 * self.hidden_size : 3 * self.hidden_size]
            ]
            o_gate = [
                _sigmoid(value) for value in gates[3 * self.hidden_size :]
            ]
            cell = [
                forget * old_cell + input_value * candidate
                for forget, old_cell, input_value, candidate in zip(
                    f_gate, cell, i_gate, g_gate, strict=True
                )
            ]
            hidden = [
                output * math.tanh(cell_value)
                for output, cell_value in zip(o_gate, cell, strict=True)
            ]
            logits = _matrix_vector(self.output_weight, hidden, self.output_bias)
            maximum = max(logits)
            log_sum_exp = maximum + math.log(
                sum(math.exp(logit - maximum) for logit in logits)
            )
            total_nll += log_sum_exp - logits[target_index]
            previous_token = action

        return total_nll / len(actions)

    def score(self, actions: Sequence[str]) -> RiskAssessment:
        raw_score = self.raw_score(actions)
        risk_score = _sigmoid((raw_score - self.threshold) / self.risk_scale)
        anomalous = raw_score >= self.threshold
        return RiskAssessment(
            model_name=self.model_name,
            raw_score=raw_score,
            risk_score=risk_score,
            threshold=self.threshold,
            is_anomalous=anomalous,
            signals=(
                ("unfamiliar_action_sequence",)
                if anomalous
                else ("sequence_within_learned_baseline",)
            ),
        )

