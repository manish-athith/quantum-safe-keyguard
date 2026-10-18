"""Tests for the dependency-free LinuxONE LSTM runtime."""

import math

import pytest

from quantum_keyguard.detection.portable_lstm import PortableLSTMDetector


def tiny_model() -> dict[str, object]:
    # One hidden unit and one-dimensional embeddings make the expected recurrence
    # small while still exercising all four LSTM gates.
    return {
        "format_version": 1,
        "model_type": "lstm_next_action",
        "model_name": "tiny-lstm",
        "vocabulary": ["<PAD>", "<START>", "<UNKNOWN>", "LOGIN", "LOGOUT"],
        "start_token": "<START>",
        "unknown_token": "<UNKNOWN>",
        "hidden_size": 1,
        "embedding": [[0.0], [0.2], [-0.2], [0.4], [0.6]],
        "lstm": {
            "weight_ih": [[0.1], [0.2], [0.3], [0.4]],
            "weight_hh": [[0.05], [0.06], [0.07], [0.08]],
            "bias_ih": [0.0, 0.0, 0.0, 0.0],
            "bias_hh": [0.0, 0.0, 0.0, 0.0],
        },
        "output": {
            "weight": [[0.0], [0.0], [0.0], [0.5], [-0.5]],
            "bias": [0.0, 0.0, 0.0, 0.1, -0.1],
        },
        "threshold_raw_nll": 1.7,
        "risk_scale": 0.2,
    }


def test_portable_lstm_returns_bounded_explainable_score() -> None:
    detector = PortableLSTMDetector(tiny_model())
    result = detector.score(["LOGIN", "LOGOUT"])

    assert math.isfinite(result.raw_score)
    assert 0.0 <= result.risk_score <= 1.0
    assert result.threshold == 1.7
    assert len(result.signals) == 1


def test_unknown_action_is_scored_without_crashing() -> None:
    detector = PortableLSTMDetector(tiny_model())
    result = detector.score(["LOGIN", "UNSEEN_ACTION"])
    assert math.isfinite(result.raw_score)


def test_empty_sequence_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        PortableLSTMDetector(tiny_model()).score([])


def test_invalid_model_shapes_are_rejected() -> None:
    payload = tiny_model()
    payload["output"] = {"weight": [], "bias": []}
    with pytest.raises(ValueError, match="output"):
        PortableLSTMDetector(payload)

