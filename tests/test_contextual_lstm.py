"""Tests for the portable contextual LSTM runtime."""

import math

import pytest

from quantum_keyguard.detection.contextual_lstm import ContextualLSTMDetector


def tiny_contextual_model() -> dict[str, object]:
    gate_row = [0.1, 0.1, 0.1, 0.1, 0.0, 0.0, 0.0, 0.7, 0.0, 0.0]
    return {
        "format_version": 2,
        "model_type": "contextual_lstm_multitask",
        "model_name": "tiny-contextual-lstm",
        "vocabularies": {
            "action": ["<PAD>", "<START>", "<UNKNOWN>", "LOGIN", "LOGOUT"],
            "role": ["<UNKNOWN>", "viewer", "key_admin"],
            "algorithm": ["<NONE>", "<UNKNOWN>", "ML-DSA-65"],
            "outcome": ["<START>", "<UNKNOWN>", "allowed", "denied"],
        },
        "tokens": {
            "start_action": "<START>",
            "unknown_action": "<UNKNOWN>",
            "unknown_role": "<UNKNOWN>",
            "none_algorithm": "<NONE>",
            "unknown_algorithm": "<UNKNOWN>",
            "start_outcome": "<START>",
            "unknown_outcome": "<UNKNOWN>",
        },
        "feature_scaling": {"interval_log_scale": math.log1p(300.0)},
        "embeddings": {
            "action": [[0.0], [0.2], [-0.2], [0.4], [0.6]],
            "role": [[0.0], [0.2], [0.5]],
            "algorithm": [[0.0], [-0.2], [0.3]],
            "outcome": [[0.0], [-0.2], [0.2], [0.6]],
        },
        "hidden_size": 1,
        "lstm": {
            "weight_ih": [gate_row, gate_row, gate_row, gate_row],
            "weight_hh": [[0.05], [0.06], [0.07], [0.08]],
            "bias_ih": [0.0, 0.0, 0.0, 0.0],
            "bias_hh": [0.0, 0.0, 0.0, 0.0],
        },
        "next_action_output": {
            "weight": [[0.0], [0.0], [0.0], [0.5], [-0.5]],
            "bias": [0.0, 0.0, 0.0, 0.1, -0.1],
        },
        "anomaly_output": {"weight": [1.0], "bias": -0.1},
        "nll_threshold": 1.7,
        "risk_scale": 0.2,
        "sequence_weight": 0.4,
        "attack_weight": 0.6,
        "decision_threshold": 0.6,
        "training": {"maximum_sequence_length": 20},
    }


def session(new_device: bool = False) -> dict[str, object]:
    return {
        "actions": ["LOGIN", "LOGOUT"],
        "role": "viewer",
        "hours": [9, 9],
        "interval_seconds": [0, 30],
        "is_new_device": [new_device, new_device],
        "algorithms": [None, None],
        "outcomes": ["allowed", "allowed"],
    }


def test_contextual_detector_returns_component_and_combined_scores() -> None:
    detector = ContextualLSTMDetector(tiny_contextual_model())
    nll, attack_probability, combined = detector.component_scores(session())
    result = detector.score_session(session())

    assert math.isfinite(nll)
    assert 0.0 <= attack_probability <= 1.0
    assert 0.0 <= combined <= 1.0
    assert result.risk_score == pytest.approx(combined)


def test_context_changes_the_score() -> None:
    detector = ContextualLSTMDetector(tiny_contextual_model())
    known = detector.score_session(session(new_device=False)).risk_score
    new = detector.score_session(session(new_device=True)).risk_score
    assert new != pytest.approx(known)


def test_misaligned_context_is_rejected() -> None:
    detector = ContextualLSTMDetector(tiny_contextual_model())
    invalid = session()
    invalid["hours"] = [9]
    with pytest.raises(ValueError, match="align"):
        detector.score_session(invalid)


def test_empty_contextual_sequence_is_rejected() -> None:
    detector = ContextualLSTMDetector(tiny_contextual_model())
    with pytest.raises(ValueError, match="at least one"):
        detector.score_session({"actions": []})
