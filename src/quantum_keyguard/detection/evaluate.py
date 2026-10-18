"""Evaluate the exported portable LSTM without importing PyTorch."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Iterator

from quantum_keyguard.detection.contextual_lstm import ContextualLSTMDetector
from quantum_keyguard.detection.portable_lstm import PortableLSTMDetector


def evaluate(
    model_path: Path, sessions_path: Path, split: str = "test"
) -> dict[str, float | int | str]:
    with model_path.open("r", encoding="utf-8") as model_file:
        model_payload = json.load(model_file)
    contextual = model_payload.get("format_version") == 2
    detector = (
        ContextualLSTMDetector(model_payload)
        if contextual
        else PortableLSTMDetector(model_payload)
    )
    rows = [
        json.loads(line)
        for line in sessions_path.read_text(encoding="utf-8").splitlines()
    ]
    selected = [row for row in rows if row["split"] == split]
    if not selected:
        raise ValueError(f"no sessions found for split: {split}")

    started = time.perf_counter()
    assessments = [
        detector.score_session(row) if contextual else detector.score(row["actions"])
        for row in selected
    ]
    elapsed = time.perf_counter() - started
    labels = [row["label"] == "anomalous" for row in selected]
    predictions = [assessment.is_anomalous for assessment in assessments]
    true_positive = sum(p and y for p, y in zip(predictions, labels, strict=True))
    true_negative = sum(not p and not y for p, y in zip(predictions, labels, strict=True))
    false_positive = sum(p and not y for p, y in zip(predictions, labels, strict=True))
    false_negative = sum(not p and y for p, y in zip(predictions, labels, strict=True))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    return {
        "model_name": detector.model_name,
        "split": split,
        "sessions": len(selected),
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "accuracy": (true_positive + true_negative) / len(labels),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "average_inference_ms": elapsed * 1_000 / len(selected),
    }


def parse_args(arguments: Iterator[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model", type=Path, default=Path("artifacts/contextual_lstm_detector.json")
    )
    parser.add_argument(
        "--sessions", type=Path, default=Path("data/processed/sessions.jsonl")
    )
    parser.add_argument("--split", choices=("validation", "test"), default="test")
    return parser.parse_args(arguments)


def main() -> None:
    args = parse_args()
    print(
        json.dumps(
            evaluate(args.model, args.sessions, args.split), indent=2, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()

