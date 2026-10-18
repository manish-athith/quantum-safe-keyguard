"""Quality and reproducibility tests for the synthetic dataset."""

import json
from pathlib import Path

from quantum_keyguard.dataset.generator import DatasetConfig, generate_dataset


def load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def small_config(output_root: Path) -> DatasetConfig:
    return DatasetConfig(
        output_root=output_root,
        normal_sessions=20,
        anomalous_sessions=6,
        min_actions=5,
        max_actions=8,
        seed=12345,
    )


def test_generation_is_byte_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_dataset(small_config(first))
    generate_dataset(small_config(second))

    assert (first / "raw/audit_events.jsonl").read_bytes() == (
        second / "raw/audit_events.jsonl"
    ).read_bytes()
    assert (first / "processed/sessions.jsonl").read_bytes() == (
        second / "processed/sessions.jsonl"
    ).read_bytes()
    assert b"\r\n" not in (first / "processed/dataset_summary.json").read_bytes()


def test_split_counts_and_training_purity(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    summary = generate_dataset(small_config(root))
    sessions = load_jsonl(root / "processed/sessions.jsonl")

    assert summary["total_sessions"] == 26
    assert len(sessions) == 26
    assert summary["splits"] == {
        "train": {"normal": 14, "anomalous": 3},
        "validation": {"normal": 3, "anomalous": 1},
        "test": {"normal": 3, "anomalous": 2},
    }


def test_events_are_ordered_and_session_lengths_match(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    generate_dataset(small_config(root))
    sessions = load_jsonl(root / "processed/sessions.jsonl")
    events = load_jsonl(root / "raw/audit_events.jsonl")

    events_by_session: dict[str, list[dict[str, object]]] = {}
    for event in events:
        events_by_session.setdefault(str(event["session_id"]), []).append(event)

    for session in sessions:
        session_events = events_by_session[str(session["session_id"])]
        assert len(session_events) == session["event_count"]
        timestamps = [event["occurred_at"] for event in session_events]
        assert timestamps == sorted(timestamps)
        assert len(session["actions"]) == session["event_count"]
        assert len(session["hours"]) == session["event_count"]
        assert len(session["interval_seconds"]) == session["event_count"]
        assert len(session["is_new_device"]) == session["event_count"]
        assert len(session["algorithms"]) == session["event_count"]
        assert len(session["outcomes"]) == session["event_count"]


def test_anomalies_include_denied_security_events(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    generate_dataset(small_config(root))
    sessions = load_jsonl(root / "processed/sessions.jsonl")
    events = load_jsonl(root / "raw/audit_events.jsonl")
    hard_attack_ids = {
        str(session["session_id"])
        for session in sessions
        if session["attack_type"] in {
            "private_key_exfiltration",
            "algorithm_downgrade",
            "rapid_master_key_access",
            "evidence_tampering",
        }
    }

    for session_id in hard_attack_ids:
        session_events = [event for event in events if event["session_id"] == session_id]
        assert any(event["outcome"] == "denied" for event in session_events)


def test_users_do_not_cross_data_splits(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    generate_dataset(small_config(root))
    events = load_jsonl(root / "raw/audit_events.jsonl")
    users_by_split: dict[str, set[str]] = {"train": set(), "validation": set(), "test": set()}
    session_splits = {
        row["session_id"]: row["split"]
        for row in load_jsonl(root / "processed/sessions.jsonl")
    }
    for event in events:
        users_by_split[str(session_splits[event["session_id"]])].add(str(event["user_id"]))

    assert users_by_split["train"].isdisjoint(users_by_split["validation"])
    assert users_by_split["train"].isdisjoint(users_by_split["test"])
    assert users_by_split["validation"].isdisjoint(users_by_split["test"])

