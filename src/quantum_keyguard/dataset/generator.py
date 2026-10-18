"""Generate reproducible, secret-free normal and anomalous audit sessions."""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.enums import (
    Algorithm,
    AuditAction,
    EventOutcome,
    Role,
)

NORMAL_TEMPLATES: dict[Role, tuple[tuple[AuditAction, ...], ...]] = {
    Role.VIEWER: (
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.LIST_KEYS, AuditAction.LOGOUT),
    ),
    Role.KEY_OPERATOR: (
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.SIGN, AuditAction.VERIFY, AuditAction.LOGOUT),
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.KEM_ENCAPSULATE, AuditAction.KEM_DECAPSULATE, AuditAction.LOGOUT),
    ),
    Role.KEY_ADMIN: (
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.ROTATE_KEY, AuditAction.VERIFY, AuditAction.LOGOUT),
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.CREATE_KEY, AuditAction.SIGN, AuditAction.VERIFY, AuditAction.LOGOUT),
    ),
    Role.SECURITY_ANALYST: (
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.LOCK_KEY, AuditAction.LIST_KEYS, AuditAction.LOGOUT),
        (AuditAction.LOGIN, AuditAction.LIST_KEYS, AuditAction.REVOKE_SESSION, AuditAction.LOGOUT),
    ),
    Role.SYSTEM_SERVICE: (
        (AuditAction.LOGIN, AuditAction.KEM_ENCAPSULATE, AuditAction.KEM_DECAPSULATE, AuditAction.LOGOUT),
        (AuditAction.LOGIN, AuditAction.SIGN, AuditAction.VERIFY, AuditAction.LOGOUT),
    ),
}

SAFE_REPEAT_ACTIONS: dict[Role, tuple[AuditAction, ...]] = {
    Role.VIEWER: (AuditAction.LIST_KEYS,),
    Role.KEY_OPERATOR: (AuditAction.LIST_KEYS, AuditAction.SIGN, AuditAction.VERIFY, AuditAction.KEM_ENCAPSULATE, AuditAction.KEM_DECAPSULATE),
    Role.KEY_ADMIN: (AuditAction.LIST_KEYS, AuditAction.CREATE_KEY, AuditAction.ROTATE_KEY, AuditAction.SIGN, AuditAction.VERIFY),
    Role.SECURITY_ANALYST: (AuditAction.LIST_KEYS, AuditAction.LOCK_KEY, AuditAction.REVOKE_SESSION),
    Role.SYSTEM_SERVICE: (AuditAction.SIGN, AuditAction.VERIFY, AuditAction.KEM_ENCAPSULATE, AuditAction.KEM_DECAPSULATE),
}

ATTACK_TEMPLATES: dict[str, tuple[AuditAction, ...]] = {
    "private_key_exfiltration": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.EXPORT_PRIVATE_KEY,
        AuditAction.DELETE_AUDIT_LOGS,
    ),
    "algorithm_downgrade": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.DOWNGRADE_ALGORITHM,
        AuditAction.EXPORT_PRIVATE_KEY,
    ),
    "rapid_master_key_access": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.EXPORT_PRIVATE_KEY,
    ),
    "evidence_tampering": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.SIGN,
        AuditAction.DELETE_AUDIT_LOGS,
        AuditAction.EXPORT_PRIVATE_KEY,
    ),
    "signing_burst": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.SIGN,
        AuditAction.SIGN,
        AuditAction.SIGN,
        AuditAction.SIGN,
        AuditAction.LOGOUT,
    ),
    "kem_decapsulation_burst": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.KEM_DECAPSULATE,
        AuditAction.KEM_DECAPSULATE,
        AuditAction.KEM_DECAPSULATE,
        AuditAction.LOGOUT,
    ),
    "unusual_key_rotation": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.ROTATE_KEY,
        AuditAction.CREATE_KEY,
        AuditAction.ROTATE_KEY,
        AuditAction.ROTATE_KEY,
        AuditAction.LOGOUT,
    ),
    "compromised_service": (
        AuditAction.LOGIN,
        AuditAction.KEM_ENCAPSULATE,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.SIGN,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.LOGOUT,
    ),
    "off_hours_recon": (
        AuditAction.LOGIN,
        AuditAction.LIST_KEYS,
        AuditAction.LIST_KEYS,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.LIST_KEYS,
        AuditAction.LOGOUT,
    ),
}

DENIED_ACTIONS = {
    AuditAction.EXPORT_PRIVATE_KEY,
    AuditAction.DOWNGRADE_ALGORITHM,
    AuditAction.DELETE_AUDIT_LOGS,
}


@dataclass(frozen=True)
class DatasetConfig:
    output_root: Path
    normal_sessions: int = 21_000
    anomalous_sessions: int = 9_000
    min_actions: int = 5
    max_actions: int = 30
    seed: int = 20_261_017

    def __post_init__(self) -> None:
        if self.normal_sessions < 10:
            raise ValueError("normal_sessions must be at least 10")
        if self.anomalous_sessions < 2:
            raise ValueError("anomalous_sessions must be at least 2")
        if self.min_actions < 5:
            raise ValueError("min_actions must be at least 5")
        if self.max_actions < self.min_actions:
            raise ValueError("max_actions must not be smaller than min_actions")


@dataclass(frozen=True)
class SessionSpec:
    session_id: str
    label: str
    split: str
    attack_type: str | None


def _split_assignments(config: DatasetConfig, rng: random.Random) -> list[SessionSpec]:
    normal_ids = list(range(1, config.normal_sessions + 1))
    anomaly_ids = list(range(1, config.anomalous_sessions + 1))
    rng.shuffle(normal_ids)
    rng.shuffle(anomaly_ids)

    train_normal = config.normal_sessions * 70 // 100
    validation_normal = config.normal_sessions * 15 // 100
    train_anomalous = config.anomalous_sessions * 60 // 100
    validation_anomalous = config.anomalous_sessions * 20 // 100

    normal_split: dict[int, str] = {}
    for index, session_number in enumerate(normal_ids):
        if index < train_normal:
            split = "train"
        elif index < train_normal + validation_normal:
            split = "validation"
        else:
            split = "test"
        normal_split[session_number] = split

    anomaly_split: dict[int, str] = {}
    for index, session_number in enumerate(anomaly_ids):
        if index < train_anomalous:
            split = "train"
        elif index < train_anomalous + validation_anomalous:
            split = "validation"
        else:
            split = "test"
        anomaly_split[session_number] = split

    specs = [
        SessionSpec(
            session_id=f"sess_n_{number:06d}",
            label="normal",
            split=normal_split[number],
            attack_type=None,
        )
        for number in range(1, config.normal_sessions + 1)
    ]
    attack_names = tuple(ATTACK_TEMPLATES)
    specs.extend(
        SessionSpec(
            session_id=f"sess_a_{number:06d}",
            label="anomalous",
            split=anomaly_split[number],
            attack_type=attack_names[(number - 1) % len(attack_names)],
        )
        for number in range(1, config.anomalous_sessions + 1)
    )
    return specs


def _normal_actions(
    rng: random.Random, role: Role, target_count: int
) -> list[AuditAction]:
    template = list(rng.choice(NORMAL_TEMPLATES[role]))
    while len(template) < target_count:
        template.insert(-1, rng.choice(SAFE_REPEAT_ACTIONS[role]))
    return template[: target_count - 1] + [AuditAction.LOGOUT]


def _anomalous_actions(
    rng: random.Random, attack_type: str, target_count: int
) -> tuple[list[AuditAction], int]:
    actions = list(ATTACK_TEMPLATES[attack_type])
    suspicious_repeat = (
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.LIST_KEYS,
        AuditAction.SIGN,
    )
    while len(actions) < target_count:
        insert_at = max(2, len(actions) - 1)
        actions.insert(insert_at, rng.choice(suspicious_repeat))
    actions = actions[:target_count]
    onset = 0 if attack_type == "off_hours_recon" else min(2, len(actions) - 1)
    return actions, onset


def _algorithm_for(action: AuditAction, rng: random.Random) -> Algorithm | None:
    if action in {AuditAction.KEM_ENCAPSULATE, AuditAction.KEM_DECAPSULATE}:
        return Algorithm.ML_KEM_768
    if action in {AuditAction.SIGN, AuditAction.VERIFY}:
        return Algorithm.ML_DSA_65
    if action is AuditAction.CREATE_KEY:
        return rng.choice((Algorithm.ML_KEM_768, Algorithm.ML_DSA_65))
    if action is AuditAction.DOWNGRADE_ALGORITHM:
        return Algorithm.RSA_1024
    if action in {
        AuditAction.ROTATE_KEY,
        AuditAction.ACCESS_MASTER_KEY,
        AuditAction.EXPORT_PRIVATE_KEY,
        AuditAction.LOCK_KEY,
        AuditAction.REVOKE_KEY,
    }:
        return Algorithm.ML_DSA_65
    return None


def _needs_key(action: AuditAction) -> bool:
    return action not in {
        AuditAction.LOGIN,
        AuditAction.LOGOUT,
        AuditAction.LIST_KEYS,
        AuditAction.DELETE_AUDIT_LOGS,
        AuditAction.REVOKE_SESSION,
    }


def _reason_for(action: AuditAction) -> str | None:
    return {
        AuditAction.EXPORT_PRIVATE_KEY: "rule_private_export",
        AuditAction.DOWNGRADE_ALGORITHM: "rule_weak_algorithm",
        AuditAction.DELETE_AUDIT_LOGS: "rule_evidence_tampering",
    }.get(action)


def _session_events(
    spec: SessionSpec,
    config: DatasetConfig,
    rng: random.Random,
    ordinal: int,
) -> tuple[list[AuditEvent], dict[str, object]]:
    is_anomalous = spec.label == "anomalous"
    event_count = rng.randint(config.min_actions, config.max_actions)
    if is_anomalous:
        attack_type = spec.attack_type or ""
        actions, attack_start_index = _anomalous_actions(rng, attack_type, event_count)
        role = {
            "signing_burst": Role.KEY_OPERATOR,
            "kem_decapsulation_burst": Role.SYSTEM_SERVICE,
            "compromised_service": Role.SYSTEM_SERVICE,
            "off_hours_recon": Role.KEY_ADMIN,
        }.get(attack_type, Role.KEY_ADMIN)
        hour = (
            rng.choice((0, 1, 2, 3, 4, 5, 22, 23))
            if attack_type == "off_hours_recon" or rng.random() < 0.55
            else rng.randint(7, 20)
        )
        user_id = f"{role.value}_{spec.split}_compromised_{(ordinal % 700) + 1:04d}"
        is_new_device = rng.random() < 0.6
        device_kind = "new" if is_new_device else "known"
        device_id = f"device_{spec.split}_{device_kind}_{(ordinal % 900) + 1:04d}"
        source_network = rng.choice(("203.0.113", "198.51.100", "192.0.2"))
    else:
        role = rng.choice(tuple(NORMAL_TEMPLATES))
        actions = _normal_actions(rng, role, event_count)
        attack_start_index = None
        hour = (
            rng.choice((5, 6, 21, 22)) if rng.random() < 0.08 else rng.randint(7, 20)
        )
        user_id = f"{role.value}_{spec.split}_{(ordinal % 1400) + 1:04d}"
        is_new_device = rng.random() < 0.1
        device_kind = "new" if is_new_device else "known"
        device_id = f"device_{spec.split}_{device_kind}_{(ordinal % 1800) + 1:04d}"
        source_network = rng.choice(("192.0.2", "198.51.100"))

    day_offset = rng.randint(0, 59)
    minute = rng.randint(0, 59)
    start = datetime(2026, 1, 5, hour, minute, tzinfo=timezone.utc) + timedelta(
        days=day_offset
    )
    source_ip = f"{source_network}.{(ordinal % 250) + 1}"
    correlation_id = spec.session_id.replace("sess", "corr", 1)
    key_id = f"finance_key_{(ordinal % 25) + 1:03d}"

    events: list[AuditEvent] = []
    hours: list[int] = []
    intervals: list[int] = []
    algorithms: list[str | None] = []
    outcomes: list[str] = []
    elapsed_seconds = 0
    for index, action in enumerate(actions):
        if is_anomalous and spec.attack_type in {
            "rapid_master_key_access",
            "signing_burst",
            "kem_decapsulation_burst",
        }:
            interval = rng.randint(1, 25)
        else:
            interval = rng.randint(10, 240)
        if index == 0:
            interval = 0
        elapsed_seconds += interval
        occurred_at = start + timedelta(seconds=elapsed_seconds)
        hours.append(occurred_at.hour)
        intervals.append(interval)
        if action in DENIED_ACTIONS:
            outcome = EventOutcome.DENIED
        elif not is_anomalous and action not in {AuditAction.LOGIN, AuditAction.LOGOUT} and rng.random() < 0.025:
            outcome = EventOutcome.FAILED
        else:
            outcome = EventOutcome.ALLOWED
        algorithm = _algorithm_for(action, rng)
        event = AuditEvent(
            event_id=f"evt_{spec.session_id[5:]}_{index:03d}",
            correlation_id=correlation_id,
            session_id=spec.session_id,
            user_id=user_id,
            role=role,
            action=action,
            outcome=outcome,
            occurred_at=occurred_at,
            source_ip=source_ip,
            device_id=device_id,
            key_id=key_id if _needs_key(action) else None,
            algorithm=algorithm,
            reason_code=_reason_for(action),
            context={
                "synthetic": True,
                "hour": occurred_at.hour,
                "is_new_device": is_new_device,
                "actions_in_session": index + 1,
                "interval_seconds": interval,
            },
        )
        events.append(event)
        algorithms.append(algorithm.value if algorithm is not None else None)
        outcomes.append(outcome.value)

    session_document: dict[str, object] = {
        "session_id": spec.session_id,
        "label": spec.label,
        "split": spec.split,
        "attack_type": spec.attack_type,
        "attack_start_index": attack_start_index,
        "role": role.value,
        "event_count": len(events),
        "actions": [event.action.value for event in events],
        "hours": hours,
        "interval_seconds": intervals,
        "is_new_device": [is_new_device] * len(events),
        "algorithms": algorithms,
        "outcomes": outcomes,
    }
    return events, session_document


def _json_line(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _write_dataset(
    specs: Iterable[SessionSpec], config: DatasetConfig, rng: random.Random
) -> dict[str, object]:
    raw_dir = config.output_root / "raw"
    processed_dir = config.output_root / "processed"
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    event_path = raw_dir / "audit_events.jsonl"
    session_path = processed_dir / "sessions.jsonl"
    event_temp = event_path.with_suffix(".jsonl.tmp")
    session_temp = session_path.with_suffix(".jsonl.tmp")

    split_counts: dict[str, dict[str, int]] = {
        "train": {"normal": 0, "anomalous": 0},
        "validation": {"normal": 0, "anomalous": 0},
        "test": {"normal": 0, "anomalous": 0},
    }
    event_total = 0
    attack_counts: dict[str, int] = {name: 0 for name in ATTACK_TEMPLATES}

    with event_temp.open("w", encoding="utf-8", newline="\n") as event_file, session_temp.open(
        "w", encoding="utf-8", newline="\n"
    ) as session_file:
        for ordinal, spec in enumerate(specs, start=1):
            events, session_document = _session_events(spec, config, rng, ordinal)
            for event in events:
                event_file.write(_json_line(event.model_dump(mode="json")))
            session_file.write(_json_line(session_document))
            event_total += len(events)
            split_counts[spec.split][spec.label] += 1
            if spec.attack_type:
                attack_counts[spec.attack_type] += 1

    event_temp.replace(event_path)
    session_temp.replace(session_path)

    summary: dict[str, object] = {
        "seed": config.seed,
        "normal_sessions": config.normal_sessions,
        "anomalous_sessions": config.anomalous_sessions,
        "total_sessions": config.normal_sessions + config.anomalous_sessions,
        "total_events": event_total,
        "min_actions": config.min_actions,
        "max_actions": config.max_actions,
        "splits": split_counts,
        "attack_types": attack_counts,
        "files": {
            "events": str(event_path.as_posix()),
            "sessions": str(session_path.as_posix()),
        },
    }
    summary_path = processed_dir / "dataset_summary.json"
    summary_temp = summary_path.with_suffix(".json.tmp")
    with summary_temp.open("w", encoding="utf-8", newline="\n") as summary_file:
        summary_file.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    summary_temp.replace(summary_path)
    return summary


def generate_dataset(config: DatasetConfig) -> dict[str, object]:
    """Generate the full event and session dataset atomically."""
    rng = random.Random(config.seed)
    specs = _split_assignments(config, rng)
    return _write_dataset(specs, config, rng)


def parse_args(arguments: Iterator[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=Path("data"))
    parser.add_argument("--normal-sessions", type=int, default=21_000)
    parser.add_argument("--anomalous-sessions", type=int, default=9_000)
    parser.add_argument("--min-actions", type=int, default=5)
    parser.add_argument("--max-actions", type=int, default=30)
    parser.add_argument("--seed", type=int, default=20_261_017)
    return parser.parse_args(arguments)


def main() -> None:
    args = parse_args()
    summary = generate_dataset(
        DatasetConfig(
            output_root=args.output_root,
            normal_sessions=args.normal_sessions,
            anomalous_sessions=args.anomalous_sessions,
            min_actions=args.min_actions,
            max_actions=args.max_actions,
            seed=args.seed,
        )
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

