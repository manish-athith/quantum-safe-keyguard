"""Authenticated SOC snapshot API and judge-facing dashboard assets."""

from __future__ import annotations

import platform
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, RedirectResponse

from quantum_keyguard.api.auth import current_principal, services
from quantum_keyguard.domain.common import Identifier, StrictModel, utc_now
from quantum_keyguard.domain.enums import (
    AlertSeverity,
    Algorithm,
    AuditAction,
    EventOutcome,
    KeyStatus,
    PolicyEffect,
    SessionStatus,
)
from quantum_keyguard.services.auth_service import AuthPrincipal
from quantum_keyguard.services.container import ServiceContainer

router = APIRouter()
WEB_ROOT = Path(__file__).resolve().parents[1] / "web"
ASSET_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


class PlatformStatus(StrictModel):
    host: str
    architecture: str
    crypto_backend: str
    algorithms: tuple[str, ...]
    model: str
    model_threshold: float
    vault_persistence: str
    retired_keys_on_startup: int


class DashboardMetrics(StrictModel):
    active_keys: int
    locked_keys: int
    revoked_sessions: int
    critical_alerts: int
    audited_events: int


class DashboardKey(StrictModel):
    key_id: Identifier
    algorithm: Algorithm
    status: KeyStatus
    created_at: datetime


class DashboardSession(StrictModel):
    session_id: Identifier
    status: SessionStatus
    device_id: Identifier
    created_at: datetime
    revoked_at: datetime | None
    current: bool


class DashboardAlert(StrictModel):
    alert_id: Identifier
    correlation_id: Identifier
    severity: AlertSeverity
    summary: str
    created_at: datetime
    acknowledged: bool


class DashboardEvent(StrictModel):
    event_id: Identifier
    correlation_id: Identifier
    action: AuditAction
    outcome: EventOutcome
    occurred_at: datetime
    key_id: Identifier | None
    algorithm: Algorithm | None
    reason_code: Identifier | None
    risk_score: float | None
    policy_effect: PolicyEffect | None
    risk_signals: tuple[str, ...]
    triggered_rules: tuple[Identifier, ...]


class DashboardSnapshot(StrictModel):
    generated_at: datetime
    principal: AuthPrincipal
    platform: PlatformStatus
    metrics: DashboardMetrics
    keys: tuple[DashboardKey, ...]
    sessions: tuple[DashboardSession, ...]
    alerts: tuple[DashboardAlert, ...]
    events: tuple[DashboardEvent, ...]


def _asset(name: str, media_type: str) -> FileResponse:
    return FileResponse(WEB_ROOT / name, media_type=media_type, headers=ASSET_HEADERS)


@router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=307)


@router.get("/dashboard", include_in_schema=False)
def dashboard() -> FileResponse:
    return _asset("dashboard.html", "text/html")


@router.get("/dashboard/assets/dashboard.css", include_in_schema=False)
def dashboard_css() -> FileResponse:
    return _asset("dashboard.css", "text/css")


@router.get("/dashboard/assets/dashboard.js", include_in_schema=False)
def dashboard_js() -> FileResponse:
    return _asset("dashboard.js", "application/javascript")


@router.get(
    "/dashboard/snapshot",
    response_model=DashboardSnapshot,
    tags=["SOC dashboard"],
)
def snapshot(
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> DashboardSnapshot:
    keys = container.state.list_keys()
    sessions = container.state.list_sessions_by_user(principal.user_id)
    alerts = container.state.list_alerts_by_user(principal.user_id)
    events = container.audit.list_by_user(principal.user_id)
    machine = platform.machine().lower()
    platform_name = (
        "IBM LinuxONE" if machine in {"s390x", "s390"} else "Development host"
    )

    event_rows: list[DashboardEvent] = []
    for event in events:
        context: dict[str, Any] = event.context
        policy_effect = context.get("policy_effect")
        event_rows.append(
            DashboardEvent(
                event_id=event.event_id,
                correlation_id=event.correlation_id,
                action=event.action,
                outcome=event.outcome,
                occurred_at=event.occurred_at,
                key_id=event.key_id,
                algorithm=event.algorithm,
                reason_code=event.reason_code,
                risk_score=event.risk_score,
                policy_effect=PolicyEffect(policy_effect) if policy_effect else None,
                risk_signals=tuple(context.get("risk_signals", ())),
                triggered_rules=tuple(context.get("triggered_rules", ())),
            )
        )

    threshold = float(getattr(container.detector, "threshold", 0.85))
    model_name = str(getattr(container.detector, "model_name", "contextual-detector"))
    return DashboardSnapshot(
        generated_at=utc_now(),
        principal=principal,
        platform=PlatformStatus(
            host=platform_name,
            architecture=machine or "unknown",
            crypto_backend=(
                "Native liboqs 0.16.0 (software-backed)"
                if machine in {"s390x", "s390"}
                else "LinuxONE liboqs target (local test adapter)"
            ),
            algorithms=("ML-KEM-768", "ML-DSA-65", "AES-256-GCM"),
            model=model_name,
            model_threshold=threshold,
            vault_persistence="Process-memory prototype",
            retired_keys_on_startup=container.retired_ephemeral_keys,
        ),
        metrics=DashboardMetrics(
            active_keys=sum(item.status is KeyStatus.ACTIVE for item in keys),
            locked_keys=sum(item.status is KeyStatus.LOCKED for item in keys),
            revoked_sessions=sum(
                item.status is SessionStatus.REVOKED for item in sessions
            ),
            critical_alerts=sum(
                item.severity is AlertSeverity.CRITICAL for item in alerts
            ),
            audited_events=len(events),
        ),
        keys=tuple(
            DashboardKey(
                key_id=item.key_id,
                algorithm=item.algorithm,
                status=item.status,
                created_at=item.created_at,
            )
            for item in keys
        ),
        sessions=tuple(
            DashboardSession(
                session_id=item.session_id,
                status=item.status,
                device_id=item.device_id,
                created_at=item.created_at,
                revoked_at=item.revoked_at,
                current=item.session_id == principal.session_id,
            )
            for item in sessions
        ),
        alerts=tuple(
            DashboardAlert(
                alert_id=item.alert_id,
                correlation_id=item.correlation_id,
                severity=item.severity,
                summary=item.summary,
                created_at=item.created_at,
                acknowledged=item.acknowledged,
            )
            for item in alerts
        ),
        events=tuple(event_rows),
    )
