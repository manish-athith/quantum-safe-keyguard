"""FastAPI application entry point."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI

from quantum_keyguard.api.auth import router as auth_router
from quantum_keyguard.api.dashboard import router as dashboard_router
from quantum_keyguard.api.health import router as health_router
from quantum_keyguard.api.operations import router as operations_router
from quantum_keyguard.crypto.oqs_vault import OQSVault
from quantum_keyguard.services.container import ServiceContainer


def create_app(
    *,
    database_path: str | Path | None = None,
    model_path: str | Path | None = None,
    vault_factory: Callable[[], Any] = OQSVault,
    detector: Any | None = None,
) -> FastAPI:
    """Create and configure the HTTP application."""
    container = ServiceContainer(
        database_path or os.getenv("KEYGUARD_DATABASE", "runtime/keyguard.db"),
        model_path or os.getenv(
            "KEYGUARD_MODEL", "artifacts/contextual_lstm_detector.json"
        ),
        vault_factory=vault_factory,
        detector=detector,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        container.close()

    application = FastAPI(
        title="Quantum-Safe KeyGuard",
        description=(
            "Quantum-safe key operations with behavioral detection and "
            "automated containment."
        ),
        version="0.3.0",
        lifespan=lifespan,
    )
    application.state.services = container
    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(operations_router)
    application.include_router(dashboard_router)
    return application


app = create_app()

