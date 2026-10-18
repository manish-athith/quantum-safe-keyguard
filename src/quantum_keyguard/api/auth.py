"""Credential login and bearer-session endpoints."""

from __future__ import annotations

from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import Field, SecretStr

from quantum_keyguard.domain.audit import AuditEvent
from quantum_keyguard.domain.common import Identifier, StrictModel
from quantum_keyguard.domain.enums import AuditAction, EventOutcome
from quantum_keyguard.services.auth_service import (
    AuthenticationError,
    AuthPrincipal,
    LoginResult,
)
from quantum_keyguard.services.container import ServiceContainer

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)


class LoginRequest(StrictModel):
    user_id: Identifier
    password: SecretStr
    device_id: Identifier


def services(request: Request) -> ServiceContainer:
    return request.app.state.services


def request_ip(request: Request) -> str:
    host = request.client.host if request.client else "127.0.0.1"
    try:
        return str(ip_address(host))
    except ValueError:
        return "127.0.0.1"


def access_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="bearer authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def current_principal(
    token: str = Depends(access_token),
    container: ServiceContainer = Depends(services),
) -> AuthPrincipal:
    try:
        return container.auth.authenticate(token)
    except AuthenticationError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


@router.post("/login", response_model=LoginResult)
def login(
    payload: LoginRequest,
    request: Request,
    container: ServiceContainer = Depends(services),
) -> LoginResult:
    try:
        result = container.auth.login(
            payload.user_id,
            payload.password.get_secret_value(),
            payload.device_id,
            request_ip(request),
        )
        container.audit.append(
            AuditEvent(
                correlation_id=f"corr_{result.principal.session_id[5:]}",
                session_id=result.principal.session_id,
                user_id=result.principal.user_id,
                role=result.principal.role,
                action=AuditAction.LOGIN,
                outcome=EventOutcome.ALLOWED,
                source_ip=result.principal.source_ip,
                device_id=result.principal.device_id,
                reason_code="authentication_success",
                risk_score=0.0,
                context={"authentication": "password"},
            )
        )
        return result
    except AuthenticationError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error


@router.get("/me", response_model=AuthPrincipal)
def me(principal: AuthPrincipal = Depends(current_principal)) -> AuthPrincipal:
    return principal


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    token: str = Depends(access_token),
    principal: AuthPrincipal = Depends(current_principal),
    container: ServiceContainer = Depends(services),
) -> None:
    try:
        container.audit.append(
            AuditEvent(
                correlation_id=f"corr_{principal.session_id[5:]}",
                session_id=principal.session_id,
                user_id=principal.user_id,
                role=principal.role,
                action=AuditAction.LOGOUT,
                outcome=EventOutcome.ALLOWED,
                source_ip=principal.source_ip,
                device_id=principal.device_id,
                reason_code="logout",
                context={},
            )
        )
        container.auth.logout(token)
    except AuthenticationError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error
