"""Stable scoring contract shared by LSTM and fallback detectors."""

from __future__ import annotations

from typing import Protocol, Sequence

from pydantic import Field

from quantum_keyguard.domain.common import StrictModel


class RiskAssessment(StrictModel):
    model_name: str = Field(min_length=3, max_length=100)
    raw_score: float = Field(ge=0.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0)
    is_anomalous: bool
    signals: tuple[str, ...]


class SequenceDetector(Protocol):
    def score(self, actions: Sequence[str]) -> RiskAssessment:
        """Score one ordered action sequence."""

