"""zxcvbn-backed strength evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from zxcvbn import zxcvbn


@dataclass(slots=True, frozen=True)
class StrengthResult:
    score: int  # 0..4
    crack_time_display: str
    suggestions: list[str]
    warning: str


class StrengthMeter:
    def evaluate(self, password: str) -> StrengthResult:
        if not password:
            return StrengthResult(score=0, crack_time_display="", suggestions=[], warning="")
        r = zxcvbn(password)
        feedback = r.get("feedback") or {}
        crack_times = r.get("crack_times_display", {})
        return StrengthResult(
            score=int(r.get("score", 0)),
            crack_time_display=str(crack_times.get("offline_slow_hashing_1e4_per_second", "")),
            suggestions=list(feedback.get("suggestions", [])),
            warning=str(feedback.get("warning", "")),
        )
