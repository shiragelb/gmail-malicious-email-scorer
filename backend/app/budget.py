"""Process-local estimated-spend ledger. Resets at UTC midnight."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from app.config import get_settings

_LEDGER_LOCK = threading.Lock()
_LEDGER: BudgetLedger | None = None


class BudgetLedger:
    """In-memory circuit breaker for optional paid pipelines on this instance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day = _utc_day()
        self._spent = 0.0

    def _roll_day(self) -> None:
        today = _utc_day()
        if self._day != today:
            self._day = today
            self._spent = 0.0

    @property
    def spent_usd(self) -> float:
        with self._lock:
            self._roll_day()
            return round(self._spent, 6)

    @property
    def remaining_usd(self) -> float:
        budget = max(0.0, get_settings().budget_usd_per_day)
        with self._lock:
            self._roll_day()
            return round(max(0.0, budget - self._spent), 6)

    @property
    def optional_paused(self) -> bool:
        budget = max(0.0, get_settings().budget_usd_per_day)
        with self._lock:
            self._roll_day()
            return self._spent + 1e-12 >= budget

    def reserve(self, purpose: str, usd: float) -> bool:
        """Debit ``usd`` if it fits. Zero-cost calls still fail once the cap is hit."""
        del purpose
        amount = max(0.0, float(usd))
        budget = max(0.0, get_settings().budget_usd_per_day)
        with self._lock:
            self._roll_day()
            if self._spent + 1e-12 >= budget:
                return False
            if amount == 0.0:
                return True
            if self._spent + amount > budget + 1e-12:
                return False
            self._spent += amount
            return True

    def release(self, usd: float) -> None:
        amount = max(0.0, float(usd))
        with self._lock:
            self._roll_day()
            self._spent = max(0.0, self._spent - amount)

    def snapshot(self) -> dict:
        budget = max(0.0, get_settings().budget_usd_per_day)
        with self._lock:
            self._roll_day()
            remaining = round(max(0.0, budget - self._spent), 6)
            return {
                "spent_usd": round(self._spent, 6),
                "remaining_usd": remaining,
                "paused": self._spent + 1e-12 >= budget,
                "day": self._day.isoformat(),
                "budget_usd": budget,
            }


def _utc_day():
    return datetime.now(timezone.utc).date()


def ledger() -> BudgetLedger:
    global _LEDGER
    with _LEDGER_LOCK:
        if _LEDGER is None:
            _LEDGER = BudgetLedger()
        return _LEDGER


def reset_ledger() -> None:
    global _LEDGER
    with _LEDGER_LOCK:
        _LEDGER = BudgetLedger()


def estimate_claude_cost(system: str, user: str, max_tokens: int = 400) -> float:
    settings = get_settings()
    input_tokens = max(1, (len(system) + len(user)) // 4)
    output_tokens = max(1, int(max_tokens))
    return (
        input_tokens / 1_000_000 * settings.claude_input_usd_per_million
        + output_tokens / 1_000_000 * settings.claude_output_usd_per_million
    )
