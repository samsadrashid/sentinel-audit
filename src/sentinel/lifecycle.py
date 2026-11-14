"""Audit and check lifecycle (§5, §8.1, §8.2). Illegal transitions raise; outcomes never default to PASS."""

from __future__ import annotations

from collections.abc import Iterable

from .domain.enums import COMPLETE_STATUSES, AuditState, CheckStatus
from .errors import LifecycleError

S = AuditState
TRANSITIONS: dict[AuditState, frozenset[AuditState]] = {
    S.CREATED: frozenset({S.PLANNED}),
    S.PLANNED: frozenset({S.AUTHORIZED, S.BLOCKED}),
    S.AUTHORIZED: frozenset({S.RUNNING}),
    S.RUNNING: frozenset({S.PAUSED, S.CANCELLED, S.COMPLETED, S.INCOMPLETE}),
    S.PAUSED: frozenset({S.RUNNING, S.CANCELLED}),
    S.COMPLETED: frozenset({S.REPORTED}),
    S.INCOMPLETE: frozenset({S.REPORTED}),
    S.CANCELLED: frozenset({S.REPORTED}),
    S.BLOCKED: frozenset({S.REPORTED}),
    S.REPORTED: frozenset(),
}


class AuditStateMachine:
    def __init__(self) -> None:
        self.state = AuditState.CREATED
        self.history: list[AuditState] = [self.state]

    def to(self, new: AuditState) -> None:
        if new not in TRANSITIONS[self.state]:
            raise LifecycleError(f"illegal audit transition {self.state} -> {new}")
        self.state = new
        self.history.append(new)


def final_state(statuses: Iterable[CheckStatus], cancelled: bool = False) -> AuditState:
    """§8.2: Completed only if every check is PASS, FAIL or NOT_APPLICABLE. Empty plans are Incomplete."""
    sts = list(statuses)
    if cancelled:
        return AuditState.CANCELLED
    if sts and all(s in COMPLETE_STATUSES for s in sts):
        return AuditState.COMPLETED
    return AuditState.INCOMPLETE


def overall_result(state: AuditState, statuses: Iterable[CheckStatus]) -> str:
    """Headline result. Only a Completed audit with no FAIL may read PASS; otherwise never PASS."""
    sts = list(statuses)
    # Must be evaluated on the final pre-report state; REPORTED is not accepted because it also follows
    # Incomplete, Cancelled and Blocked.
    if state != AuditState.COMPLETED or not sts or any(s not in COMPLETE_STATUSES for s in sts):
        return "INCOMPLETE" if state == AuditState.COMPLETED else state.value.upper()
    if any(s == CheckStatus.FAIL for s in sts):
        return "FAIL"
    return "PASS"
