"""Explicit enumerations for every lifecycle and result state (discovery.md §5, §6.3, §7, §8)."""

from enum import StrEnum


class CheckStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - check status, not a credential
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


#: Statuses that count as "finished" for an audit to be Completed (§8.2).
COMPLETE_STATUSES = frozenset({CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.NOT_APPLICABLE})


class AuditState(StrEnum):
    CREATED = "Created"
    PLANNED = "Planned"
    AUTHORIZED = "Authorized"
    BLOCKED = "Blocked"
    RUNNING = "Running"
    PAUSED = "Paused"
    CANCELLED = "Cancelled"
    COMPLETED = "Completed"
    INCOMPLETE = "Incomplete"
    REPORTED = "Reported"


class AuditMode(StrEnum):
    """D-21. RED TEAM is deliberately absent: excluded from V1."""

    READ = "READ"
    VALIDATE = "VALIDATE"


class AuditLevel(StrEnum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class ActivityClass(StrEnum):
    """§10 isolation matrix. B3 exists only so it can be refused explicitly (D-15)."""

    S1 = "S1"
    S2 = "S2"
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    A1 = "A1"


class Environment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


class FindingState(StrEnum):
    UNVERIFIED = "unverified"
    SUSPECTED = "suspected"
    VERIFIED = "verified"
    HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE = "HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FindingOrigin(StrEnum):
    SCANNER = "scanner"
    AGENT = "agent"
    MODEL = "model"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ApprovalAction(StrEnum):
    """The trust-anchor actions (§11.3), plus `release.publish` (D-74). `allowlist.change` was removed by
    D-42: adapter allowlists and pinned hashes are part of the policy file and change only via
    `policy.change`."""

    AUTHORIZE_RECORD = "authorize_record"
    REVOKE_RECORD = "revoke_record"
    REVIEW_VERIFY_NO_EVIDENCE = "review.verify_no_evidence"
    REVIEW_ACCEPT_RISK = "review.accept_risk"
    SUPPRESS = "suppress"
    POLICY_CHANGE = "policy.change"
    KEY_ROTATE = "key.rotate"
    KEY_REVOKE = "key.revoke"
    #: D-74: signs a Sentinel release (SHA256SUMS) on the signing device. Never used by an audit.
    RELEASE_PUBLISH = "release.publish"


ONE_TIME_ACTIONS = frozenset(
    {
        ApprovalAction.REVOKE_RECORD,
        ApprovalAction.KEY_ROTATE,
        ApprovalAction.KEY_REVOKE,
        ApprovalAction.RELEASE_PUBLISH,
    }
)
STANDING_ACTIONS = frozenset(set(ApprovalAction) - ONE_TIME_ACTIONS)


class KeyRole(StrEnum):
    RUN = "run"
    OPERATOR = "operator"
