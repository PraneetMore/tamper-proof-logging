"""
Rule-based risk scoring and tier selection.
"""

from .config import HIGH_THRESHOLD, MEDIUM_THRESHOLD


TYPE_BASE_SCORE = {
    # ─── Authentication / login ─────────────────────────
    "auth": 80,
    "login": 80,
    "logout": 80,
    "authentication": 80,
    "credential": 80,
    "journal_auth": 80,
    "journal_ssh": 80,
    "journal_session": 60,
    "audit_login": 80,
    "audit_user_auth": 80,
    "audit_user_start": 60,
    "audit_user_cmd": 70,
    "audit_cred_acq": 80,

    # ─── Privileged operations ──────────────────────────
    "sudo": 90,
    "privilege": 90,
    "root_command": 90,
    "journal_sudo": 90,
    "windows_4672": 85,

    # ─── Process / service ──────────────────────────────
    "process": 50,
    "execve": 50,
    "service": 50,
    "audit_execve": 50,

    # ─── Windows Security Event IDs ─────────────────────
    "windows_4624": 75,   # successful logon
    "windows_4625": 90,   # failed logon
    "windows_4672": 85,   # special privileges
    "windows_4688": 60,
    "windows_5379": 20,
    "windows_4798": 55,
    "windows_4799": 55,
    "windows_5382": 45,
    "windows_4634": 20,
    "windows_4648": 55,   # explicit credential logon

    # ─── Generic fallbacks ──────────────────────────────
    "journal_generic": 30,

    # ─── Informational ──────────────────────────────────
    "info": 10,
    "debug": 10,
    "trace": 10,
}

NEGATIVE_KEYWORDS = ["failed", "denied", "invalid"]
POSITIVE_KEYWORDS = ["created", "modified", "accessed"]


def score_event_type(event_type: str) -> int:
    et = (event_type or "").lower()
    score = 0
    for key, val in TYPE_BASE_SCORE.items():
        if key in et and val > score:
            score = val
    return score


def score_keywords(content: str) -> int:
    text = (content or "").lower()
    for kw in NEGATIVE_KEYWORDS:
        if kw in text:
            return 15
    for kw in POSITIVE_KEYWORDS:
        if kw in text:
            return 5
    return 0


def risk_score(event_type: str, content: str) -> int:
    return min(100, score_event_type(event_type) + score_keywords(content))


def tier_for(event_type: str, content: str):
    """Return (tier, algorithm, score)."""
    score = risk_score(event_type, content)
    if score >= HIGH_THRESHOLD:
        return "high", "sha512", score
    if score >= MEDIUM_THRESHOLD:
        return "medium", "blake2s", score
    return "low", "batch", score
