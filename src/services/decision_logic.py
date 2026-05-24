"""Decision logic service for prompt filtering.

This module implements a conservative, regex-driven guardrail engine for
detecting prompt injection attempts. Rules are grouped into security
categories and precompiled at import time for fast repeated evaluation.
"""

from dataclasses import dataclass
import re
from typing import Optional, Sequence


HIGH_RISK = "HIGH"
MEDIUM_RISK = "MEDIUM"
LOW_RISK = "LOW"
NO_RISK = "NONE"

_RISK_RANK = {LOW_RISK: 1, MEDIUM_RISK: 2, HIGH_RISK: 3}


@dataclass(frozen=True)
class SecurityRule:
    """A single compiled regex guardrail rule."""

    pattern: re.Pattern[str]
    category: str
    severity: str


@dataclass(frozen=True)
class PromptSafetyResult:
    """Structured result from prompt safety evaluation."""

    is_safe: bool
    block_reason: Optional[str]
    category: Optional[str]
    risk_score: str


@dataclass(frozen=True)
class DecisionResult:
    """Backward-compatible allow/block result for existing API wiring."""

    allowed: bool
    reason: str


def _compile_rule(pattern: str, category: str, severity: str) -> SecurityRule:
    """Compile a regex rule once and store its metadata alongside it."""

    return SecurityRule(
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        category=category,
        severity=severity,
    )


SYSTEM_PROMPT_OVERRIDE_RULES: tuple[SecurityRule, ...] = (
    _compile_rule(
        r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions|directives|guidance)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\bdisregard\s+(?:the\s+)?safety\s+(?:guidelines|instructions|rules)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:system|developer)\s+override\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\byou\s+are\s+now\s+in\s+(?:developer\s+mode|jailbroken)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:תתעלם|התעלם)\s+מההנחיות\s+הקודמות\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
)

DATA_LEAKING_RULES: tuple[SecurityRule, ...] = (
    _compile_rule(
        r"\b(?:reveal|show|print|expose|output)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions|constraints)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:show|reveal|print|expose)\s+(?:me\s+)?(?:the\s+)?(?:password|secret)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:print|display|show)\s+(?:the\s+)?(?:hidden\s+)?instructions\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:תחשוף|הצג|תדפיס)\s+(?:את\s+)?(?:פרומפט\s+המערכת|ההוראות\s+המוסתרות|הסיסמה|הסוד)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
)

ROLEPLAY_ATTACK_RULES: tuple[SecurityRule, ...] = (
    _compile_rule(
        r"\blet'?s\s+play\s+a\s+game\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bhypothetically\s+speaking\s+how\s+would\s+you\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bact\s+as\s+an\s+evil\s+ai\s+without\s+restrictions\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bpretend\s+you\s+are\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bבוא\s+נשחק\s+משחק\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bתיאורטית\s+איך\s+היית\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    _compile_rule(
        r"\bתתנהג\s+כמו\s+בינה\s+מלאכותית\s+רעה\s+בלי\s+הגבלות\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
)

ALL_SECURITY_RULES: tuple[SecurityRule, ...] = (
    *SYSTEM_PROMPT_OVERRIDE_RULES,
    *DATA_LEAKING_RULES,
    *ROLEPLAY_ATTACK_RULES,
)


def _select_risk_score(matches: Sequence[SecurityRule]) -> str:
    """Return the highest risk score observed across all matching rules."""

    if not matches:
        return NO_RISK

    highest = max(matches, key=lambda rule: _RISK_RANK[rule.severity])
    return highest.severity


def is_prompt_safe(prompt: str) -> PromptSafetyResult:
    """Evaluate a prompt using categorized, precompiled injection rules.

    The engine is intentionally conservative: any matched rule is treated as a
    block condition. Severity is used to express the risk weight of the match,
    while the category identifies the guardrail bucket that fired first at the
    highest observed risk level.
    """

    matching_rules = [rule for rule in ALL_SECURITY_RULES if rule.pattern.search(prompt)]

    if not matching_rules:
        return PromptSafetyResult(
            is_safe=True,
            block_reason=None,
            category=None,
            risk_score=NO_RISK,
        )

    selected_risk = _select_risk_score(matching_rules)
    selected_matches = [rule for rule in matching_rules if rule.severity == selected_risk]
    selected_rule = selected_matches[0]

    return PromptSafetyResult(
        is_safe=False,
        block_reason=(
            f"Blocked by firewall policy: {selected_risk} risk prompt injection detected "
            f"in {selected_rule.category}."
        ),
        category=selected_rule.category,
        risk_score=selected_risk,
    )


def evaluate_prompt(prompt: str) -> DecisionResult:
    """Backward-compatible wrapper used by the API route.

    Existing integration code expects an allow/block result. New callers should
    prefer :func:`is_prompt_safe` for richer metadata.
    """

    safety = is_prompt_safe(prompt)
    return DecisionResult(
        allowed=safety.is_safe,
        reason=safety.block_reason or "Prompt accepted.",
    )
