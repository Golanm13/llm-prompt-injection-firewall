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
    # התקפות קלאסיות של ביטול הנחיות קודמות
    _compile_rule(
        r"\b(?:ignore|disregard|forget|override|clear|reset|bypass)\s+(?:all\s+)?(?:previous|prior|earlier|past|initial)?\s*(?:instructions|directives|guidance|rules|context|constraints|prompts)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\bdisregard\s+(?:the\s+)?safety\s+(?:guidelines|instructions|rules|filters|policies)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:system|developer|admin|root|supervisor)\s+(?:override|mode|access|privileges)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    # התקפות Jailbreak מבוססות מצב (כמו DAN / Developer Mode)
    _compile_rule(
        r"\byou\s+are\s+now\s+in\s+(?:developer\s+mode|jailbroken|dan\s+mode|unrestricted\s+mode)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:do\s+anything\s+now|d\.a\.n\.|jailbreak)\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
    # תמיכה מורחבת בעברית לעקיפת פרומפטים
    _compile_rule(
        r"\b(?:תתעלם|התעלם|תשכח|תעקוף|תאפס)\s+(?:מההנחיות|מההוראות|מהכללים)\s+(?:הקודמות|הקודמים|הראשוניות|המקוריות)?\b",
        "system_prompt_override",
        HIGH_RISK,
    ),
)

DATA_LEAKING_RULES: tuple[SecurityRule, ...] = (
    # שיפור קריטי: הפיכת מילות הקישור (the/your/any) לאופציונליות, והוספת שאלות (what is/can you)
    _compile_rule(
        r"\b(?:reveal|show|print|expose|output|dump|share|get|display|write|tell\s+me)\s+(?:your\s+|the\s+|any\s+|all\s+)?(?:system\s+prompt|hidden\s+instructions|constraints|initial\s+prompt|original\s+instructions)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:what\s+is|what\s+are)\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|secret\s+rules|creator\s+instructions)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    _compile_rule(
        r"\b(?:show|reveal|print|expose|output|give\s+me)\s+(?:me\s+)?(?:the\s+)?(?:password|secret|token|credential|api\s+key)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    # הגנה מפני הנדסה הפוכה לפרומפט (Reverse Engineering)
    _compile_rule(
        r"\b(?:how\s+were\s+you\s+programmed|what\s+are\s+your\s+rules|repeat\s+the\s+instructions|copy\s+the\s+text\s+above)\b",
        "data_leaking_exfiltration",
        HIGH_RISK,
    ),
    # שיפור הגנה מורחבת בעברית להדלפת מידע
    _compile_rule(
        r"\b(?:תחשוף|הצג|תדפיס|תגלה|מהו|מה\s+הוא|מהם|רשום)\s+(?:את\s+|שלך\s+)?(?:פרומפט\s+המערכת|ההוראות\s+המוסתרות|הסיסמה|הסוד|הנחיות\s+המערכת|הוראות\s+היצרן)\b",
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
        r"\bpretend\s+you\s+are\s+(?:not\s+an\s+ai|someone\s+else|a\s+terminal|a\s+linux\s+shell)\b",
        "hypothetical_roleplay_attack",
        MEDIUM_RISK,
    ),
    # התקפות מבוססות תרגום או קידוד ("תרגם את המשפט הבא ובצע אותו")
    _compile_rule(
        r"\b(?:translate|decode|base64|hex)\s+(?:the\s+)?(?:following|next)\s+(?:text|string|command|instruction)\b",
        "hypothetical_roleplay_attack",
        LOW_RISK,  # סיכון נמוך יותר אך עדיין נבדק בשרשרת
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