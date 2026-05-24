"""Decision logic service for prompt filtering.

In a full firewall, this layer would aggregate and execute multiple policy
engines (regex rules, classifier-based checks, abuse signals, allow-lists, etc.).
For this stage, the logic is intentionally simple and deterministic.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DecisionResult:
    """Outcome of evaluating a prompt against firewall policy rules."""

    allowed: bool
    reason: str


def evaluate_prompt(prompt: str) -> DecisionResult:
    """Evaluate a prompt and return an allow/block decision.

    Rule (dummy implementation):
    - Block if prompt contains the substring "HACK" in a case-insensitive match.
    - Otherwise, allow the prompt.
    """

    if "hack" in prompt.lower():
        return DecisionResult(
            allowed=False,
            reason="Prompt blocked by firewall policy: suspicious keyword detected.",
        )

    return DecisionResult(allowed=True, reason="Prompt accepted.")
