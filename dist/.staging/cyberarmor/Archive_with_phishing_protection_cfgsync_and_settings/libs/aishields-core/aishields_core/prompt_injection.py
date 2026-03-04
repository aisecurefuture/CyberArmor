from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


# Lightweight, deterministic prompt-injection detector with configurable patterns.
PROMPT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bignore (all )?previous instructions", re.I),
    re.compile(r"\bdisregard (the )?(system|previous) prompt", re.I),
    re.compile(r"\bjailbreak\b", re.I),
    re.compile(r"\bbegin(?: new)? system prompt", re.I),
    re.compile(r"\bdeveloper mode\b", re.I),
    re.compile(r"\bno longer follow(ing)? safety", re.I),
    re.compile(r"\bprovide credentials\b", re.I),
    re.compile(r"\bdisable safety\b", re.I),
    re.compile(r"\bprompt injection\b", re.I),
    re.compile(r"\bexecute (bash|powershell|cmd)\b", re.I),
    re.compile(r"\bexfiltrate\b", re.I),
    re.compile(r"\bprint (the )?system prompt\b", re.I),
]

PRIVACY_LEAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bapi[_ -]?key\b", re.I),
    re.compile(r"\bsecret\b", re.I),
    re.compile(r"\bpassword\b", re.I),
    re.compile(r"\bprivate token\b", re.I),
]


@dataclass
class PromptInjectionResult:
    risk_score: float
    matched_indicators: List[str] = field(default_factory=list)
    privacy_leak_risk: bool = False
    reasoning: str = ""

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 0.7

    @property
    def is_medium_risk(self) -> bool:
        return 0.4 <= self.risk_score < 0.7


class PromptInjectionDetector:
    """
    Improved deterministic detector that scores based on pattern hits and context.

    This avoids unsafe pickle loading while providing a stable interface
    that can later be backed by ML models.
    """

    def __init__(self, patterns: list[re.Pattern] | None = None):
        self.patterns = patterns or PROMPT_INJECTION_PATTERNS

    def detect(self, prompt: str) -> PromptInjectionResult:
        text = prompt or ""
        indicators: list[str] = []
        score = 0.0

        for pat in self.patterns:
            if pat.search(text):
                indicators.append(pat.pattern)
                score += 0.2

        privacy_hits = [pat.pattern for pat in PRIVACY_LEAK_PATTERNS if pat.search(text)]
        if privacy_hits:
            indicators.extend(privacy_hits)
            score += 0.15

        # Heuristic: long prompts requesting raw system instructions are riskier.
        if len(text) > 800 and "system" in text.lower():
            score += 0.1

        # If we saw any indicator, enforce a minimum medium score to stay conservative.
        if indicators:
            score = max(score, 0.4)

        # Cap score at 1.0
        score = min(score, 1.0)
        reasoning = (
            "Matched indicators: " + ", ".join(indicators)
            if indicators
            else "No prompt-injection indicators detected"
        )
        return PromptInjectionResult(
            risk_score=score,
            matched_indicators=indicators,
            privacy_leak_risk=bool(privacy_hits),
            reasoning=reasoning,
        )
