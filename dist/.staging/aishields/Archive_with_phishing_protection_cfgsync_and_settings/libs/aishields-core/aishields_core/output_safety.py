from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


LEAK_PATTERNS = [
    re.compile(r"BEGIN RSA PRIVATE KEY"),
    re.compile(r"ssh-rsa"),
    re.compile(r"-----BEGIN CERTIFICATE-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key pattern
    re.compile(r"(?i)password\\s*[:=]"),
    re.compile(r"(?i)token\\s*[:=]"),
]

COMMAND_PATTERNS = [
    re.compile(r"rm\\s+-rf"),
    re.compile(r"curl\\s+http"),
    re.compile(r"powershell -enc", re.I),
    re.compile(r"bash -c", re.I),
    re.compile(r"wget\\s+http", re.I),
]


@dataclass
class OutputSafetyResult:
    leak_indicators: List[str] = field(default_factory=list)
    dangerous_commands: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    @property
    def is_block(self) -> bool:
        return self.risk_score >= 0.7


class OutputSafetyAnalyzer:
    def __init__(self):
        ...

    def analyze(self, text: str) -> OutputSafetyResult:
        leak_hits = [pat.pattern for pat in LEAK_PATTERNS if pat.search(text or "")]
        cmd_hits = [pat.pattern for pat in COMMAND_PATTERNS if pat.search(text or "")]
        score = 0.0
        if leak_hits:
            score += 0.6
        if cmd_hits:
            score += 0.3
        score = min(score, 1.0)
        return OutputSafetyResult(leak_indicators=leak_hits, dangerous_commands=cmd_hits, risk_score=score)
