from __future__ import annotations

import hashlib
import regex as re
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class SensitiveMatch:
    name: str
    start: int
    end: int
    value: str


class SensitiveInfoFilter:
    def __init__(self, patterns: List[Dict[str, str]], mask_policy: str, redact_placeholder: str) -> None:
        self.compiled = [(p["name"], re.compile(p["regex"])) for p in patterns]
        self.mask_policy = mask_policy
        self.redact_placeholder = redact_placeholder

    def scan(self, text: str) -> List[SensitiveMatch]:
        matches: List[SensitiveMatch] = []
        for name, pattern in self.compiled:
            for m in pattern.finditer(text):
                matches.append(SensitiveMatch(name=name, start=m.start(), end=m.end(), value=m.group(0)))
        return matches

    def mask_value(self, value: str) -> str:
        if self.mask_policy == "redact":
            return self.redact_placeholder
        if self.mask_policy == "hash":
            return f"[HASH:{hashlib.sha256(value.encode()).hexdigest()[:10]}]"
        return ""  # for block mode, caller decides

    def filter_text(self, text: str) -> tuple[str, List[SensitiveMatch]]:
        matches = self.scan(text)
        if not matches:
            return text, []
        # Replace from end to not disturb indices
        mutable = list(text)
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            replacement = self.mask_value(match.value)
            mutable[match.start:match.end] = list(replacement)
        return "".join(mutable), matches