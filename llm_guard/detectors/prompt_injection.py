from __future__ import annotations

import regex as re
from dataclasses import dataclass
from typing import List


@dataclass
class PromptInjectionResult:
    is_malicious: bool
    reasons: List[str]
    requires_human_approval: bool


class PromptInjectionDetector:
    def __init__(self, keywords: List[str], patterns: List[str], allowed_prompt_list: List[str], require_human_approval_on_executable_requests: bool) -> None:
        self.keywords = [k.lower() for k in keywords]
        self.patterns = [re.compile(p) for p in patterns]
        self.allowed_prompt_list = [a.lower() for a in allowed_prompt_list]
        self.require_human_approval = require_human_approval_on_executable_requests

    def analyze(self, user_text: str) -> PromptInjectionResult:
        lower_text = user_text.lower()
        reasons: List[str] = []

        for keyword in self.keywords:
            if keyword and keyword in lower_text:
                reasons.append(f"keyword:{keyword}")

        for pattern in self.patterns:
            if pattern.search(user_text):
                reasons.append(f"pattern:{pattern.pattern}")

        is_executable_intent = any(x in lower_text for x in [
            "run ",
            "execute ",
            "call api",
            "系统指令",
            "管理员",
            "bypass",
        ])

        is_malicious = len(reasons) > 0 or (is_executable_intent and self.require_human_approval)

        requires_human_approval = is_executable_intent and self.require_human_approval

        # Simple allow-list: if user intent clearly matches allowed tasks, downgrade
        if self.allowed_prompt_list:
            for allowed in self.allowed_prompt_list:
                if allowed in lower_text:
                    requires_human_approval = False
                    if not reasons:
                        is_malicious = False
                    break

        return PromptInjectionResult(
            is_malicious=is_malicious,
            reasons=reasons,
            requires_human_approval=requires_human_approval,
        )