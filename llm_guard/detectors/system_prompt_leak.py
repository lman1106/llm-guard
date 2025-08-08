from __future__ import annotations

from dataclasses import dataclass
from typing import List
from difflib import SequenceMatcher


def normalize(text: str) -> str:
    return " ".join(text.lower().split())


@dataclass
class SystemPromptLeakResult:
    is_leak: bool
    similarity: float
    matched_substrings: List[str]


class SystemPromptLeakDetector:
    def __init__(self, system_prompt: str, similarity_threshold: float = 0.72) -> None:
        self.system_prompt = system_prompt
        self.system_prompt_norm = normalize(system_prompt)
        self.threshold = similarity_threshold

    def analyze(self, output_text: str) -> SystemPromptLeakResult:
        output_norm = normalize(output_text)
        ratio = SequenceMatcher(a=self.system_prompt_norm, b=output_norm).ratio()

        matched: List[str] = []
        tokens = set(self.system_prompt_norm.split())
        out_tokens = output_norm.split()
        window = max(3, min(12, len(out_tokens)))
        for i in range(0, len(out_tokens) - window + 1):
            window_tokens = out_tokens[i:i+window]
            overlap = tokens.intersection(window_tokens)
            if len(overlap) / window >= 0.6:
                matched.append(" ".join(window_tokens))
                if len(matched) >= 3:
                    break

        is_leak = ratio >= self.threshold or len(matched) > 0
        return SystemPromptLeakResult(is_leak=is_leak, similarity=ratio, matched_substrings=matched)