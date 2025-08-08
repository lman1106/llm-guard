from __future__ import annotations

import html
from dataclasses import dataclass
from typing import List


@dataclass
class OutputScanResult:
    is_high_risk: bool
    triggers: List[str]
    escaped_html: str | None


class ImproperOutputScanner:
    def __init__(self, high_risk_functions: List[str], html_escape: bool) -> None:
        self.high_risk_functions = high_risk_functions
        self.html_escape_enabled = html_escape

    def scan(self, text: str) -> OutputScanResult:
        triggers: List[str] = []
        for frag in self.high_risk_functions:
            if frag in text:
                triggers.append(frag)
        escaped = html.escape(text) if self.html_escape_enabled else None
        return OutputScanResult(is_high_risk=len(triggers) > 0, triggers=triggers, escaped_html=escaped)