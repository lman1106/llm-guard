from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict


class InMemoryRateLimiter:
    def __init__(self, qps_per_user: int, qpm_per_user: int) -> None:
        self.qps = qps_per_user
        self.qpm = qpm_per_user
        self.per_second: Dict[str, Deque[float]] = defaultdict(deque)
        self.per_minute: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, user_key: str) -> bool:
        now = time.time()
        second_window = self.per_second[user_key]
        minute_window = self.per_minute[user_key]

        while second_window and now - second_window[0] >= 1.0:
            second_window.popleft()
        while minute_window and now - minute_window[0] >= 60.0:
            minute_window.popleft()

        if len(second_window) >= self.qps:
            return False
        if len(minute_window) >= self.qpm:
            return False

        second_window.append(now)
        minute_window.append(now)
        return True


def estimate_token_count(text: str) -> int:
    return max(1, len(text) // 4)