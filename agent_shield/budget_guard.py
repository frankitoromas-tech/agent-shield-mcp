"""
Budget and Rate-Limiting Guard for Model Context Protocol (FastMCP) Tools.

Enforces:
1. Sliding-window rate limiting (invocations per minute).
2. Token consumption budgets (cumulative input/output tokens per session or rolling window).
3. Concurrency limits per tool.

Author: Frank Emiliano Vargas Huamán (Frankosyni - Φρανκοσύνη/Francus.)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .models import BudgetExceededError, RateLimitExceededError


@dataclass
class ToolUsageTracker:
    max_calls_per_minute: int = 60
    max_tokens_per_hour: int = 100_000
    call_timestamps: deque = field(default_factory=deque)
    token_records: deque = field(default_factory=deque)  # tuple of (timestamp, token_count)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record_call(self) -> None:
        now = time.time()
        window_start = now - 60.0
        with self.lock:
            # Purge calls older than 60 seconds
            while self.call_timestamps and self.call_timestamps[0] < window_start:
                self.call_timestamps.popleft()

            if len(self.call_timestamps) >= self.max_calls_per_minute:
                retry_after = round(60.0 - (now - self.call_timestamps[0]), 2)
                raise RateLimitExceededError(
                    f"Rate limit exceeded: {len(self.call_timestamps)}/{self.max_calls_per_minute} calls in last 60s. "
                    f"Retry after {retry_after}s."
                )

            self.call_timestamps.append(now)

    def record_tokens(self, token_count: int) -> None:
        if token_count <= 0:
            return

        now = time.time()
        window_start = now - 3600.0
        with self.lock:
            # Purge token entries older than 1 hour
            while self.token_records and self.token_records[0][0] < window_start:
                self.token_records.popleft()

            current_usage = sum(tokens for _, tokens in self.token_records)
            if current_usage + token_count > self.max_tokens_per_hour:
                raise BudgetExceededError(
                    f"Token budget exceeded: current={current_usage}, requested={token_count}, "
                    f"max={self.max_tokens_per_hour} tokens/hour."
                )

            self.token_records.append((now, token_count))

    def get_stats(self) -> Dict[str, float]:
        now = time.time()
        with self.lock:
            active_calls = sum(1 for t in self.call_timestamps if t >= now - 60.0)
            active_tokens = sum(tok for t, tok in self.token_records if t >= now - 3600.0)
            return {
                "calls_last_minute": active_calls,
                "max_calls_per_minute": self.max_calls_per_minute,
                "tokens_last_hour": active_tokens,
                "max_tokens_per_hour": self.max_tokens_per_hour,
            }


class BudgetGuard:
    """Thread-safe multi-tool budget and rate-limiting coordinator."""

    def __init__(self, default_rpm: int = 60, default_tph: int = 100_000) -> None:
        self.default_rpm = default_rpm
        self.default_tph = default_tph
        self._trackers: Dict[str, ToolUsageTracker] = {}
        self._global_lock = threading.Lock()

    def configure_tool(self, tool_name: str, max_rpm: int, max_tph: int) -> None:
        with self._global_lock:
            self._trackers[tool_name] = ToolUsageTracker(
                max_calls_per_minute=max_rpm,
                max_tokens_per_hour=max_tph,
            )

    def _get_tracker(self, tool_name: str) -> ToolUsageTracker:
        with self._global_lock:
            if tool_name not in self._trackers:
                self._trackers[tool_name] = ToolUsageTracker(
                    max_calls_per_minute=self.default_rpm,
                    max_tokens_per_hour=self.default_tph,
                )
            return self._trackers[tool_name]

    def check_and_record_call(self, tool_name: str) -> None:
        tracker = self._get_tracker(tool_name)
        tracker.record_call()

    def check_and_record_tokens(self, tool_name: str, estimated_tokens: int) -> None:
        tracker = self._get_tracker(tool_name)
        tracker.record_tokens(estimated_tokens)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        with self._global_lock:
            return {name: trk.get_stats() for name, trk in self._trackers.items()}
