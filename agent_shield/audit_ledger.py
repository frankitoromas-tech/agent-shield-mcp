"""
Immutable Cryptographic Audit Ledger for AI Agent Tool Invocations.

Every tool call evaluated by Agent Shield produces an `AuditEntry`:
- Timestamp (UTC ISO-8601)
- Tool name & caller identity
- Arguments payload digest (SHA-256)
- Shield decision (ALLOW / ASK_HUMAN / DENY)
- Human approval metadata (if applicable)
- Execution latency & outcome

Author: Frank Emiliano Vargas Huamán (Frankosyni - Φρανκοσύνη/Francus.)
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AuditEntry, Decision


class AuditLedger:
    """Thread-safe append-only audit ledger with optional JSONL persistence."""

    def __init__(self, log_filepath: Optional[str | Path] = None) -> None:
        self.log_filepath = Path(log_filepath) if log_filepath else None
        self._in_memory_records: List[AuditEntry] = []
        self._lock = threading.Lock()

        if self.log_filepath:
            self.log_filepath.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_payload_hash(arguments: Dict[str, Any]) -> str:
        serialized = json.dumps(arguments, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def record_decision(
        self,
        tool_name: str,
        caller: str,
        arguments: Dict[str, Any],
        decision: Decision,
        reason: str,
        approved_by_human: Optional[bool] = None,
        duration_ms: Optional[float] = None,
    ) -> AuditEntry:
        now_utc = datetime.now(timezone.utc).isoformat()
        digest = self.compute_payload_hash(arguments)

        entry = AuditEntry(
            timestamp=now_utc,
            tool_name=tool_name,
            caller=caller,
            arguments_digest=digest,
            decision=decision,
            reason=reason,
            approved_by_human=approved_by_human,
            duration_ms=duration_ms,
        )

        with self._lock:
            self._in_memory_records.append(entry)
            if self.log_filepath:
                self._append_to_file(entry)

        return entry

    def _append_to_file(self, entry: AuditEntry) -> None:
        data = {
            "timestamp": entry.timestamp,
            "tool_name": entry.tool_name,
            "caller": entry.caller,
            "arguments_digest": entry.arguments_digest,
            "decision": entry.decision.value,
            "reason": entry.reason,
            "approved_by_human": entry.approved_by_human,
            "duration_ms": entry.duration_ms,
        }
        with open(self.log_filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def query_recent(self, limit: int = 50) -> List[AuditEntry]:
        with self._lock:
            return list(self._in_memory_records[-limit:])

    def query_by_tool(self, tool_name: str) -> List[AuditEntry]:
        with self._lock:
            return [e for e in self._in_memory_records if e.tool_name == tool_name]

    def query_by_decision(self, decision: Decision) -> List[AuditEntry]:
        with self._lock:
            return [e for e in self._in_memory_records if e.decision == decision]

    def clear_in_memory(self) -> None:
        with self._lock:
            self._in_memory_records.clear()
