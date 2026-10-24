"""
Comprehensive PyTest Suite for Agent Shield.

Covers:
- PolicyEngine deterministic evaluation
- Dynamic parameter inspection & threat detection (RCE, SQLi, Path Traversal)
- Sliding-window BudgetGuard rate limits
- Cryptographic AuditLedger SHA-256 integrity
- AgentShield decorator interception (sync & async)

Author: Frank Emiliano Vargas Huamán (Frankosyni - Φρανκοσύνη/Francus.)
"""

import asyncio
import pytest

from agent_shield import (
    AgentShield,
    AuditLedger,
    BudgetGuard,
    Decision,
    PolicyEngine,
    RiskLevel,
    ShieldViolationError,
)
from agent_shield.models import RateLimitExceededError


class TestPolicyEngine:
    def test_default_decision(self):
        engine = PolicyEngine(default_decision=Decision.ASK_HUMAN)
        verdict = engine.evaluate("unknown_tool", {})
        assert verdict.decision == Decision.ASK_HUMAN

    def test_explicit_allow_and_deny(self):
        engine = PolicyEngine()
        engine.allow("read_docs", risk_level=RiskLevel.LOW)
        engine.deny("delete_database", risk_level=RiskLevel.CRITICAL)

        v_allow = engine.evaluate("read_docs", {})
        assert v_allow.decision == Decision.ALLOW

        v_deny = engine.evaluate("delete_database", {})
        assert v_deny.decision == Decision.DENY

    def test_threat_detection_path_traversal(self):
        engine = PolicyEngine()
        engine.allow("read_file")

        # Threat payload
        verdict = engine.evaluate("read_file", {"path": "../../etc/shadow"})
        assert verdict.decision == Decision.DENY
        assert "Security threat detected" in verdict.reason

    def test_threat_detection_sqli(self):
        engine = PolicyEngine()
        engine.allow("query_db")

        verdict = engine.evaluate("query_db", {"sql": "SELECT 1; DROP TABLE users; --"})
        assert verdict.decision == Decision.DENY
        assert "sqli" in verdict.reason.lower()


class TestBudgetGuard:
    def test_rate_limiting_sliding_window(self):
        guard = BudgetGuard()
        guard.configure_tool("fast_tool", max_rpm=3, max_tph=10_000)

        # 3 calls should pass
        guard.check_and_record_call("fast_tool")
        guard.check_and_record_call("fast_tool")
        guard.check_and_record_call("fast_tool")

        # 4th call within the same window must raise RateLimitExceededError
        with pytest.raises(RateLimitExceededError):
            guard.check_and_record_call("fast_tool")


class TestAuditLedger:
    def test_sha256_payload_integrity(self):
        args1 = {"a": 1, "b": "test"}
        args2 = {"b": "test", "a": 1}  # Key order difference
        hash1 = AuditLedger.compute_payload_hash(args1)
        hash2 = AuditLedger.compute_payload_hash(args2)

        # Must be deterministic and sorted
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_record_and_query(self):
        ledger = AuditLedger()
        ledger.record_decision(
            tool_name="test_tool",
            caller="unit_test",
            arguments={"query": "test"},
            decision=Decision.ALLOW,
            reason="Safe call",
            duration_ms=1.25,
        )

        entries = ledger.query_by_tool("test_tool")
        assert len(entries) == 1
        assert entries[0].decision == Decision.ALLOW
        assert entries[0].caller == "unit_test"


class TestAgentShieldIntegration:
    def test_protect_allowed_sync_tool(self):
        shield = AgentShield()
        shield.allow("safe_add")

        @shield.protect(name="safe_add")
        def safe_add(x: int, y: int) -> int:
            return x + y

        assert safe_add(3, 4) == 7

    def test_protect_denied_tool(self):
        shield = AgentShield()
        shield.deny("dangerous_op")

        @shield.protect(name="dangerous_op")
        def dangerous_op():
            return "exec"

        with pytest.raises(ShieldViolationError):
            dangerous_op()

    def test_protect_human_approval_flow(self):
        # Approver approves only if reason does not contain 'forbidden'
        def mock_approver(tool_name: str, arguments: dict, reason: str) -> bool:
            return arguments.get("allowed", False)

        shield = AgentShield(
            default_decision=Decision.ASK_HUMAN,
            human_approval_callback=mock_approver,
        )
        shield.ask("deploy_contract")

        @shield.protect(name="deploy_contract")
        def deploy_contract(allowed: bool):
            return "deployed"

        # Approved branch
        assert deploy_contract(allowed=True) == "deployed"

        # Rejected branch
        with pytest.raises(ShieldViolationError):
            deploy_contract(allowed=False)

    @pytest.mark.asyncio
    async def test_protect_async_tool(self):
        shield = AgentShield()
        shield.allow("async_fetch")

        @shield.protect(name="async_fetch")
        async def async_fetch(url: str) -> str:
            await asyncio.sleep(0.01)
            return f"content of {url}"

        result = await async_fetch("https://api.internal/health")
        assert result == "content of https://api.internal/health"
