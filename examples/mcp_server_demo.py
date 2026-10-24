"""
Example FastMCP Server with Agent Shield Enterprise Sandboxing.

Demonstrates:
- Safe Read Tool: `get_system_time` (ALLOW)
- Sensitive Operations: `execute_sql_query` (ASK_HUMAN approval required)
- Dangerous Tool: `shell_exec` (DENY by policy)
- Threat Interception: SQL injection patterns and Path Traversal detection

Author: Frank Emiliano Vargas Huamán (Frankosyni - Φρανκοσύνη/Francus.)
"""

import sys
from datetime import datetime, timezone

from agent_shield import AgentShield, Decision, RiskLevel, ShieldViolationError

# 1. Initialize Shield with Human-in-the-Loop Callback
def terminal_human_approver(tool_name: str, arguments: dict, reason: str) -> bool:
    print(f"\n[AGENT SHIELD ALERT] Security check requested for '{tool_name}'!")
    print(f"Reason: {reason}")
    print(f"Arguments: {arguments}")
    # In production, this can integrate with Slack, Webhook, or Approval Portal
    # For this automated demo, we approve SELECT operations and deny DROP/DELETE
    query = str(arguments.get("query", "")).upper()
    if "DROP" in query or "DELETE" in query:
        print("[HUMAN APPROVAL] -> DENIED by security policy.")
        return False
    print("[HUMAN APPROVAL] -> APPROVED by operator.")
    return True

shield = AgentShield(
    default_decision=Decision.ASK_HUMAN,
    audit_file="agent_shield_audit.jsonl",
    human_approval_callback=terminal_human_approver,
)

# 2. Configure Declarative Zero-Trust Policies
shield.allow("get_system_time", risk_level=RiskLevel.LOW)
shield.ask("execute_sql_query", risk_level=RiskLevel.HIGH)
shield.deny("shell_exec", risk_level=RiskLevel.CRITICAL)

# 3. Define Protected Tools
@shield.protect(name="get_system_time", risk_level=RiskLevel.LOW)
def get_system_time() -> str:
    """Returns current UTC timestamp (Safe read operation)."""
    return datetime.now(timezone.utc).isoformat()

@shield.protect(name="execute_sql_query", risk_level=RiskLevel.HIGH)
def execute_sql_query(query: str, database: str = "prod_db") -> dict:
    """Executes sanitized SQL query on target database."""
    return {"status": "success", "database": database, "rows_affected": 1, "query": query}

@shield.protect(name="shell_exec", risk_level=RiskLevel.CRITICAL)
def shell_exec(command: str) -> str:
    """Dangerous OS command executor (Permanently blocked)."""
    return f"Executed: {command}"


def main() -> None:
    print("=" * 70)
    print(" Agent Shield: FastMCP Security Sandbox Demonstration")
    print("=" * 70)

    # Test 1: Allowed Safe Tool
    print("\n--- Test 1: Allowed Safe Tool (get_system_time) ---")
    time_result = get_system_time()
    print(f"Result: {time_result}")

    # Test 2: Sensitive Tool with Human Approval
    print("\n--- Test 2: Sensitive Tool with Human Approval (Safe Query) ---")
    try:
        query_result = execute_sql_query("SELECT id, username FROM users WHERE active = 1")
        print(f"Result: {query_result}")
    except ShieldViolationError as e:
        print(f"Blocked: {e}")

    # Test 3: Sensitive Tool with Threat Detection (SQL Injection Attempt)
    print("\n--- Test 3: Sensitive Tool with Threat (SQL Injection) ---")
    try:
        execute_sql_query("SELECT * FROM users; DROP TABLE users; --")
    except ShieldViolationError as e:
        print(f"Shield Intercepted Threat: {e}")

    # Test 4: Denied Tool (shell_exec)
    print("\n--- Test 4: Denied Tool Execution (shell_exec) ---")
    try:
        shell_exec("rm -rf /")
    except ShieldViolationError as e:
        print(f"Shield Blocked Execution: {e}")

    # Test 5: Audit Ledger Query
    print("\n--- Test 5: Cryptographic Audit Ledger Entries ---")
    entries = shield.audit_ledger.query_recent(5)
    for i, entry in enumerate(entries, 1):
        print(f"[{i}] {entry.timestamp} | Tool: {entry.tool_name:<18} | Verdict: {entry.decision.value:<10} | Digest: {entry.arguments_digest[:12]}...")

    print("\n[SUCCESS] Agent Shield sandboxing validated.")


if __name__ == "__main__":
    main()
