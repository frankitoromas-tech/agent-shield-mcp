"""
Core Agent Shield Facade and Function/Tool Decorator.

Provides the `@shield.protect(...)` decorator that wraps FastMCP tools,
enforcing:
1. Declarative zero-trust security policy (ALLOW / ASK_HUMAN / DENY).
2. Dynamic parameter inspection and regex threat detection (Prompt Injection, RCE, Path Traversal).
3. Sliding-window rate-limiting and token consumption limits.
4. Cryptographic SHA-256 audit logging.

Author: Frank Emiliano Vargas Huamán (Frankosyni - Φρανκοσύνη/Francus.)
"""

from __future__ import annotations

import functools
import inspect
import time
from typing import Any, Callable, Coroutine, Dict, Optional, TypeVar, Union

from .audit_ledger import AuditLedger
from .budget_guard import BudgetGuard
from .models import Decision, HumanApprovalCallback, RiskLevel, ShieldViolationError
from .policy_engine import PolicyEngine

F = TypeVar("F", bound=Callable[..., Any])


class AgentShield:
    """Enterprise firewall and governance facade for AI agent tool invocations."""

    def __init__(
        self,
        default_decision: Decision = Decision.ASK_HUMAN,
        audit_file: Optional[str] = None,
        human_approval_callback: Optional[HumanApprovalCallback] = None,
    ) -> None:
        self.policy_engine = PolicyEngine(default_decision=default_decision)
        self.budget_guard = BudgetGuard()
        self.audit_ledger = AuditLedger(log_filepath=audit_file)
        self.human_approval_callback = human_approval_callback

    def set_human_approval_callback(self, callback: HumanApprovalCallback) -> None:
        self.human_approval_callback = callback

    def allow(self, tool_name: str, **kwargs: Any) -> AgentShield:
        self.policy_engine.allow(tool_name, **kwargs)
        return self

    def ask(self, tool_name: str, **kwargs: Any) -> AgentShield:
        self.policy_engine.ask(tool_name, **kwargs)
        return self

    def deny(self, tool_name: str, **kwargs: Any) -> AgentShield:
        self.policy_engine.deny(tool_name, **kwargs)
        return self

    def protect(
        self,
        name: Optional[str] = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        max_rpm: int = 60,
        max_tph: int = 100_000,
        caller: str = "agent_default",
    ) -> Callable[[F], F]:
        """Decorator for FastMCP or standard Python functions/tools."""

        def decorator(func: F) -> F:
            tool_name = name or func.__name__
            self.budget_guard.configure_tool(tool_name, max_rpm=max_rpm, max_tph=max_tph)

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound_args = self._bind_arguments(func, args, kwargs)
                    self._enforce_pre_execution(tool_name, caller, bound_args)

                    start_time = time.perf_counter()
                    try:
                        result = await func(*args, **kwargs)
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        self.audit_ledger.record_decision(
                            tool_name=tool_name,
                            caller=caller,
                            arguments=bound_args,
                            decision=Decision.ALLOW,
                            reason="Execution completed successfully",
                            duration_ms=duration_ms,
                        )
                        return result
                    except Exception as exc:
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        self.audit_ledger.record_decision(
                            tool_name=tool_name,
                            caller=caller,
                            arguments=bound_args,
                            decision=Decision.ALLOW,
                            reason=f"Execution failed: {exc}",
                            duration_ms=duration_ms,
                        )
                        raise

                return async_wrapper  # type: ignore

            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound_args = self._bind_arguments(func, args, kwargs)
                    self._enforce_pre_execution(tool_name, caller, bound_args)

                    start_time = time.perf_counter()
                    try:
                        result = func(*args, **kwargs)
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        self.audit_ledger.record_decision(
                            tool_name=tool_name,
                            caller=caller,
                            arguments=bound_args,
                            decision=Decision.ALLOW,
                            reason="Execution completed successfully",
                            duration_ms=duration_ms,
                        )
                        return result
                    except Exception as exc:
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        self.audit_ledger.record_decision(
                            tool_name=tool_name,
                            caller=caller,
                            arguments=bound_args,
                            decision=Decision.ALLOW,
                            reason=f"Execution failed: {exc}",
                            duration_ms=duration_ms,
                        )
                        raise

                return sync_wrapper  # type: ignore

        return decorator

    def _bind_arguments(
        self, func: Callable[..., Any], args: tuple, kwargs: dict
    ) -> Dict[str, Any]:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)

    def _enforce_pre_execution(
        self, tool_name: str, caller: str, arguments: Dict[str, Any]
    ) -> None:
        # 1. Evaluate declarative security policy and parameter threat rules
        verdict = self.policy_engine.evaluate(tool_name, arguments)

        if verdict.decision == Decision.DENY:
            self.audit_ledger.record_decision(
                tool_name=tool_name,
                caller=caller,
                arguments=arguments,
                decision=Decision.DENY,
                reason=verdict.reason,
            )
            raise ShieldViolationError(
                f"Agent Shield blocked tool '{tool_name}': {verdict.reason}"
            )

        if verdict.decision == Decision.ASK_HUMAN:
            approved = False
            if self.human_approval_callback:
                approved = self.human_approval_callback(tool_name, arguments, verdict.reason)

            if not approved:
                self.audit_ledger.record_decision(
                    tool_name=tool_name,
                    caller=caller,
                    arguments=arguments,
                    decision=Decision.ASK_HUMAN,
                    reason=f"Human approval required: {verdict.reason}",
                    approved_by_human=False,
                )
                raise ShieldViolationError(
                    f"Execution suspended: human operator denied or did not approve '{tool_name}'."
                )

            # Record human approval
            self.audit_ledger.record_decision(
                tool_name=tool_name,
                caller=caller,
                arguments=arguments,
                decision=Decision.ASK_HUMAN,
                reason="Approved by human operator",
                approved_by_human=True,
            )

        # 2. Check rate limit
        self.budget_guard.check_and_record_call(tool_name)
