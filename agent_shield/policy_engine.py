"""
Policy Engine for Agent Shield MCP.

Evaluates incoming tool call requests against granular security rules, regex blacklists,
and parameter constraints to issue ALLOW, ASK_HUMAN, or DENY decisions.

Author: Frank Emiliano Vargas Huamán (Frankosyni / Φρανκοσύνη)
"""

import fnmatch
import re
from typing import Any, Dict, List, Optional
from agent_shield.models import PolicyAction, PolicyRule, ToolCallRequest, ToolDecision


class PolicyEngine:
    """Motor de evaluación de políticas y cortafuegos de seguridad para llamadas de herramientas."""

    def __init__(self, rules: Optional[List[PolicyRule]] = None, default_action: PolicyAction = PolicyAction.ASK_HUMAN):
        self.rules = rules or []
        self.default_action = default_action

    def add_rule(self, rule: PolicyRule) -> None:
        """Registra una nueva regla de política en el motor."""
        self.rules.append(rule)

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        """
        Evalúa una solicitud de llamada a herramienta contra el conjunto jerárquico de reglas.
        Aplica inspección profunda de argumentos para detectar inyecciones, comandos destructivos
        y rutas sensibles.
        """
        matched_rule: Optional[PolicyRule] = None

        # 1. Búsqueda de coincidencia por patrón de herramienta (soporta wildcards: db_*, sys_*)
        for rule in self.rules:
            if fnmatch.fnmatch(request.tool_name, rule.tool_pattern):
                matched_rule = rule
                break

        action = matched_rule.action if matched_rule else self.default_action
        rule_desc = matched_rule.description or matched_rule.tool_pattern if matched_rule else "Default-Policy"

        # 2. Si la acción base es DENY, denegar inmediatamente
        if action == PolicyAction.DENY:
            return ToolDecision(
                tool_name=request.tool_name,
                action=PolicyAction.DENY,
                allowed=False,
                reason=f"Herramienta bloqueada por política explícita ({rule_desc}).",
                rule_matched=rule_desc,
            )

        # 3. Inspección profunda de argumentos con Blacklist Regex
        if matched_rule and matched_rule.regex_blacklist:
            blacklist_violation = self._scan_arguments_against_blacklist(
                request.arguments, matched_rule.regex_blacklist
            )
            if blacklist_violation:
                return ToolDecision(
                    tool_name=request.tool_name,
                    action=PolicyAction.DENY,
                    allowed=False,
                    reason=f"Violación de seguridad: Argumento contiene patrón peligroso '{blacklist_violation}'.",
                    rule_matched=rule_desc,
                )

        # 4. Verificación de claves de argumentos permitidas (Whitelisting opcional)
        if matched_rule and matched_rule.allowed_arg_keys is not None:
            for key in request.arguments.keys():
                if key not in matched_rule.allowed_arg_keys:
                    return ToolDecision(
                        tool_name=request.tool_name,
                        action=PolicyAction.DENY,
                        allowed=False,
                        reason=f"Argumento no autorizado: '{key}' no figura en la lista blanca permitida.",
                        rule_matched=rule_desc,
                    )

        # 5. Decisión final (ALLOW o ASK_HUMAN)
        is_allowed = (action == PolicyAction.ALLOW)
        decision_reason = (
            "Ejecución autorizada por política."
            if is_allowed
            else "Requiere confirmación explícita del operador humano antes de ejecutar."
        )

        return ToolDecision(
            tool_name=request.tool_name,
            action=action,
            allowed=is_allowed,
            reason=decision_reason,
            rule_matched=rule_desc,
        )

    def _scan_arguments_against_blacklist(
        self, arguments: Dict[str, Any], blacklist: List[str]
    ) -> Optional[str]:
        """Escanea recursivamente strings dentro de argumentos buscando expresiones regulares prohibidas."""
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in blacklist]

        def _traverse(val: Any) -> Optional[str]:
            if isinstance(val, str):
                for pat in compiled_patterns:
                    if pat.search(val):
                        return pat.pattern
            elif isinstance(val, dict):
                for v in val.values():
                    found = _traverse(v)
                    if found:
                        return found
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    found = _traverse(item)
                    if found:
                        return found
            return None

        return _traverse(arguments)
