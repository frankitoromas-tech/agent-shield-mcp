"""
Data models and schemas for Agent Shield MCP using Pydantic V2.

Author: Frank Emiliano Vargas Huamán (Frankosyni / Φρανκοσύνη)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """Acción de política de ejecución para herramientas agénticas."""
    ALLOW = "ALLOW"
    ASK_HUMAN = "ASK_HUMAN"
    DENY = "DENY"


class ShieldViolationError(RuntimeError):
    """Excepción lanzada cuando una llamada a herramienta viola las directivas de seguridad."""
    def __init__(self, message: str, tool_name: str, reason: str):
        super().__init__(message)
        self.tool_name = tool_name
        self.reason = reason


class PolicyRule(BaseModel):
    """Regla granular de control de acceso a una o más herramientas MCP."""
    tool_pattern: str = Field(
        ...,
        description="Patrón de nombre de herramienta (soporta comodines como 'db_*' o 'exec_*')."
    )
    action: PolicyAction = Field(
        default=PolicyAction.ASK_HUMAN,
        description="Acción predeterminada a tomar ante este patrón."
    )
    regex_blacklist: List[str] = Field(
        default_factory=list,
        description="Patrones regex bloqueados incondicionalmente en argumentos de texto."
    )
    allowed_arg_keys: Optional[List[str]] = Field(
        default=None,
        description="Lista blanca opcional de claves de argumentos permitidas."
    )
    description: Optional[str] = Field(
        default=None,
        description="Propósito de la regla para fines de auditoría."
    )


class ShieldConfig(BaseModel):
    """Configuración global del cortafuegos de seguridad de agentes."""
    default_action: PolicyAction = Field(
        default=PolicyAction.ASK_HUMAN,
        description="Acción por defecto si ninguna regla específica coincide."
    )
    max_calls_per_minute: int = Field(
        default=60,
        ge=1,
        description="Límite máximo de llamadas a herramientas por minuto para frenar bucles infinitos."
    )
    max_daily_tokens: int = Field(
        default=500_000,
        ge=1000,
        description="Límite presupuestario diario estimado de tokens."
    )
    audit_log_path: str = Field(
        default="agent_shield_audit.jsonl",
        description="Ruta de destino del libro mayor de auditoría criptográfica."
    )
    rules: List[PolicyRule] = Field(
        default_factory=list,
        description="Catálogo jerárquico de reglas de evaluación."
    )


class ToolCallRequest(BaseModel):
    """Solicitud de llamada a herramienta emitida por el agente LLM."""
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    caller_id: str = "agent-core"
    estimated_tokens: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ToolDecision(BaseModel):
    """Decisión de seguridad evaluada por el motor de políticas."""
    tool_name: str
    action: PolicyAction
    allowed: bool
    reason: str
    rule_matched: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class AuditEntry(BaseModel):
    """Entrada inmutable del libro mayor de auditoría con hash criptográfico."""
    timestamp: str
    tool_name: str
    caller_id: str
    action: str
    allowed: bool
    reason: str
    payload_hash_sha256: str
    arguments_summary: Dict[str, Any]
