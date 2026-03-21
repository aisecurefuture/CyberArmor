"""
AgentIdentity — immutable identity record for an AI agent.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AgentIdentity:
    """
    Immutable identity record representing an AI agent within the
    CyberArmor Identity Control Plane.

    Fields
    ------
    agent_id : str
        Globally unique identifier for this agent instance.
    tenant_id : str
        The owning organisation / tenant.
    name : str
        Human-readable agent name (e.g. "customer-support-bot").
    agent_type : str
        Functional type: "llm", "tool", "orchestrator", "retrieval", etc.
    version : str
        Semantic version of the agent software.
    environment : str
        Deployment environment: "production", "staging", "development".
    capabilities : list of str
        Declared capabilities, e.g. ["web_search", "code_exec"].
    trust_level : int
        Numeric trust tier: 0 = untrusted, 1 = basic, 2 = elevated, 3 = privileged.
    owner_user_id : str or None
        Human user who provisioned this agent (optional).
    parent_agent_id : str or None
        If this agent was spawned by another agent, the parent's ID.
    labels : dict
        Arbitrary key/value metadata (team, cost-center, project, …).
    registered_at : float
        Unix epoch when this identity was first registered.
    issued_at : float
        Unix epoch of the current identity assertion (per-request).
    """

    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = ""
    name: str = "unnamed-agent"
    agent_type: str = "llm"
    version: str = "0.0.0"
    environment: str = "production"
    capabilities: List[str] = field(default_factory=list)
    trust_level: int = 1
    owner_user_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    labels: Dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    issued_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Predicates
    # ------------------------------------------------------------------

    def is_privileged(self) -> bool:
        """Return True when trust_level >= 3."""
        return self.trust_level >= 3

    def has_capability(self, capability: str) -> bool:
        """Return True if *capability* is declared for this agent."""
        return capability in self.capabilities

    def is_expired(self, ttl_seconds: float = 3600.0) -> bool:
        """Return True if *issued_at* is older than *ttl_seconds*."""
        return (time.time() - self.issued_at) > ttl_seconds

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "agent_type": self.agent_type,
            "version": self.version,
            "environment": self.environment,
            "capabilities": list(self.capabilities),
            "trust_level": self.trust_level,
            "owner_user_id": self.owner_user_id,
            "parent_agent_id": self.parent_agent_id,
            "labels": dict(self.labels),
            "registered_at": self.registered_at,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity":
        """Reconstruct an AgentIdentity from a dict (e.g. API response)."""
        return cls(
            agent_id=data.get("agent_id", str(uuid.uuid4())),
            tenant_id=data.get("tenant_id", ""),
            name=data.get("name", "unnamed-agent"),
            agent_type=data.get("agent_type", "llm"),
            version=data.get("version", "0.0.0"),
            environment=data.get("environment", "production"),
            capabilities=list(data.get("capabilities", [])),
            trust_level=int(data.get("trust_level", 1)),
            owner_user_id=data.get("owner_user_id"),
            parent_agent_id=data.get("parent_agent_id"),
            labels=dict(data.get("labels", {})),
            registered_at=float(data.get("registered_at", time.time())),
            issued_at=float(data.get("issued_at", time.time())),
        )

    @classmethod
    def from_jwt_claims(cls, claims: Dict[str, Any]) -> "AgentIdentity":
        """
        Build an AgentIdentity from JWT claims.

        Expects claims like:
          sub = agent_id, tid = tenant_id, name = name, ...
        """
        return cls(
            agent_id=claims.get("sub", str(uuid.uuid4())),
            tenant_id=claims.get("tid", claims.get("tenant_id", "")),
            name=claims.get("name", "unnamed-agent"),
            agent_type=claims.get("agent_type", "llm"),
            version=claims.get("ver", "0.0.0"),
            environment=claims.get("env", "production"),
            capabilities=list(claims.get("caps", [])),
            trust_level=int(claims.get("trust", 1)),
            owner_user_id=claims.get("uid"),
            parent_agent_id=claims.get("parent"),
            labels=dict(claims.get("labels", {})),
            registered_at=float(claims.get("reg", time.time())),
            issued_at=float(claims.get("iat", time.time())),
        )

    def __str__(self) -> str:
        return (
            f"AgentIdentity({self.name!r}, id={self.agent_id!r}, "
            f"tenant={self.tenant_id!r}, trust={self.trust_level})"
        )
