"""
DelegationChain — represents a chain of AI agent delegations.

When an orchestrator agent delegates work to a sub-agent, the calling agent
appends itself to the chain so that the full provenance of a request can be
audited and policies enforced at every hop.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DelegationLink:
    """
    A single hop in a delegation chain.

    Fields
    ------
    agent_id : str
        The delegating agent's identifier.
    agent_name : str
        Human-readable name of the delegating agent.
    delegated_at : float
        Unix epoch when the delegation occurred.
    purpose : str
        Short description of why the delegation was made.
    token_jti : str or None
        JWT ID of the token used for this delegation (for audit correlation).
    signature : str or None
        Optional cryptographic signature over this link's canonical form.
    """

    agent_id: str
    agent_name: str = "unknown"
    delegated_at: float = field(default_factory=time.time)
    purpose: str = ""
    token_jti: Optional[str] = None
    signature: Optional[str] = None

    def canonical(self) -> str:
        """Return a deterministic string representation suitable for signing."""
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "delegated_at": round(self.delegated_at, 3),
                "purpose": self.purpose,
                "token_jti": self.token_jti,
            },
            sort_keys=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "delegated_at": self.delegated_at,
            "purpose": self.purpose,
            "token_jti": self.token_jti,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationLink":
        return cls(
            agent_id=data["agent_id"],
            agent_name=data.get("agent_name", "unknown"),
            delegated_at=float(data.get("delegated_at", time.time())),
            purpose=data.get("purpose", ""),
            token_jti=data.get("token_jti"),
            signature=data.get("signature"),
        )


@dataclass
class DelegationChain:
    """
    An ordered sequence of DelegationLink objects.

    The chain grows as tasks are delegated through the agent hierarchy.
    The first entry is the root (human or top-level orchestrator); the last
    entry is the most-recently delegating agent.

    Usage
    -----
    chain = DelegationChain.new(root_agent_id="orchestrator-1", root_name="OrchestratorBot")
    chain = chain.delegate(agent_id="sub-agent-2", agent_name="ResearchBot", purpose="web search")
    chain = chain.delegate(agent_id="sub-agent-3", agent_name="SummaryBot", purpose="summarise")

    # Enforce depth limits
    chain.assert_max_depth(max_depth=5)

    # Serialise for JWT claim or HTTP header
    header_value = chain.to_header()
    """

    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    links: List[DelegationLink] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def new(cls, root_agent_id: str, root_name: str = "root", purpose: str = "initial") -> "DelegationChain":
        """Create a new chain with a single root link."""
        root = DelegationLink(
            agent_id=root_agent_id,
            agent_name=root_name,
            purpose=purpose,
        )
        return cls(links=[root])

    @classmethod
    def empty(cls) -> "DelegationChain":
        """Return an empty chain (no delegations yet)."""
        return cls(links=[])

    @classmethod
    def from_list(cls, agent_ids: List[str]) -> "DelegationChain":
        """Build a minimal chain from a plain list of agent IDs."""
        links = [DelegationLink(agent_id=aid) for aid in agent_ids]
        return cls(links=links)

    # ------------------------------------------------------------------
    # Chain operations (immutable — return new chain)
    # ------------------------------------------------------------------

    def delegate(
        self,
        agent_id: str,
        agent_name: str = "unknown",
        purpose: str = "",
        token_jti: Optional[str] = None,
    ) -> "DelegationChain":
        """
        Return a new DelegationChain with *agent_id* appended.
        """
        new_link = DelegationLink(
            agent_id=agent_id,
            agent_name=agent_name,
            purpose=purpose,
            token_jti=token_jti,
        )
        return DelegationChain(
            chain_id=self.chain_id,
            links=self.links + [new_link],
            created_at=self.created_at,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def depth(self) -> int:
        """Number of links in the chain."""
        return len(self.links)

    @property
    def agent_ids(self) -> List[str]:
        """Ordered list of agent IDs in the chain."""
        return [link.agent_id for link in self.links]

    @property
    def root_agent_id(self) -> Optional[str]:
        return self.links[0].agent_id if self.links else None

    @property
    def leaf_agent_id(self) -> Optional[str]:
        return self.links[-1].agent_id if self.links else None

    def contains(self, agent_id: str) -> bool:
        """Return True if *agent_id* appears anywhere in the chain."""
        return agent_id in self.agent_ids

    def has_cycle(self) -> bool:
        """Return True if any agent_id appears more than once (cycle detected)."""
        seen = set()
        for aid in self.agent_ids:
            if aid in seen:
                return True
            seen.add(aid)
        return False

    def assert_max_depth(self, max_depth: int) -> None:
        """Raise ValueError if the chain depth exceeds *max_depth*."""
        if self.depth > max_depth:
            raise ValueError(
                f"Delegation chain depth {self.depth} exceeds maximum {max_depth}. "
                f"Chain: {' -> '.join(self.agent_ids)}"
            )

    def assert_no_cycle(self) -> None:
        """Raise ValueError if a cycle is detected."""
        if self.has_cycle():
            raise ValueError(
                f"Delegation cycle detected in chain: {' -> '.join(self.agent_ids)}"
            )

    # ------------------------------------------------------------------
    # Integrity / fingerprint
    # ------------------------------------------------------------------

    def fingerprint(self) -> str:
        """
        SHA-256 fingerprint of the entire chain (canonical form).

        Can be stored in JWT claims or audit records for tamper detection.
        """
        canonical = json.dumps(
            {
                "chain_id": self.chain_id,
                "links": [link.canonical() for link in self.links],
                "created_at": round(self.created_at, 3),
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "links": [link.to_dict() for link in self.links],
            "created_at": self.created_at,
            "depth": self.depth,
            "fingerprint": self.fingerprint(),
        }

    def to_header(self) -> str:
        """
        Compact representation for the X-Delegation-Chain HTTP header.

        Format: <chain_id>:<agent_id_1>,<agent_id_2>,...
        """
        return f"{self.chain_id}:{','.join(self.agent_ids)}"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DelegationChain":
        return cls(
            chain_id=data.get("chain_id", str(uuid.uuid4())),
            links=[DelegationLink.from_dict(l) for l in data.get("links", [])],
            created_at=float(data.get("created_at", time.time())),
        )

    @classmethod
    def from_header(cls, header_value: str) -> "DelegationChain":
        """
        Parse a chain from the compact header format.

        Format: <chain_id>:<agent_id_1>,<agent_id_2>,...
        """
        parts = header_value.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid delegation chain header: {header_value!r}")
        chain_id, agents_str = parts
        agent_ids = [a.strip() for a in agents_str.split(",") if a.strip()]
        links = [DelegationLink(agent_id=aid) for aid in agent_ids]
        return cls(chain_id=chain_id, links=links)

    def __len__(self) -> int:
        return self.depth

    def __repr__(self) -> str:
        return (
            f"DelegationChain(chain_id={self.chain_id!r}, "
            f"depth={self.depth}, "
            f"agents={self.agent_ids!r})"
        )
