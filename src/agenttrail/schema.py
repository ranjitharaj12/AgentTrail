"""Event schema for AgentTrail (PRD: Event schema).

One Event = one row in the event store. Fields come in three groups:
  1. Raw: copied from Claude Code OTel attributes (or mocked in fixtures).
  2. Enriched: derived by the loader (Chunk 3), so optional here.
  3. Detection output: filled in later by rules / drift / judge.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EventType(str, Enum):
    user_prompt = "user_prompt"
    tool_decision = "tool_decision"
    tool_result = "tool_result"
    assistant_response = "assistant_response"
    mcp_server_connection = "mcp_server_connection"
    plugin_loaded = "plugin_loaded"


class Actor(str, Enum):
    main = "main"
    subagent = "subagent"  # fixture-only for now (open question in PRD)


class ToolSource(str, Enum):
    builtin = "builtin"
    mcp = "mcp"


class Decision(str, Enum):
    accept = "accept"
    reject = "reject"


class Outcome(str, Enum):
    success = "success"
    failure = "failure"


class PathClass(str, Enum):
    project = "project"
    home = "home"
    sensitive = "sensitive"
    system = "system"


class TrustLevel(str, Enum):
    user_authored = "user_authored"  # user's own project file
    third_party = "third_party"      # vendored / dependency code
    web = "web"
    mcp_result = "mcp_result"


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos in fixtures fail loudly

    # --- Raw (OTel) ---
    session_id: str                      # session.id
    seq: int                             # event.sequence (orders events in a session)
    ts: str                              # event.timestamp, ISO 8601
    project: str                         # resource attribute
    event_type: EventType                # event.name
    turn_id: str                         # prompt.id: groups events under one user prompt
    actor: Actor = Actor.main            # fixture-only
    tool: Optional[str] = None           # tool_name
    tool_source: Optional[ToolSource] = None
    mcp_server: Optional[str] = None
    tool_use_id: Optional[str] = None    # joins tool_decision to tool_result
    decision: Optional[Decision] = None
    permission_mode: Optional[str] = None
    stated_purpose: Optional[str] = None  # Bash `description`
    args: dict[str, Any] = Field(default_factory=dict)  # fake canary secrets only!
    prompt_text: Optional[str] = None    # user_prompt text (source of "intent")
    content_excerpt: Optional[str] = None  # fixture-only: ingested content snippet
    outcome: Optional[Outcome] = None
    result_size: Optional[int] = None    # tool_result_size_bytes
    response: Optional[str] = None       # assistant_response text

    # --- Enriched (Chunk 3) ---
    paths: list[str] = Field(default_factory=list)
    path_class: Optional[PathClass] = None
    net_dest: Optional[str] = None
    action_type: Optional[str] = None
    trust_level: Optional[TrustLevel] = None
    intent: Optional[str] = None

    # --- Detection output (later chunks) ---
    signals: list[str] = Field(default_factory=list)
    drift_score: Optional[float] = None
    judge_verdict: Optional[dict[str, Any]] = None

    @property
    def event_id(self) -> str:
        """session.id + event.sequence; this is what narratives cite."""
        return f"{self.session_id}:{self.seq}"


class Label(BaseModel):
    """Ground truth for one fixture session (used only by the eval)."""
    model_config = ConfigDict(extra="forbid")

    session_id: str
    malicious: bool
    malicious_event_ids: list[str] = Field(default_factory=list)
    trigger_event_id: Optional[str] = None   # the content that caused the attack, when there is one
    scenario: str = ""
    notes: str = ""
