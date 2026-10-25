"""Per-project baselines (PRD FR-4), built only from benign tuning sessions.

A baseline records what is normal for a project: tools, command binaries, top-level
directories touched, and network domains. In the POC only domains drive a detection
(R-02); the rest is context for the analyst and for later tuning.
"""
from __future__ import annotations

import json
import posixpath
from collections import Counter
from dataclasses import dataclass, field

from agenttrail.enrich import Config, command_binary
from agenttrail.schema import Event, EventType


@dataclass
class ProjectBaseline:
    tools: Counter = field(default_factory=Counter)
    binaries: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)
    top_dirs: Counter = field(default_factory=Counter)      # first folder under the project root
    sessions: int = 0


class Baseline:
    def __init__(self, projects: dict[str, ProjectBaseline]):
        self.projects = projects

    @classmethod
    def build(cls, sessions: dict[str, list[Event]], cfg: Config) -> "Baseline":
        """`sessions` maps session_id -> enriched events. Callers pass benign sessions only."""
        projects: dict[str, ProjectBaseline] = {}
        for events in sessions.values():
            if not events:
                continue
            pb = projects.setdefault(events[0].project, ProjectBaseline())
            pb.sessions += 1
            root = cfg.projects[events[0].project].root
            for ev in events:
                if ev.event_type != EventType.tool_decision or ev.decision != "accept":
                    continue
                pb.tools[ev.tool] += 1
                if ev.tool == "Bash":
                    binary = command_binary(str(ev.args.get("command", "")))
                    if binary:
                        pb.binaries[binary] += 1
                if ev.net_dest:
                    pb.domains[ev.net_dest] += 1
                for p in ev.paths:
                    rel = p[len(root) + 1:] if p.startswith(root + "/") else ""
                    if "/" in rel:                       # a file inside a subfolder, not a root-level file
                        pb.top_dirs[rel.split("/")[0]] += 1
        return cls(projects)

    def has_project(self, project: str) -> bool:
        return project in self.projects

    def knows_domain(self, project: str, domain: str) -> bool:
        return domain in self.projects[project].domains

    def to_dict(self) -> dict:
        return {name: {"sessions": pb.sessions, "tools": dict(pb.tools), "binaries": dict(pb.binaries),
                       "domains": dict(pb.domains), "top_dirs": dict(pb.top_dirs)}
                for name, pb in self.projects.items()}


def main() -> int:
    from agenttrail.score import load_context
    ctx = load_context()
    print(json.dumps(ctx.baseline.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
