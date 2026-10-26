"""Why was this event flagged? Plain-language reasons, with the evidence that matched.

Nothing here is written separately from the detector. For a single-event rule the facts come from walking the
rule's own `match` definition against the event; for a sequence rule from the steps it matched; for drift from
the scores; for the reply check from the reply and the names it looked for. So the explanation cannot disagree
with what the detector actually did, and it stays correct when a rule file is edited.

Everything returned is plain text. Event content is attacker-controlled, so callers must escape it for markdown.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from agenttrail.explain import clip, redact, summarize
from agenttrail.rules import SEVERITIES, _context, _lookup, _mention_tokens, _node_matches
from agenttrail.schema import Event
from agenttrail.ui_data import World

# How the engine's field names read to a person.
LABELS = {
    "path_class": "path class", "paths": "path", "action_type": "action", "net_dest": "network destination",
    "trust_level": "content trust level", "content_excerpt": "content", "args.command": "command",
    "tool": "tool", "tool_source": "tool source", "mcp_server": "MCP server", "decision": "decision",
    "signals": "other detections on this event", "after_first_prompt": "happened after the first user prompt",
    "domain_new": "destination is new to this project", "path_in_intent": "the user's prompt names this path",
    "mcp_server_in_intent": "the user's prompt names this server", "event_type": "event type",
}
QUIET = {"event_type", "decision"}                      # true of nearly every hit, so they add noise
OVERRIDE_WHY = {
    "path_in_intent": "the user's own prompt names this file, so it is treated as asked for",
    "any_step_path_in_intent": "the user's own prompt names the file that was read earlier",
}


@dataclass
class Step:
    label: str
    event_id: str
    summary: str
    facts: list[str] = field(default_factory=list)


@dataclass
class Reason:
    rule_id: str
    title: str
    severity: str
    event_id: str
    what: str                                           # what the rule looks for, in a sentence
    facts: list[str] = field(default_factory=list)      # the evidence on this event
    steps: list[Step] = field(default_factory=list)     # for rules that span several events
    note: str | None = None                             # e.g. why a severity was lowered


# ---------- turning a rule's conditions into facts ----------

AT_FILE = re.compile(r"^(?:/[^@]*)?/@(?=/)")


def clean_path(p: str) -> str:
    """Display only. A curl-style `@/path` argument is stored as `<project>/@/path`; show the path that was meant.
    (The detector still classifies it correctly. This is a known enrichment limit, recorded in the docs.)"""
    return AT_FILE.sub("", p)



def _show(actual) -> str:
    if isinstance(actual, bool):
        return "yes" if actual else "no"
    if isinstance(actual, list):
        return ", ".join(str(a) for a in actual) if actual else "none"
    return str(actual)


def _fact(key: str, cond, actual) -> str | None:
    label = LABELS.get(key, key)
    values = actual if isinstance(actual, list) else [actual]
    if isinstance(cond, dict):
        op, arg = next(iter(cond.items()))
        if op in ("regex", "any_regex"):
            for v in values:
                for pat in ([arg] if op == "regex" else arg):
                    m = re.search(pat, str(v))
                    if m:
                        around = str(v)[m.start(): m.start() + 200]          # the matched words and what follows them
                        return f"{label} matched “{clip(redact(around), 200)}”"
            return None
        if op == "exists":
            return f"{label}: {clip(redact(_show(actual)), 160)}" if actual else None
        if op == "ne_step":
            return f"{label}: {clip(_show(actual), 160)}"
    if key in ("signals",):
        hit = [s for s in (cond if isinstance(cond, list) else [cond]) if s in values]
        return f"{label}: {', '.join(hit)}" if hit else None
    return f"{label}: {clip(redact(_show(actual)), 200)}"


def facts_for_node(node: dict, fields: dict, ctx: dict) -> list[str]:
    """The conditions of a rule that this event actually satisfied, with the event's real values."""
    out: list[str] = []
    for key, cond in node.items():
        if key == "any":
            for sub in cond:                              # report the first alternative that matched
                if _node_matches(sub, fields, ctx):
                    out += facts_for_node(sub, fields, ctx)
                    break
        elif key == "not" or key in QUIET:
            continue
        else:
            f = _fact(key, cond, _lookup(fields, ctx, key))
            if f:
                out.append(f)
            if key == "path_class" and fields.get("paths"):
                shown = list(dict.fromkeys(clean_path(p) for p in fields["paths"]))
                out.append(f"path{'s' if len(shown) > 1 else ''} on this event: {', '.join(shown)}")
    return list(dict.fromkeys(out))


# ---------- the explainer ----------


class Why:
    """Reasons for every hit in one session. Build once per session, then ask per event."""

    def __init__(self, world: World, sid: str):
        self.world, self.sid = world, sid
        self.result = world.result(sid)
        self.events = sorted(world.events[sid], key=lambda e: e.seq)
        self.by_id = {e.event_id: e for e in self.events}
        self.fields = {e.event_id: e.model_dump(mode="json") for e in self.events}
        self.rules = {r.id: r for r in world.ctx.rules}
        first = next((e.seq for e in self.events if e.event_type == "user_prompt"), None)
        signals: dict[str, list[str]] = {e.event_id: [] for e in self.events}
        for h in self.result.hits:
            r = self.rules.get(h.rule_id)
            if h.rule_id == "D-01" or (r and r.kind == "event"):
                signals[h.event_id].append(h.rule_id)
        self.ctx = {e.event_id: _context(e, first, world.ctx.cfg.home, signals[e.event_id], world.ctx.baseline)
                    for e in self.events}

    def flagged_events(self) -> list[str]:
        return sorted({h.event_id for h in self.result.hits}, key=lambda i: int(i.split(":")[1]))

    def top_severity(self, event_id: str) -> str:
        """The highest severity among the rules that fired on this event ("" if none)."""
        return max((h.severity for h in self.result.hits if h.event_id == event_id), key=SEVERITIES.index, default="")

    def for_event(self, event_id: str) -> list[Reason]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        hits = [h for h in self.result.hits if h.event_id == event_id]
        reasons = [self._reason(h) for h in sorted(hits, key=lambda h: (-order[h.severity], h.rule_id))]
        return reasons

    # -- one hit --
    def _reason(self, h) -> Reason:
        ev, fields, ctx = self.by_id[h.event_id], self.fields[h.event_id], self.ctx[h.event_id]
        if h.rule_id == "D-01":
            return self._drift(h, ev)
        rule = self.rules[h.rule_id]
        r = Reason(h.rule_id, rule.title, h.severity, h.event_id, rule.description or rule.title)
        if rule.kind == "event":
            r.facts = facts_for_node(rule.match, fields, ctx)
            if h.rule_id == "R-02" and ev.net_dest:
                r.facts.append(f"destination: {ev.net_dest}")
                known = sorted(self.world.ctx.baseline.projects[ev.project].domains)
                r.facts.append(f"known destinations for {ev.project}: {', '.join(known) or 'none'}")
        elif rule.kind == "sequence":
            r.steps = self._steps(rule, h)
            last_ctx = {**ctx, "any_step_path_in_intent": any(self.ctx[x]["path_in_intent"] for x in h.related)}
            ctx = last_ctx
        else:                                             # the reply check
            r.facts = self._reply_facts(ev, h)
        r.note = self._severity_note(rule, h.severity, fields, ctx)
        return r

    def _steps(self, rule, h) -> list[Step]:
        ids = [*h.related, h.event_id]
        steps = []
        for st, eid in zip(rule.steps, ids):
            steps.append(Step(st.name.replace("_", " "), eid, summarize(self.by_id[eid]),
                              facts_for_node(st.match, self.fields[eid], self.ctx[eid])))
        return steps

    def _severity_note(self, rule, shown: str, fields: dict, ctx: dict) -> str | None:
        if shown == rule.severity:
            return None
        for o in rule.overrides:
            if _node_matches(o["when"], fields, ctx):
                why = next((OVERRIDE_WHY[k] for k in o["when"] if k in OVERRIDE_WHY), "an override in the rule applied")
                return f"Severity lowered from {rule.severity} to {shown}: {why}."
        return f"Severity is {shown} (the rule's default is {rule.severity})."

    def _reply_facts(self, ev: Event, h) -> list[str]:
        replies = [self.by_id[x] for x in h.related if x in self.by_id]
        out = []
        for rp in replies:
            out.append(f"the agent's reply ({rp.event_id}): “{clip(redact(rp.response or ''), 220)}”")
        tokens = sorted({clean_path(t) for t in _mention_tokens(ev)})
        out.append(f"the reply does not mention this action: it names none of {', '.join(tokens) or 'its details'}")
        return out

    def _drift(self, h, ev: Event) -> Reason:
        d, cfg = self.result.drift, self.world.ctx.drift_cfg
        r = Reason("D-01", "Drift from the current intent", h.severity, h.event_id,
                   "An action whose meaning is far from what the user asked, judged by comparing short descriptions "
                   "with a small embedding model that runs locally.")
        if not d or not cfg:
            return r
        reasons = sorted(d.reasons.get(h.event_id, set()))
        if h.event_id in d.scores:
            r.facts.append(f"distance from the user's intent: {d.scores[h.event_id]:.3f} (higher is further away)")
        r.facts.append(f"flag limits: a single action above {cfg.event_threshold}, a window of {cfg.window_size} actions "
                       f"above {cfg.window_threshold}, or {cfg.run_length} in a row above {cfg.run_threshold}")
        r.facts.append(f"flagged because of the: {', '.join(reasons)} test")
        if h.event_id in d.descriptions:
            r.facts.append(f"what was compared: “{clip(d.descriptions[h.event_id], 160)}” against the user's request “{clip(ev.intent or '', 160)}”")
        return r
