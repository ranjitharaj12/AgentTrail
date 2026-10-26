"""Everything the Streamlit view shows, as plain data, so it can be tested without a browser.

The screen code (app.py) only lays this out. Nothing here returns markup: event text is attacker-controlled
(a README, a web page, an MCP result) and must reach the screen as plain text.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from agenttrail import store
from agenttrail.eval import SOURCE_RULES, load_narratives, tag_explainer_sessions
from agenttrail.explain import SECTIONS, HEADINGS, clip, redact, summarize
from agenttrail.schema import Event
from agenttrail.score import ROOT, Context, SessionResult, analyze_all, load_context

STATUS_LABEL = {"alert": "ALERT", "review": "REVIEW", "clear": "clear"}
SEV_ORDER = ("low", "medium", "high", "critical")


@dataclass
class World:
    db: Path
    ctx: Context
    results: list[SessionResult]                      # ranked: alerts, then needs-review, then the rest
    events: dict[str, list[Event]]
    narratives: dict[str, dict] = field(default_factory=dict)

    def result(self, sid: str) -> SessionResult:
        return next(r for r in self.results if r.session_id == sid)

    def set_label(self, r: SessionResult) -> str:
        """Which group a session belongs to. Unlisted sessions are the user's own (the playground)."""
        scripted = self.ctx.split.get("scripted_attacks")
        if r.split == "attack" and scripted is not None and r.session_id not in scripted:
            return "yours"
        return r.split


def stale_modules(started_at: float, package_dir: Path = ROOT / "agenttrail") -> list[str]:
    """Files of the package edited after this server started. Streamlit reloads the page script when it
    changes but not the modules it imports, so a long-running server can end up with new page code over old
    data code. Better to say so than to crash with a traceback."""
    return sorted(f.name for f in Path(package_dir).glob("*.py") if f.stat().st_mtime > started_at)


def load_world(db: Path, narratives_dir: Path = ROOT / "reports" / "narratives", use_drift: bool = True,
               embedder=None, base_narratives: Path | None = None) -> World:
    ctx = load_context(db, use_drift=use_drift, embedder=embedder)
    results = tag_explainer_sessions(analyze_all(ctx, db), ctx)
    conn = store.connect(db)
    events = {r.session_id: store.get_session_events(conn, r.session_id) for r in results}
    narratives = {n["session_id"]: n for n in load_narratives(base_narratives)} if base_narratives else {}
    narratives.update({n["session_id"]: n for n in load_narratives(narratives_dir)})      # yours win over the base
    return World(db, ctx, results, events, narratives)


# ---------- the session list (view 1) ----------


def fmt_duration(events: list[Event]) -> str:
    ts = [datetime.fromisoformat(e.ts.replace("Z", "+00:00")) for e in events]
    secs = int((max(ts) - min(ts)).total_seconds()) if ts else 0
    return f"{secs // 60}m{secs % 60:02d}s" if secs >= 60 else f"{secs}s"


def first_prompt(events: list[Event]) -> str:
    return next((clip(e.prompt_text, 90) for e in sorted(events, key=lambda e: e.seq) if e.event_type == "user_prompt"), "")


def session_rows(world: World, statuses: set[str] | None = None) -> list[dict]:
    rows = []
    for r in world.results:
        if statuses and r.status not in statuses:
            continue
        top = r.top_alert
        rows.append({
            "Session": r.session_id, "Status": STATUS_LABEL[r.status], "Score": r.risk.score,
            "Intent": first_prompt(world.events[r.session_id]), "Duration": fmt_duration(world.events[r.session_id]),
            "Events": r.n_events, "Top alert": f"{top.rule_id} {top.severity}: {top.title}" if top else "",
            "Set": world.set_label(r), "Label (eval only)": "malicious" if r.malicious else "benign",
            "Narrative": ("Claude" if world.narratives.get(r.session_id, {}).get("usage", {}).get("input_tokens")
                          else "template" if r.session_id in world.narratives else ""),
        })
    return rows


def status_counts(world: World) -> dict[str, int]:
    return {k: sum(r.status == k for r in world.results) for k in ("alert", "review", "clear")}


# ---------- one session (view 2) ----------


def cited_events(world: World, sid: str) -> set[str]:
    n = world.narratives.get(sid)
    return {x for c in n["claims"] for x in c["cites"]} if n else set()


def trigger_events(result: SessionResult) -> set[str]:
    return {x for h in result.hits if h.rule_id in SOURCE_RULES for x in h.related}


def top_severity(hits: list) -> str:
    """The most severe of a set of hits, or "" when there are none."""
    return max((h.severity for h in hits), key=SEV_ORDER.index, default="")


def timeline(world: World, sid: str) -> list[dict]:
    r = world.result(sid)
    flags: dict[str, list[str]] = {}
    for h in r.hits:
        flags.setdefault(h.event_id, []).append(h.rule_id)
    cited, trig = cited_events(world, sid), trigger_events(r)
    drift = r.drift.scores if r.drift else {}
    rows = []
    for e in sorted(world.events[sid], key=lambda e: e.seq):
        marks = []
        if e.event_id in flags:
            marks.append("flagged")
        if e.event_id in trig:
            marks.append("trigger")
        if e.event_id in cited:
            marks.append("cited")
        rows.append({
            "Seq": e.seq, "Event": e.event_id, "Time": e.ts[11:19], "Type": str(getattr(e.event_type, "value", e.event_type)),
            "Who": str(getattr(e.actor, "value", e.actor)), "What happened": summarize(e),
            "Severity": top_severity([h for h in r.hits if h.event_id == e.event_id]).capitalize(),
            "Rules": ", ".join(sorted(set(flags.get(e.event_id, [])))),
            "Drift": round(drift[e.event_id], 3) if e.event_id in drift else None,
            "Marks": " + ".join(marks),
        })
    return rows


def event_detail(world: World, sid: str, event_id: str) -> dict:
    e = next(x for x in world.events[sid] if x.event_id == event_id)
    d = {"event": e.event_id, "time": e.ts, "type": str(getattr(e.event_type, "value", e.event_type)),
         "actor": str(getattr(e.actor, "value", e.actor)), "turn": e.turn_id, "tool": e.tool,
         "stated_purpose": e.stated_purpose, "args": json.loads(redact(json.dumps(e.args))),
         "paths": e.paths, "path_class": getattr(e.path_class, "value", e.path_class), "network_destination": e.net_dest,
         "action_type": e.action_type, "trust_level": getattr(e.trust_level, "value", e.trust_level),
         "content_excerpt": redact(e.content_excerpt) if e.content_excerpt else None,
         "reply": redact(e.response) if e.response else None, "prompt": e.prompt_text,
         "current_intent": e.intent}
    return {k: v for k, v in d.items() if v not in (None, [], {})}


def prompts(world: World, sid: str) -> list[dict]:
    return [{"Event": e.event_id, "Prompt": e.prompt_text}
            for e in sorted(world.events[sid], key=lambda e: e.seq) if e.event_type == "user_prompt"]


def hits_table(world: World, sid: str) -> list[dict]:
    r = world.result(sid)
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    return [{"Event": h.event_id, "Rule": h.rule_id, "Severity": h.severity, "What it means": h.title,
             "Related events": ", ".join(h.related)}
            for h in sorted(r.hits, key=lambda h: (-order[h.severity], h.seq))]


def breakdown(world: World, sid: str) -> list[dict]:
    return [{"Source": c.source, "Contribution": c.label, "Points": c.points} for c in world.result(sid).risk.contributions]


def narrative_sections(world: World, sid: str) -> list[tuple[str, list[dict]]]:
    n = world.narratives.get(sid)
    if not n:
        return []
    return [(HEADINGS[s], [c for c in n["claims"] if c["section"] == s]) for s in SECTIONS
            if any(c["section"] == s for c in n["claims"])]


TRUST_PHRASE = {"third_party": "vendored or third-party content", "web": "web content", "mcp_result": "an MCP tool result",
                "user_authored": "the user's own file"}


def headline(world: World, sid: str) -> dict:
    """The facts for the banner at the top of a session: all from the detector, none from the narrator."""
    r = world.result(sid)
    hits = sorted(r.hits, key=lambda h: (-SEV_ORDER.index(h.severity), h.seq, h.rule_id))
    top = hits[0] if hits else None
    src = next((x for h in sorted(r.hits, key=lambda h: h.seq) if h.rule_id in SOURCE_RULES for x in h.related[:1]), None)
    by_id = {e.event_id: e for e in world.events[sid]}
    trust = getattr(by_id[src].trust_level, "value", by_id[src].trust_level) if src else None
    return {
        "status": r.status, "score": r.risk.score, "threshold": r.risk.threshold,
        "severity": top.severity if top else "",
        "flagged_events": len({h.event_id for h in r.hits}), "rules": sorted({h.rule_id for h in r.hits}),
        "top": {"rule_id": top.rule_id, "title": top.title, "event_id": top.event_id} if top else None,
        "trigger": {"event_id": src, "trust": trust, "phrase": TRUST_PHRASE.get(trust, "low-trust content")} if src else None,
    }


def cite_kinds(world: World, sid: str) -> dict[str, str]:
    """What each event is, for colouring a citation: its worst severity if flagged, 'trigger', or 'plain'."""
    r = world.result(sid)
    kinds = {e.event_id: "plain" for e in world.events[sid]}
    for h in r.hits:
        kinds[h.event_id] = top_severity([x for x in r.hits if x.event_id == h.event_id])
    for eid in trigger_events(r):
        if kinds.get(eid) == "plain":
            kinds[eid] = "trigger"
    return kinds


def narrative_by_section(world: World, sid: str) -> dict[str, list[dict]]:
    n = world.narratives.get(sid)
    return {sec: [c for c in n["claims"] if c["section"] == sec] for sec in SECTIONS
            if n and any(c["section"] == sec for c in n["claims"])}


def narrative_source(world: World, sid: str) -> str | None:
    n = world.narratives.get(sid)
    return n["source"] if n else None


MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|<>~$:])")
URL_SCHEME = re.compile(r"(?i)\b(https?|ftps?)://")
WWW = re.compile(r"(?i)\bwww\.")
EMAIL = re.compile(r"(?<=\w)@(?=\w)")


def _defang(text: str) -> str:
    """Make attacker-controlled URLs and addresses unclickable (the SOC convention: hxxp, [.], [@])."""
    text = URL_SCHEME.sub(lambda m: m.group(1).lower().replace("tt", "xx") + "://", text)
    return EMAIL.sub("[@]", WWW.sub("www[.]", text))


def md_escape(text: str) -> str:
    """Make recorded or model-written text safe to put in markdown.

    A quoted README must not become a link, image, heading or table. Text in backticks is shown as an inline
    code span (markdown never parses inside one, so a URL there cannot be clicked); everything else is defanged
    and escaped. An unbalanced backtick makes the whole text literal."""
    text = " ".join(text.split())
    parts = text.split("`")
    if len(parts) % 2 == 0:                                   # unbalanced: treat every backtick as plain text
        return MD_SPECIAL.sub(r"\\\1", _defang(text))
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            out.append(MD_SPECIAL.sub(r"\\\1", _defang(part)))
        elif part:
            out.append(f"`{part}`")
    return "".join(out)
