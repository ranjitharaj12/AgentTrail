"""The explainer (PRD FR-9 to FR-11): turn an alert into a short narrative where every claim cites events.

Division of labour, enforced in code:

  * The DETECTION LAYER decides status, score, severity and ATLAS mapping. The narrator never produces
    them; they are attached to the narrative afterwards, so a narrator cannot change them.
  * A NARRATOR (a template, or Claude) only writes claims: {section, text, cites}.
  * A VALIDATOR accepts a narrative only if every claim cites real events, everything concrete it names
    (paths, domains, rule ids) appears in those events, and it contains no motive language and no
    "this is benign / authorised / low severity" verdicts. Rejected output is regenerated with feedback,
    and if every attempt fails the deterministic template narrator is used. Rejected text is never shown.

    .venv/bin/python -m agenttrail.explain --all --narrator template
    .venv/bin/python -m agenttrail.explain --session s-a01 --narrator claude     # needs ANTHROPIC_API_KEY
"""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from agenttrail import store
from agenttrail.rules import RANK, Hit
from agenttrail.schema import Event
from agenttrail.score import ROOT, Context, SessionResult, analyze_all, load_context

SECTIONS = ["asked", "did", "reported", "deviation", "trigger", "action"]
HEADINGS = {"asked": "What the user asked", "did": "What the agent did", "reported": "What the agent reported",
            "deviation": "Where it deviated", "trigger": "Likely trigger", "action": "Recommended action"}
SOURCE_RULES = {"R-07", "R-08"}

# $ per million tokens (input, output), for the spend cap. First-party API prices.
PRICES = {"claude-opus-5-5": (4.0, 20.0), "claude-sonnet-5-5": (2.0, 10.0), "claude-haiku-5-5": (0.10, 0.50),
          "claude-opus-5": (5.0, 25.0), "claude-sonnet-5": (2.0, 10.0), "claude-fable-5-1": (10.0, 50.0)}


# ---------- redaction and compact text ----------

SECRET_VALUE = re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w-]*\s*[:=]\s*)\S+")
SECRET_SHAPES = [re.compile(p) for p in (r"AKIA[0-9A-Z]{8,}", r"\b(?:sk|pk)_(?:test|live)_\w+", r"\bgh[opsu]_\w{8,}",
                                         r"-----BEGIN [A-Z ]*KEY-----")]


def redact(text: str) -> str:
    text = SECRET_VALUE.sub(lambda m: m.group(1) + "[REDACTED]", text)
    for rx in SECRET_SHAPES:
        text = rx.sub("[REDACTED]", text)
    return text


def clip(text: str | None, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def summarize(ev: Event) -> str:
    t = str(getattr(ev.event_type, "value", ev.event_type))
    if t == "user_prompt":
        return clip(ev.prompt_text, 400)
    if t == "assistant_response":
        return clip(ev.response, 500)
    if t == "mcp_server_connection":
        return f"MCP server {ev.mcp_server} connected"
    if t == "plugin_loaded":
        return "plugin loaded"
    bits = []
    if t == "tool_decision":
        bits.append(f"{getattr(ev.decision, 'value', ev.decision)}: {ev.tool}")
        if ev.stated_purpose:
            bits.append(f"purpose “{clip(ev.stated_purpose, 120)}”")
        if ev.args.get("command"):
            bits.append(f"command `{clip(ev.args['command'], 220)}`")
        elif ev.paths:
            bits.append("paths " + ", ".join(ev.paths[:3]))
        elif ev.args.get("url"):
            bits.append(f"url {ev.args['url']}")
        if ev.net_dest:
            bits.append(f"network destination {ev.net_dest}")
    else:
        bits.append(f"result of {ev.tool}: {getattr(ev.outcome, 'value', ev.outcome)}, {ev.result_size} bytes")
        if ev.trust_level:
            bits.append(f"content trust level {getattr(ev.trust_level, 'value', ev.trust_level)}")
        if ev.content_excerpt:
            bits.append(f"content excerpt “{clip(ev.content_excerpt, 400)}”")
    return redact("; ".join(bits))


# ---------- the evidence package ----------


@dataclass
class Evidence:
    session_id: str
    project: str
    home: str
    status: str
    score: int
    threshold: int
    severity: str | None
    atlas: list[str]
    contributions: list[dict]
    hits: list[dict]
    turns: list[dict]
    events: list[dict]
    has_reply: bool
    trigger_sources: list[str]          # event ids that R-07 / R-08 named as the likely trigger

    def event_ids(self) -> set[str]:
        return {e["id"] for e in self.events}

    def search_text(self, eid: str) -> str:
        e = next(x for x in self.events if x["id"] == eid)
        return e["search"]

    def rule_ids(self) -> set[str]:
        return {h["rule_id"] for h in self.hits}

    def rules_at(self, event_ids: list[str]) -> set[str]:
        """Rules that fired ON these events, or that cite one of them (R-12 cites the reply it checked)."""
        want = set(event_ids)
        return {h["rule_id"] for h in self.hits if h["event_id"] in want or want & set(h["related"])}

    def prompt_json(self) -> str:
        slim = [{k: v for k, v in e.items() if k != "search"} for e in self.events]
        return json.dumps({"turns": self.turns, "events": slim}, ensure_ascii=False, indent=1)


def build_evidence(result: SessionResult, events: list[Event], home: str = "/home/dev") -> Evidence:
    events = sorted(events, key=lambda e: e.seq)
    flags: dict[str, list[str]] = {}
    for h in result.hits:
        flags.setdefault(h.event_id, []).append(h.rule_id)

    def tilde(p: str) -> str:
        return "~/" + p[len(home) + 1:] if p.startswith(home + "/") else p

    compact = []
    for ev in events:
        paths = list(ev.paths) + [tilde(p) for p in ev.paths]
        search = " ".join([summarize(ev), ev.tool or "", ev.net_dest or "", " ".join(paths),
                           redact(json.dumps(ev.args, ensure_ascii=False)), redact(ev.content_excerpt or "")]).lower()
        compact.append({"id": ev.event_id, "turn": ev.turn_id, "actor": getattr(ev.actor, "value", ev.actor),
                        "type": getattr(ev.event_type, "value", ev.event_type), "summary": summarize(ev),
                        **({"detection_flags": sorted(set(flags[ev.event_id]))} if ev.event_id in flags else {}),
                        "search": search})
    turns = [{"turn": e.turn_id, "event": e.event_id, "prompt": clip(e.prompt_text, 400)}
             for e in events if e.event_type == "user_prompt"]
    hits = [{"rule_id": h.rule_id, "title": h.title, "severity": h.severity, "event_id": h.event_id,
             "related": list(h.related), "atlas": list(h.atlas)} for h in result.hits]
    top = max((RANK[h["severity"]] for h in hits), default=None)
    sources = sorted({r for h in result.hits if h.rule_id in SOURCE_RULES for r in h.related})
    return Evidence(
        session_id=result.session_id, project=result.project, home=home, status=result.status,
        score=result.risk.score, threshold=result.risk.threshold,
        severity=None if top is None else next(s for s, i in RANK.items() if i == top),
        atlas=sorted({a for h in hits for a in h["atlas"]}),
        contributions=[{"source": c.source, "label": c.label, "points": c.points} for c in result.risk.contributions],
        hits=hits, turns=turns, events=compact,
        has_reply=any(e.event_type == "assistant_response" for e in events), trigger_sources=sources)


# ---------- validation (FR-10) ----------

PATH_RE = re.compile(r"(?<![\w])(?:~|\.{0,2})/[\w.\-@/+]*\w|(?<![\w/])\.[A-Za-z][\w\-]*(?:\.[\w\-]+)*")
FILE_EXT = "py|md|json|ya?ml|toml|sh|txt|cfg|ini|lock|env|js|ts|xml|conf|log|tgz|b64|csv"
FILE_RE = re.compile(rf"\b[\w\-]+\.(?:{FILE_EXT})\b", re.I)
DOMAIN_RE = re.compile(r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.([a-z]{2,})\b", re.I)
RULE_RE = re.compile(r"\b[RD]-\d{2}\b")
EVENT_RE = re.compile(r"\bs-\w+:\d+\b")
QUOTED = re.compile(r"“[^”]*”|\"[^\"]*\"|`[^`]*`")

MOTIVE = re.compile(r"(?i)\b(intend(?:s|ed|ing)?|intention\w*|motive[sd]?|wanted to|wants to|deliberate(?:ly)?|"
                    r"malicious\w*|attacker\w*|steal\w*|stole|hijack\w*|trick\w*|scheme\w*|sabotag\w*)\b")
VERDICT = re.compile(r"(?i)\b(benign|false[- ]positive|harmless|authori[sz]ed|sanctioned|legitimate|"
                     r"no action (?:is )?(?:needed|required)|safe to (?:ignore|close)|can be ignored|"
                     r"not (?:a )?(?:threat|an incident)|low[- ]severity|severity (?:should|can) be|downgrad\w+)\b")


# When a claim says detection flagged something, these phrases name what. Each maps to the rule(s) that make it true.
# (R-03's title is "sensitive read followed by network egress", and R-06's is "encoding before egress", so they count.)
DETECTION_CONTEXT = re.compile(r"(?i)\b(flag\w*|detect\w*|fired|fires|trigger(?:ed|s)|raised|alert(?:ed|s)?)\b")
DETECTION_PHRASES = [
    (re.compile(r"(?i)\bdrift"), {"D-01"}),
    (re.compile(r"(?i)sensitive (?:path )?read|sensitive path|credential read"), {"R-01", "R-03"}),
    (re.compile(r"(?i)instruction-like"), {"R-07"}),
    (re.compile(r"(?i)course change"), {"R-08"}),
    (re.compile(r"(?i)cross-server"), {"R-09"}),
    (re.compile(r"(?i)unreported"), {"R-12"}),
    (re.compile(r"(?i)egress"), {"R-03", "R-06"}),
    (re.compile(r"(?i)archiv\w*|encod\w*"), {"R-06"}),
    (re.compile(r"(?i)not in the project baseline|outside the project baseline|new (?:network )?domain"), {"R-02"}),
    (re.compile(r"(?i)persistence"), {"R-04"}),
    (re.compile(r"(?i)destructive"), {"R-05", "R-10"}),
]


@dataclass
class Problem:
    claim: int | None            # index of the claim, or None for a problem with the narrative as a whole
    code: str
    message: str


def _strip_quotes(text: str) -> str:
    return QUOTED.sub(" ", text)


def concrete_tokens(text: str) -> list[str]:
    """Paths, files, domains and ids a claim names. Each must appear in the events it cites."""
    toks = [m.group(0) for m in PATH_RE.finditer(text)]
    toks += [m.group(0) for m in FILE_RE.finditer(text)]
    for m in DOMAIN_RE.finditer(text):
        if not re.fullmatch(FILE_EXT, m.group(1), re.I):
            toks.append(m.group(0))
    return [t.rstrip(".,;:)") for t in dict.fromkeys(toks)]


def validate(claims: list[dict], ev: Evidence) -> list[Problem]:
    problems: list[Problem] = []
    valid_ids, rules = ev.event_ids(), ev.rule_ids()
    for i, c in enumerate(claims):
        text, cites = c.get("text", ""), c.get("cites", [])
        if c.get("section") not in SECTIONS:
            problems.append(Problem(i, "section", f"unknown section {c.get('section')!r}"))
        if not cites:
            problems.append(Problem(i, "uncited", "the claim cites no events"))
        bad = [x for x in cites if x not in valid_ids]
        if bad:
            problems.append(Problem(i, "bad_cite", f"cited events that do not exist in this session: {bad}"))
        for m in EVENT_RE.findall(text):
            if m not in valid_ids:
                problems.append(Problem(i, "bad_cite", f"the text mentions event {m}, which does not exist"))
        for r in RULE_RE.findall(text):
            if r not in rules:
                problems.append(Problem(i, "bad_rule", f"the text names rule {r}, which did not fire in this session"))
        # Statements about detection must match the real hits on the events the claim cites.
        carried = ev.rules_at([x for x in cites if x in valid_ids])
        if DETECTION_CONTEXT.search(text):
            for rx, rules_ok in DETECTION_PHRASES:
                m = rx.search(text)
                if m and not rules_ok & carried:
                    problems.append(Problem(i, "detection_mismatch",
                                            f"says detection flagged “{m.group(0)}”, but the events it cites carry "
                                            f"{sorted(carried) or 'no detection flags'}; cite the flagged events or drop the statement"))
        for r in RULE_RE.findall(text):
            if r in rules and r not in carried:          # naming a rule ID is itself a statement about detection
                problems.append(Problem(i, "detection_mismatch",
                                        f"names rule {r} as having fired, but it did not fire on the events this claim cites"))
        pool = " ".join(ev.search_text(x) for x in cites if x in valid_ids)
        for tok in concrete_tokens(text):
            t = tok.lower()
            if t not in pool and posixpath.basename(t) not in pool:
                problems.append(Problem(i, "unsupported",
                                        f"“{tok}” does not appear in the events this claim cites ({', '.join(cites) or 'none'})"))
        bare = _strip_quotes(text)
        bare_no_names = " ".join(w for w in bare.split() if not (DOMAIN_RE.search(w) or PATH_RE.search(w)))
        if MOTIVE.search(bare_no_names):
            problems.append(Problem(i, "motive", f"motive or intent language ({MOTIVE.search(bare_no_names).group(0)!r}); "
                                                 "describe only what the events show"))
        if VERDICT.search(bare):
            problems.append(Problem(i, "verdict", f"verdict language ({VERDICT.search(bare).group(0)!r}); the narrator does "
                                                  "not judge, and anything the content claims must be quoted"))
    have = {c.get("section") for c in claims}
    need = {"asked", "deviation", "action"} | ({"reported"} if ev.has_reply else set()) | ({"trigger"} if ev.trigger_sources else set())
    for s in sorted(need - have):
        problems.append(Problem(None, "missing_section", f"no claim in the required section {s!r}"))
    if ev.trigger_sources:
        cited = {x for c in claims if c.get("section") == "trigger" for x in c.get("cites", [])}
        if not cited & set(ev.trigger_sources):
            problems.append(Problem(None, "trigger_not_cited",
                                    f"the trigger claim must cite the content source the detector named: {ev.trigger_sources}"))
    return problems


def claim_validity(claims: list[dict], problems: list[Problem]) -> float:
    if not claims:
        return 0.0
    bad = {p.claim for p in problems if p.claim is not None}
    return (len(claims) - len(bad)) / len(claims)


# ---------- narrators ----------


@dataclass
class NarratorOutput:
    claims: list[dict]
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""


class NarratorError(RuntimeError):
    """The narrator could not produce output (API error, refusal, bad JSON). Carries no secrets."""


class Narrator(Protocol):
    name: str

    def generate(self, ev: Evidence, feedback: list[str] | None = None) -> NarratorOutput: ...


ADVICE = {
    "R-01": "Check with the user whether they asked for this read; if not, treat the credential as exposed and rotate it.",
    "R-02": "Check whether the new network destination is expected for this project.",
    "R-03": "Treat any credential read before the network call as exposed: rotate it and review what was sent.",
    "R-04": "Inspect the persistence location and remove entries nobody recognises.",
    "R-05": "Check what was deleted or overwritten and restore it from backup if needed.",
    "R-06": "Review the archive or encoded data for sensitive contents.",
    "R-07": "Review the cited content source, remove or quarantine it, and check what the session did after reading it.",
    "R-08": "Review the cited content source, remove or quarantine it, and check what the session did after reading it.",
    "R-09": "Review what was sent through the second MCP server and whether that destination was expected.",
    "R-10": "Review why the blocked action was attempted.",
    "R-11": "Check where the newly connected server or plugin came from.",
    "R-12": "Compare the agent's reply with the cited actions: the reply does not mention them.",
    "D-01": "Compare the cited action with the user's request and ask the user whether it was expected.",
}


class TemplateNarrator:
    """Deterministic narrator: needs no key, is the fallback, and is the baseline Claude is compared with."""
    name = "template"

    def generate(self, ev: Evidence, feedback: list[str] | None = None) -> NarratorOutput:
        by_id = {e["id"]: e for e in ev.events}
        flagged = sorted({h["event_id"] for h in ev.hits}, key=lambda i: int(i.split(":")[1]))
        claims: list[dict] = []

        for t in ev.turns[-3:]:
            claims.append({"section": "asked", "text": f"The user asked: “{t['prompt']}”.", "cites": [t["event"]]})

        for eid in flagged[:6]:
            rules = sorted({h["rule_id"] for h in ev.hits if h["event_id"] == eid})
            claims.append({"section": "did", "text": f"At {eid} the agent performed: {self._describe(by_id[eid])}. "
                           f"Detection rules {', '.join(rules)} fired on it.", "cites": [eid]})

        replies = [e for e in ev.events if e["type"] == "assistant_response"]
        if replies:
            last = replies[-1]
            claims.append({"section": "reported", "text": f"The agent's reply to the user said: “{last['summary']}”",
                           "cites": [last["id"]]})
            for h in ev.hits:
                if h["rule_id"] == "R-12":
                    claims.append({"section": "reported", "cites": [last["id"], h["event_id"]],
                                   "text": f"The reply does not mention the action at {h['event_id']} "
                                           f"({self._describe(by_id[h['event_id']])})."})
                    break

        if flagged:
            # The deviation is the first action a RULE flagged at medium or above; a bare drift flag can be an early false lead.
            strong = [h["event_id"] for h in sorted(ev.hits, key=lambda h: h["event_id"].split(":")[1].zfill(6))
                      if h["rule_id"] != "D-01" and RANK[h["severity"]] >= RANK["medium"]]
            first = min(strong, key=lambda i: int(i.split(":")[1])) if strong else flagged[0]
            first_rules = sorted({h["rule_id"] for h in ev.hits if h["event_id"] == first})
            text = f"The first flagged action is at {first} (rules {', '.join(first_rules)})."
            cites = [first]
            if ev.trigger_sources:
                text += f" No user prompt appears between the content at {ev.trigger_sources[0]} and this action."
                cites.append(ev.trigger_sources[0])
            claims.append({"section": "deviation", "text": text, "cites": cites})

        for src in ev.trigger_sources[:1]:
            e = by_id[src]
            claims.append({"section": "trigger", "cites": [src],
                           "text": f"The likely trigger is the result at {src}: {e['summary']}"})

        rules_present = [r for r in ADVICE if r in ev.rule_ids()]
        advice = " ".join(dict.fromkeys(ADVICE[r] for r in rules_present[:4]))
        if advice:
            claims.append({"section": "action", "text": f"Recommended: {advice}", "cites": flagged[:2] or [ev.events[0]["id"]]})
        return NarratorOutput(claims, model="template")

    @staticmethod
    def _describe(e: dict) -> str:
        return e["summary"]


# ---------- orchestration ----------


@dataclass
class Narrative:
    session_id: str
    source: str                       # "template", "claude:<model>", or a fallback description
    accepted: bool
    attempts: int
    claims: list[dict]
    first_attempt_valid_ratio: float
    first_attempt_claims: int
    first_attempt_problems: list[dict]
    final_problems: list[dict]
    fallback_reason: str | None
    usage: dict
    detection: dict


def estimate_cost(model: str, tin: int, tout: int) -> float | None:
    p = PRICES.get(model)
    return None if p is None else tin * p[0] / 1e6 + tout * p[1] / 1e6


def explain_session(ev: Evidence, narrator: Narrator, fallback: Narrator | None = None, max_attempts: int = 3,
                    spent_usd: float = 0.0, max_usd: float | None = None) -> Narrative:
    fallback = fallback or TemplateNarrator()
    tin = tout = 0
    feedback: list[str] | None = None
    first_ratio, first_problems, first_n = 1.0, [], 0
    reason, out = None, None
    attempts = 0
    claims: list[dict] = []
    problems: list[Problem] = []

    for attempt in range(1, max_attempts + 1):
        if max_usd is not None and spent_usd + (estimate_cost(getattr(narrator, "model", ""), tin, tout) or 0) >= max_usd:
            reason = f"spend cap of ${max_usd:.2f} reached"
            break
        attempts = attempt
        try:
            out = narrator.generate(ev, feedback)
        except NarratorError as e:
            reason = f"narrator error: {e}"
            break
        tin += out.input_tokens
        tout += out.output_tokens
        problems = validate(out.claims, ev)
        claims = out.claims
        if attempt == 1:
            first_ratio, first_problems, first_n = claim_validity(claims, problems), [asdict(p) for p in problems], len(claims)
        if not problems:
            break
        feedback = [f"claim {p.claim if p.claim is not None else '-'}: {p.message}" for p in problems][:12]

    accepted = out is not None and not problems and reason is None
    source = (narrator.name if out and out.model in ("", "template") else f"{narrator.name}:{out.model}") if accepted and out else None
    if not accepted:
        fb = fallback.generate(ev)
        claims, source = fb.claims, f"template (fallback: {reason or f'{attempts} attempts rejected'})"
        final = validate(claims, ev)
    else:
        final = []
    return Narrative(
        session_id=ev.session_id, source=source or narrator.name, accepted=accepted or not final, attempts=attempts,
        claims=claims, first_attempt_valid_ratio=first_ratio, first_attempt_claims=first_n,
        first_attempt_problems=first_problems,
        final_problems=[asdict(p) for p in final], fallback_reason=None if accepted else (reason or "validation failed"),
        usage={"input_tokens": tin, "output_tokens": tout,
               "cost_usd": estimate_cost(getattr(narrator, "model", ""), tin, tout)},
        detection={"status": ev.status, "score": ev.score, "threshold": ev.threshold, "severity": ev.severity,
                   "atlas": ev.atlas, "rules": sorted(ev.rule_ids()), "trigger_sources": ev.trigger_sources})


# ---------- rendering ----------


def render_markdown(n: Narrative, ev: Evidence) -> str:
    d = n.detection
    out = [f"# Incident narrative: {n.session_id}", "",
           f"**Detection (computed by the rules, not by the narrator):** {d['status'].upper()} · score {d['score']}/100 "
           f"(alert at {d['threshold']}) · highest severity {d['severity']} · rules {', '.join(d['rules'])} · "
           f"ATLAS {', '.join(d['atlas'])}", "",
           f"*Narrative source: {n.source}.*", ""]
    by_section: dict[str, list[dict]] = {}
    for c in n.claims:
        by_section.setdefault(c["section"], []).append(c)
    for s in SECTIONS:
        if s in by_section:
            out += [f"## {HEADINGS[s]}", ""]
            out += [f"- {c['text']} " + " ".join(f"[{x}]" for x in c["cites"]) for c in by_section[s]] + [""]
    cited = {x for c in n.claims for x in c["cites"]}
    ids = sorted(cited, key=lambda i: int(i.split(":")[1]))
    by_id = {e["id"]: e for e in ev.events}
    out += ["## Cited events", "", "| Event | Type | What it recorded |", "|---|---|---|"]
    out += [f"| {i} | {by_id[i]['type']} | {by_id[i]['summary'].replace('|', '/')} |" for i in ids if i in by_id]
    return "\n".join(out) + "\n"


# ---------- CLI ----------


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Explain alert sessions as cited narratives.")
    p.add_argument("--db", type=Path, default=ROOT / "agenttrail.db")
    p.add_argument("--session", action="append", help="session id (repeatable)")
    p.add_argument("--all", action="store_true", help="every session whose status is alert")
    p.add_argument("--narrator", choices=["template", "claude"], default="template")
    p.add_argument("--model", default="claude-opus-5-5")
    p.add_argument("--effort", default="medium", choices=["low", "medium", "high"])
    p.add_argument("--max-usd", type=float, default=1.0, help="stop calling Claude once estimated spend reaches this")
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--out", type=Path, default=ROOT / "reports" / "narratives")
    a = p.parse_args(argv)

    ctx = load_context(a.db)
    results = {r.session_id: r for r in analyze_all(ctx, a.db)}
    ids = a.session or [sid for sid, r in results.items() if a.all and r.status == "alert"]
    if not ids:
        print("nothing to explain: pass --session ID or --all")
        return 1

    if a.narrator == "claude":
        from agenttrail.claude_narrator import ClaudeNarrator, credentials_available
        if not credentials_available():
            print("No ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) in this shell's environment, so no request was made.\n"
                  "Export it in this terminal first:  export ANTHROPIC_API_KEY=...   (the key is read from the environment,\n"
                  "never printed or written to disk). Use --narrator template to run without one.")
            return 2
        narrator: Narrator = ClaudeNarrator(model=a.model, effort=a.effort)
    else:
        narrator = TemplateNarrator()

    conn = store.connect(a.db)
    a.out.mkdir(parents=True, exist_ok=True)
    spent = 0.0
    for sid in ids:
        if sid not in results:
            print(f"{sid}: unknown session")
            continue
        r = results[sid]
        ev = build_evidence(r, store.get_session_events(conn, sid), ctx.cfg.home)
        n = explain_session(ev, narrator, max_attempts=a.max_attempts, spent_usd=spent, max_usd=a.max_usd if a.narrator == "claude" else None)
        spent += n.usage["cost_usd"] or 0.0
        (a.out / f"{sid}.json").write_text(json.dumps(asdict(n), indent=2, ensure_ascii=False) + "\n")
        (a.out / f"{sid}.md").write_text(render_markdown(n, ev))
        print(f"{sid}: {n.source}; attempts {n.attempts}; first-attempt valid claims {n.first_attempt_valid_ratio:.0%}"
              + (f"; ${n.usage['cost_usd']:.3f}" if n.usage["cost_usd"] else ""))
    if a.narrator == "claude":
        print(f"estimated spend ${spent:.3f} of ${a.max_usd:.2f} cap")
    print(f"narratives written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
