"""YAML rule engine.

A rule file has exactly one of three bodies:

  match:      a single-event rule.
  sequence:   an ordered list of named steps over events in one session.
  check:      a named built-in check (currently: unreported_action).

MATCH NODES. A node is a mapping where
  - each ordinary key is an event field (dotted for nested, e.g. args.command) and its
    value is a condition; ALL of a node's conditions must hold;
  - `any:` is a list of nodes, at least one must match;
  - `not:` is a node that must NOT match.

CONDITIONS
  scalar              the field equals it (for list fields: some element equals it)
  [a, b]              the field equals any of them
  {regex: "..."}      re.search on the value (for list fields: some element)
  {any_regex: [...]}  any of several patterns
  {contains: "..."}   substring
  {exists: true}      the field is present / non-empty
  {ne_step: "s.f"}    (sequence steps only) differs from field f of the event matched by earlier step s

COMPUTED FIELDS usable in nodes (not stored on events):
  after_first_prompt, path_in_intent, mcp_server_in_intent,
  domain_new            net_dest is absent from the project's baseline (False if no baseline)
  signals               ids of single-event rules that fired on this event
  any_step_path_in_intent   (severity_overrides of sequence rules) an earlier step touched a path the user named

SEQUENCES. Steps must match distinct events in increasing order. A step may add
  within: N              at most N events (by seq) after the previous step
  no_prompt_between: true   no user_prompt between it and the previous step
A hit lands on the last step's event and cites the earlier steps in `related`.
"""
from __future__ import annotations

import posixpath
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agenttrail.baseline import Baseline
from agenttrail.enrich import command_binary
from agenttrail.schema import Event, EventType

SEVERITIES = ("low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
OPERATORS = {"regex", "any_regex", "contains", "exists", "ne_step"}


class RuleError(ValueError):
    pass


@dataclass
class Step:
    name: str
    match: dict
    within: int | None = None
    no_prompt_between: bool = False


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    atlas: list[str]
    kind: str                                  # "event" | "sequence" | "check"
    match: dict | None = None
    steps: list[Step] = field(default_factory=list)
    check: str | None = None
    params: dict = field(default_factory=dict)
    overrides: list[dict] = field(default_factory=list)
    description: str = ""
    source: str = ""


@dataclass(frozen=True)
class Hit:
    rule_id: str
    title: str
    severity: str
    atlas: tuple[str, ...]
    session_id: str
    event_id: str
    seq: int
    related: tuple[str, ...] = ()              # earlier steps / the reply that was checked


# ---------- loading and validation ----------


def _check_node(node, where: str, earlier: frozenset = frozenset()) -> None:
    if not isinstance(node, dict) or not node:
        raise RuleError(f"{where}: a match node must be a non-empty mapping")
    for key, value in node.items():
        if key == "any":
            if not isinstance(value, list) or not value:
                raise RuleError(f"{where}: 'any' must be a non-empty list")
            for i, sub in enumerate(value):
                _check_node(sub, f"{where}.any[{i}]", earlier)
        elif key == "not":
            _check_node(value, f"{where}.not", earlier)
        elif isinstance(value, dict):
            if len(value) != 1 or next(iter(value)) not in OPERATORS:
                raise RuleError(f"{where}.{key}: use exactly one of {sorted(OPERATORS)}")
            op, arg = next(iter(value.items()))
            if op == "ne_step":
                if not isinstance(arg, str) or arg.split(".")[0] not in earlier:
                    raise RuleError(f"{where}.{key}: ne_step must name an earlier step as 'step.field'")
            patterns = [arg] if op == "regex" else arg if op == "any_regex" else []
            for p in patterns:
                try:
                    re.compile(p)
                except (re.error, TypeError) as e:
                    raise RuleError(f"{where}.{key}: bad regex {p!r}: {e}")


def _load_steps(raw_steps, name: str) -> list[Step]:
    if not isinstance(raw_steps, list) or len(raw_steps) < 2:
        raise RuleError(f"{name}: a sequence needs at least 2 steps")
    steps, seen = [], set()
    for i, s in enumerate(raw_steps):
        if "name" not in s or "match" not in s:
            raise RuleError(f"{name}.sequence[{i}]: each step needs 'name' and 'match'")
        if s["name"] in seen:
            raise RuleError(f"{name}: duplicate step name {s['name']!r}")
        _check_node(s["match"], f"{name}.sequence[{s['name']}]", frozenset(seen))
        seen.add(s["name"])
        steps.append(Step(s["name"], s["match"], s.get("within"), bool(s.get("no_prompt_between"))))
    return steps


def load_rule(path: Path) -> Rule:
    path = Path(path)
    raw = yaml.safe_load(path.read_text())
    for k in ("id", "title", "severity", "atlas"):
        if k not in raw:
            raise RuleError(f"{path.name}: missing required key '{k}'")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{path.name}: severity must be one of {SEVERITIES}")
    bodies = [k for k in ("match", "sequence", "check") if k in raw]
    if len(bodies) != 1:
        raise RuleError(f"{path.name}: needs exactly one of match / sequence / check, found {bodies or 'none'}")
    kind = {"match": "event", "sequence": "sequence", "check": "check"}[bodies[0]]

    rule = Rule(id=raw["id"], title=raw["title"], severity=raw["severity"], atlas=list(raw["atlas"]),
                kind=kind, description=raw.get("description", ""), source=path.name,
                params=raw.get("params", {}))
    if kind == "event":
        _check_node(raw["match"], f"{path.name}.match")
        rule.match = raw["match"]
    elif kind == "sequence":
        rule.steps = _load_steps(raw["sequence"], path.name)
    else:
        if raw["check"] not in CHECKS:
            raise RuleError(f"{path.name}: unknown check {raw['check']!r}; have {sorted(CHECKS)}")
        rule.check = raw["check"]
        if rule.params.get("min_severity", "high") not in SEVERITIES:
            raise RuleError(f"{path.name}: bad min_severity")

    for i, o in enumerate(raw.get("severity_overrides", [])):
        if o.get("severity") not in SEVERITIES:
            raise RuleError(f"{path.name}: override {i} has a bad severity")
        _check_node(o["when"], f"{path.name}.severity_overrides[{i}].when")
        rule.overrides.append(o)
    return rule


def load_rules(directory: Path) -> list[Rule]:
    rules = [load_rule(p) for p in sorted(Path(directory).glob("*.yaml"))]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise RuleError("duplicate rule ids")
    return rules


# ---------- matching ----------


def _values(raw) -> list:
    if raw is None or (isinstance(raw, (str, list, dict)) and not raw):
        return []
    return raw if isinstance(raw, list) else [raw]


def _condition_ok(values: list, cond, refs: dict | None) -> bool:
    if isinstance(cond, dict):
        op, arg = next(iter(cond.items()))
        if op == "exists":
            return bool(values) == bool(arg)
        if op == "contains":
            return any(arg in str(v) for v in values)
        if op == "ne_step":
            if refs is None:                      # candidate search: checked once the chain is built
                return True
            step, fld = arg.split(".", 1)
            other = {str(v) for v in _values(_lookup(refs[step], {}, fld))}
            return not ({str(v) for v in values} & other)
        patterns = [arg] if op == "regex" else arg
        return any(re.search(p, str(v)) for v in values for p in patterns)
    allowed = cond if isinstance(cond, list) else [cond]
    return any(v in allowed for v in values)


def _lookup(fields: dict, context: dict, name: str):
    if name in context:
        return context[name]
    cur = fields
    for part in name.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def _node_matches(node: dict, fields: dict, context: dict, refs: dict | None = None) -> bool:
    for key, value in node.items():
        if key == "any":
            if not any(_node_matches(n, fields, context, refs) for n in value):
                return False
        elif key == "not":
            if _node_matches(value, fields, context, refs):
                return False
        elif not _condition_ok(_values(_lookup(fields, context, key)), value, refs):
            return False
    return True


def _path_in_intent(ev: Event, home: str) -> bool:
    """True if the user's own words name one of the paths the event touched."""
    if not ev.intent:
        return False
    for p in ev.paths:
        base = posixpath.basename(p)
        tilde = "~/" + p[len(home) + 1:] if p.startswith(home + "/") else None
        if p in ev.intent or (tilde and tilde in ev.intent) \
                or (base.startswith(".") and base in ev.intent):
            return True
    return False


def _context(ev: Event, first_prompt_seq: int | None, home: str, signals: list[str],
             baseline: Baseline | None = None) -> dict:
    return {
        "domain_new": bool(baseline and ev.net_dest and baseline.has_project(ev.project)
                           and not baseline.knows_domain(ev.project, ev.net_dest)),
        "after_first_prompt": first_prompt_seq is not None and ev.seq > first_prompt_seq,
        "path_in_intent": _path_in_intent(ev, home),
        "mcp_server_in_intent": bool(ev.mcp_server and ev.intent
                                     and ev.mcp_server.lower() in ev.intent.lower()),
        "signals": signals,
    }


def _severity(rule: Rule, fields: dict, ctx: dict) -> str:
    for o in rule.overrides:
        if _node_matches(o["when"], fields, ctx):
            return o["severity"]
    return rule.severity


# ---------- sequence rules ----------


def _chains(steps: list[Step], cand: list[list[int]], events: list[Event], k: int, later: int):
    """Yield index chains for steps[0..k] ending before `later`, nearest first."""
    for idx in reversed([c for c in cand[k] if c < later]):
        nxt = steps[k + 1]
        if nxt.within is not None and events[later].seq - events[idx].seq > nxt.within:
            continue
        if nxt.no_prompt_between and any(
                e.event_type == EventType.user_prompt and events[idx].seq < e.seq < events[later].seq
                for e in events):
            continue
        if k == 0:
            yield [idx]
        else:
            for prev in _chains(steps, cand, events, k - 1, idx):
                yield [*prev, idx]


def _run_sequence(rule: Rule, events, fields, ctxs) -> list[Hit]:
    steps = rule.steps
    cand = [[i for i in range(len(events)) if _node_matches(s.match, fields[i], ctxs[i])] for s in steps]
    hits = []
    for last in cand[-1]:
        for chain in _chains(steps, cand, events, len(steps) - 2, last):
            full = [*chain, last]
            refs = {s.name: fields[i] for s, i in zip(steps, full)}
            if not all(_node_matches(s.match, fields[i], ctxs[i], refs) for s, i in zip(steps, full)):
                continue                                    # e.g. ne_step failed; try the next chain
            ctx = {**ctxs[last], "any_step_path_in_intent": any(ctxs[i]["path_in_intent"] for i in chain)}
            hits.append(_hit(rule, events[last], _severity(rule, fields[last], ctx),
                             tuple(events[i].event_id for i in chain)))
            break
    return hits


def _hit(rule: Rule, ev: Event, severity: str, related=()) -> Hit:
    return Hit(rule.id, rule.title, severity, tuple(rule.atlas), ev.session_id, ev.event_id, ev.seq, related)


# ---------- built-in checks ----------


def _mention_tokens(ev: Event) -> set[str]:
    toks = set(ev.paths)
    toks |= {posixpath.basename(p) for p in ev.paths}
    if ev.net_dest:
        toks.add(ev.net_dest)
    if ev.mcp_server:
        toks.add(ev.mcp_server)
    if ev.tool and ev.tool.startswith("mcp__"):
        toks.add(ev.tool.split("__")[-1])
    if ev.tool == "Bash":
        binary = command_binary(str(ev.args.get("command", "")))
        if binary:
            toks.add(binary)
    return {t.lower() for t in toks if t}


def _unreported_action(rule: Rule, events: list[Event], prior: list[Hit]) -> list[Hit]:
    """A hit at/above min_severity whose event the agent's reply (same turn) never mentions."""
    min_rank = RANK[rule.params.get("min_severity", "high")]
    by_event: dict[str, Event] = {e.event_id: e for e in events}
    flagged = {h.event_id for h in prior if RANK[h.severity] >= min_rank and h.rule_id != rule.id}
    out = []
    for eid in sorted(flagged, key=lambda i: by_event[i].seq):
        ev = by_event[eid]
        replies = [e for e in events if e.event_type == EventType.assistant_response
                   and e.turn_id == ev.turn_id and e.seq > ev.seq]
        if not replies:
            continue
        text = " ".join(r.response or "" for r in replies).lower()
        mentioned = any(re.search(rf"(?<!\w){re.escape(t)}(?!\w)", text) for t in _mention_tokens(ev))
        if not mentioned:
            out.append(_hit(rule, ev, rule.severity, tuple(r.event_id for r in replies)))
    return out


CHECKS = {"unreported_action": _unreported_action}


# ---------- running ----------


def run_rules(events: list[Event], rules: list[Rule], home: str = "/home/dev",
              baseline: Baseline | None = None) -> list[Hit]:
    """Order matters: event rules, then sequences (which can read event-rule signals), then checks.

    Without a baseline, baseline-dependent fields (domain_new) are False, so R-02 stays quiet."""
    events = sorted(events, key=lambda e: e.seq)
    fields = [e.model_dump(mode="json") for e in events]
    first_prompt = next((e.seq for e in events if e.event_type == EventType.user_prompt), None)

    signals: dict[str, list[str]] = {e.event_id: [] for e in events}
    hits: list[Hit] = []
    base_ctx = [_context(e, first_prompt, home, [], baseline) for e in events]

    for rule in (r for r in rules if r.kind == "event"):
        for i, ev in enumerate(events):
            if _node_matches(rule.match, fields[i], base_ctx[i]):
                hits.append(_hit(rule, ev, _severity(rule, fields[i], base_ctx[i])))
                signals[ev.event_id].append(rule.id)

    ctxs = [_context(e, first_prompt, home, signals[e.event_id], baseline) for e in events]
    for rule in (r for r in rules if r.kind == "sequence"):
        hits += _run_sequence(rule, events, fields, ctxs)

    for rule in (r for r in rules if r.kind == "check"):
        hits += CHECKS[rule.check](rule, events, hits)

    return sorted(hits, key=lambda h: (h.seq, h.rule_id))


# ---------- CLI: run every rule over every stored session ----------


def main(argv: list[str]) -> int:
    import argparse
    from agenttrail import store
    from agenttrail.enrich import Config

    root = Path(__file__).resolve().parent.parent
    p = argparse.ArgumentParser(description="Run YAML rules over the stored sessions.")
    p.add_argument("--db", type=Path, default=root / "agenttrail.db")
    p.add_argument("--rules", type=Path, default=root / "rules")
    p.add_argument("--config", type=Path, default=root / "config" / "projects.yaml")
    p.add_argument("-v", "--verbose", action="store_true", help="show every hit")
    a = p.parse_args(argv)

    rules = load_rules(a.rules)
    home = Config.load(a.config).home
    conn = store.connect(a.db)
    print(f"{len(rules)} rules: {', '.join(r.id for r in rules)}\n")
    print(f"{'session':9} {'label':10}{'hits':>4}  rules (severity)")
    for s in store.list_sessions(conn):
        sid = s["session_id"]
        label = conn.execute("SELECT malicious FROM labels WHERE session_id=?", (sid,)).fetchone()
        hits = run_rules(store.get_session_events(conn, sid), rules, home)
        kind = "MALICIOUS" if label and label["malicious"] else "benign"
        summary = ", ".join(sorted({f"{h.rule_id}({h.severity[0].upper()})" for h in hits}))
        print(f"{sid:9} {kind:10}{len(hits):>3}  {summary}")
        if a.verbose:
            for h in hits:
                rel = f"  <- {', '.join(h.related)}" if h.related else ""
                print(f"            {h.event_id:9} {h.rule_id:5} {h.severity:8}{rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
