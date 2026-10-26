"""Session risk score (PRD FR-8) and the end-to-end analysis used by the CLI, eval and UI.

score = rule points + drift points (<= drift_cap) + judge points (<= judge_cap), capped at 100.
Nothing can lower it: every input is clamped to >= 0.

Status: "alert" when score >= threshold; "review" when below it but at least one drift flag (D-01)
fired; otherwise "clear". Drift alone is capped too low to reach an alert, by design, so the review
tier is how drift-only findings (scope drift with no rule hit) reach an analyst.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agenttrail import store
from agenttrail.baseline import Baseline
from agenttrail.drift import DriftConfig, DriftResult, compute_drift
from agenttrail.enrich import Config
from agenttrail.rules import SEVERITIES, Hit, Rule, load_rules, run_rules

ROOT = Path(__file__).resolve().parent.parent


# ---------- scoring ----------


@dataclass(frozen=True)
class Scoring:
    points: dict[str, int]
    drift_cap: int
    judge_cap: int
    threshold: int
    drift_per_flag: int = 5

    @classmethod
    def load(cls, path: Path = ROOT / "config" / "scoring.yaml") -> "Scoring":
        raw = yaml.safe_load(Path(path).read_text())
        if set(raw["points"]) != set(SEVERITIES):
            raise ValueError(f"scoring points must cover exactly {SEVERITIES}")
        return cls(raw["points"], raw["drift_cap"], raw["judge_cap"], raw["threshold"],
                   raw.get("drift_per_flag", 5))


@dataclass
class Contribution:
    source: str          # "rule", "drift" or "judge"
    label: str           # e.g. "R-03 critical @ s-a01:10"
    points: int


@dataclass
class RiskScore:
    score: int
    threshold: int
    contributions: list[Contribution]
    uncapped: int
    drift_flags: int = 0

    @property
    def flagged(self) -> bool:
        """An alert: the score reached the threshold."""
        return self.score >= self.threshold

    @property
    def needs_review(self) -> bool:
        """Below the alert threshold, but behavior drifted from the user's intent."""
        return not self.flagged and self.drift_flags > 0

    @property
    def status(self) -> str:
        return "alert" if self.flagged else "review" if self.needs_review else "clear"

    def total(self, source: str) -> int:
        return sum(c.points for c in self.contributions if c.source == source)


def score_session(hits: list[Hit], scoring: Scoring, drift_points: int = 0, judge_points: int = 0) -> RiskScore:
    # D-xx hits are drift flags: they feed the capped drift component, not the per-rule points.
    contribs = [Contribution("rule", f"{h.rule_id} {h.severity} @ {h.event_id}", scoring.points[h.severity])
                for h in hits if not h.rule_id.startswith("D-")]
    flags = sum(1 for h in hits if h.rule_id.startswith("D-"))
    drift = min(max(drift_points, 0) + flags * scoring.drift_per_flag, scoring.drift_cap)
    judge = min(max(judge_points, 0), scoring.judge_cap)
    if drift:
        contribs.append(Contribution("drift", f"event and window drift ({flags} flagged)", drift))
    if judge:
        contribs.append(Contribution("judge", "session judge", judge))
    raw = sum(c.points for c in contribs)
    return RiskScore(min(raw, 100), scoring.threshold, contribs, raw, flags)


# ---------- end-to-end analysis ----------


@dataclass
class Context:
    cfg: Config
    rules: list[Rule]
    scoring: Scoring
    baseline: Baseline
    split: dict[str, list[str]]
    drift_cfg: DriftConfig | None = None
    embedder: object | None = None          # created on first use: loading the model takes a moment

    def get_embedder(self):
        if self.embedder is None:
            self.embedder = self.drift_cfg.make_embedder()
        return self.embedder


@dataclass
class SessionResult:
    session_id: str
    project: str
    split: str                      # "tuning", "test", or "attack"
    malicious: bool
    n_events: int
    hits: list[Hit]
    risk: RiskScore
    drift: DriftResult | None = None
    scenario: str = ""
    truth_events: frozenset = frozenset()       # ground-truth malicious event ids (eval only)
    trigger: str | None = None
    n_prompts: int = 0

    @property
    def status(self) -> str:
        return self.risk.status

    @property
    def top_alert(self) -> Hit | None:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return max(self.hits, key=lambda h: (order[h.severity], -h.seq), default=None)


def load_context(db_path: Path = ROOT / "agenttrail.db", rules_dir: Path = ROOT / "rules",
                 split_path: Path = ROOT / "config" / "split.yaml", use_drift: bool = True,
                 embedder=None) -> Context:
    cfg = Config.load(ROOT / "config" / "projects.yaml")
    split = yaml.safe_load(Path(split_path).read_text())
    conn = store.connect(db_path)
    malicious = {r["session_id"] for r in conn.execute("SELECT session_id FROM labels WHERE malicious=1")}
    if set(split["tuning"]) & malicious or set(split["test"]) & malicious:
        raise ValueError("the tuning/test split must contain benign sessions only")
    if set(split["tuning"]) & set(split["test"]):
        raise ValueError("tuning and test sets overlap")
    baseline = Baseline.build({sid: store.get_session_events(conn, sid) for sid in split["tuning"]}, cfg)
    return Context(cfg, load_rules(rules_dir), Scoring.load(), baseline, split,
                   DriftConfig.load() if use_drift else None, embedder)


def analyze_all(ctx: Context, db_path: Path = ROOT / "agenttrail.db") -> list[SessionResult]:
    conn = store.connect(db_path)
    out = []
    for s in store.list_sessions(conn):
        sid = s["session_id"]
        label = conn.execute("SELECT * FROM labels WHERE session_id=?", (sid,)).fetchone()
        events = store.get_session_events(conn, sid)
        drift = compute_drift(events, ctx.cfg, ctx.drift_cfg, ctx.get_embedder()) if ctx.drift_cfg else None
        hits = run_rules(events, ctx.rules, ctx.cfg.home, ctx.baseline, drift)
        where = ("tuning" if sid in ctx.split["tuning"] else "test" if sid in ctx.split["test"]
                 else "heldout" if sid in ctx.split.get("heldout", [])
                 else "retired" if sid in ctx.split.get("retired_heldout", []) else "attack")
        out.append(SessionResult(
            sid, s["project"], where, bool(label and label["malicious"]), len(events), hits,
            score_session(hits, ctx.scoring), drift,
            scenario=label["scenario"] if label else "",
            truth_events=frozenset(json.loads(label["malicious_event_ids"])) if label else frozenset(),
            trigger=label["trigger_event_id"] if label else None,
            n_prompts=sum(e.event_type == "user_prompt" for e in events)))
    tier = {"alert": 2, "review": 1, "clear": 0}      # alerts first, then the review list, then the rest
    return sorted(out, key=lambda r: (-tier[r.status], -r.risk.score, r.session_id))


def flagged_event_ids(result: SessionResult) -> set[str]:
    return {h.event_id for h in result.hits}


# ---------- CLI: ranked sessions ----------


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Rank sessions: alerts, then the needs-review list, then the rest.")
    p.add_argument("--db", type=Path, default=ROOT / "agenttrail.db")
    p.add_argument("-v", "--verbose", action="store_true", help="show each score's breakdown")
    a = p.parse_args(argv)

    ctx = load_context(a.db)
    results = analyze_all(ctx, a.db)
    print(f"threshold {ctx.scoring.threshold}; baseline from {len(ctx.split['tuning'])} tuning sessions\n")
    counts = {k: sum(r.status == k for r in results) for k in ("alert", "review", "clear")}
    print(f"{counts['alert']} alert, {counts['review']} needs review, {counts['clear']} clear\n")
    print(f"{'session':9} {'set':7} {'score':>5}  {'status':7} {'truth':9} top alert")
    for r in results:
        top = r.top_alert
        top_s = f"{top.rule_id} {top.severity} - {top.title}" if top else ""
        status = {"alert": "ALERT", "review": "REVIEW", "clear": ""}[r.status]
        print(f"{r.session_id:9} {r.split:7} {r.risk.score:>5}  {status:7} {'malicious' if r.malicious else 'benign':9} {top_s}")
        if a.verbose and r.risk.contributions:
            for c in r.risk.contributions:
                print(f"{'':27}+{c.points:<3} {c.label}")
            if r.risk.uncapped > r.risk.score:
                print(f"{'':27}(uncapped {r.risk.uncapped}, capped at 100)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
