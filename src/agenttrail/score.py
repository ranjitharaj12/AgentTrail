"""Session risk score (PRD FR-8) and the end-to-end analysis used by the CLI, eval and UI.

score = rule points + drift points (<= drift_cap) + judge points (<= judge_cap), capped at 100.
Nothing can lower it: every input is clamped to >= 0.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agenttrail import store
from agenttrail.baseline import Baseline
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

    @classmethod
    def load(cls, path: Path = ROOT / "config" / "scoring.yaml") -> "Scoring":
        raw = yaml.safe_load(Path(path).read_text())
        if set(raw["points"]) != set(SEVERITIES):
            raise ValueError(f"scoring points must cover exactly {SEVERITIES}")
        return cls(raw["points"], raw["drift_cap"], raw["judge_cap"], raw["threshold"])


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

    @property
    def flagged(self) -> bool:
        return self.score >= self.threshold

    def total(self, source: str) -> int:
        return sum(c.points for c in self.contributions if c.source == source)


def score_session(hits: list[Hit], scoring: Scoring, drift_points: int = 0, judge_points: int = 0) -> RiskScore:
    contribs = [Contribution("rule", f"{h.rule_id} {h.severity} @ {h.event_id}", scoring.points[h.severity])
                for h in hits]
    drift = min(max(drift_points, 0), scoring.drift_cap)
    judge = min(max(judge_points, 0), scoring.judge_cap)
    if drift:
        contribs.append(Contribution("drift", "event and window drift", drift))
    if judge:
        contribs.append(Contribution("judge", "session judge", judge))
    raw = sum(c.points for c in contribs)
    return RiskScore(min(raw, 100), scoring.threshold, contribs, raw)


# ---------- end-to-end analysis ----------


@dataclass
class Context:
    cfg: Config
    rules: list[Rule]
    scoring: Scoring
    baseline: Baseline
    split: dict[str, list[str]]


@dataclass
class SessionResult:
    session_id: str
    project: str
    split: str                      # "tuning", "test", or "attack"
    malicious: bool
    n_events: int
    hits: list[Hit]
    risk: RiskScore

    @property
    def top_alert(self) -> Hit | None:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return max(self.hits, key=lambda h: (order[h.severity], -h.seq), default=None)


def load_context(db_path: Path = ROOT / "agenttrail.db", rules_dir: Path = ROOT / "rules",
                 split_path: Path = ROOT / "config" / "split.yaml") -> Context:
    cfg = Config.load(ROOT / "config" / "projects.yaml")
    split = yaml.safe_load(Path(split_path).read_text())
    conn = store.connect(db_path)
    malicious = {r["session_id"] for r in conn.execute("SELECT session_id FROM labels WHERE malicious=1")}
    if set(split["tuning"]) & malicious or set(split["test"]) & malicious:
        raise ValueError("the tuning/test split must contain benign sessions only")
    if set(split["tuning"]) & set(split["test"]):
        raise ValueError("tuning and test sets overlap")
    baseline = Baseline.build({sid: store.get_session_events(conn, sid) for sid in split["tuning"]}, cfg)
    return Context(cfg, load_rules(rules_dir), Scoring.load(), baseline, split)


def analyze_all(ctx: Context, db_path: Path = ROOT / "agenttrail.db") -> list[SessionResult]:
    conn = store.connect(db_path)
    out = []
    for s in store.list_sessions(conn):
        sid = s["session_id"]
        label = conn.execute("SELECT malicious FROM labels WHERE session_id=?", (sid,)).fetchone()
        events = store.get_session_events(conn, sid)
        hits = run_rules(events, ctx.rules, ctx.cfg.home, ctx.baseline)
        where = "tuning" if sid in ctx.split["tuning"] else "test" if sid in ctx.split["test"] else "attack"
        out.append(SessionResult(sid, s["project"], where, bool(label and label["malicious"]), len(events),
                                 hits, score_session(hits, ctx.scoring)))
    return sorted(out, key=lambda r: (-r.risk.score, r.session_id))


def flagged_event_ids(result: SessionResult) -> set[str]:
    return {h.event_id for h in result.hits}


# ---------- CLI: ranked sessions ----------


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Rank sessions by risk score.")
    p.add_argument("--db", type=Path, default=ROOT / "agenttrail.db")
    p.add_argument("-v", "--verbose", action="store_true", help="show each score's breakdown")
    a = p.parse_args(argv)

    ctx = load_context(a.db)
    results = analyze_all(ctx, a.db)
    print(f"threshold {ctx.scoring.threshold}; baseline from {len(ctx.split['tuning'])} tuning sessions\n")
    print(f"{'session':9} {'set':7} {'score':>5}  {'':7} {'truth':9} top alert")
    for r in results:
        top = r.top_alert
        top_s = f"{top.rule_id} {top.severity} - {top.title}" if top else ""
        flag = "FLAGGED" if r.risk.flagged else ""
        print(f"{r.session_id:9} {r.split:7} {r.risk.score:>5}  {flag:7} {'malicious' if r.malicious else 'benign':9} {top_s}")
        if a.verbose and r.risk.contributions:
            for c in r.risk.contributions:
                print(f"{'':27}+{c.points:<3} {c.label}")
            if r.risk.uncapped > r.risk.score:
                print(f"{'':27}(uncapped {r.risk.uncapped}, capped at 100)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
