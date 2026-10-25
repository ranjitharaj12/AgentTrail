"""Intent-drift scoring (PRD FR-6): is what the agent is doing related to what the user asked?

For each event we embed a short description (stated purpose, tool, path, path class) and
compare it with the embedded current intent. Routine commands and reads of the user's own
project files are skipped. Events are also scored in sliding windows, and a run of
consecutive drifting events is flagged. Flags become D-01 hits and a `D-01` signal that
R-08 reads.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import numpy as np
import yaml

from agenttrail.enrich import Config
from agenttrail.rules import Hit
from agenttrail.schema import Event, EventType

ROOT = Path(__file__).resolve().parent.parent
READ_TOOLS = {"Read", "Grep", "Glob", "LS"}
UNSAFE_SHELL = re.compile(r"[|;><`]|\$\(")


# ---------- embedders ----------


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> np.ndarray:
        """Return one L2-normalised row per text."""


class FastEmbedder:
    """bge-small via fastembed (ONNX, runs locally). Caches vectors by text."""

    def __init__(self, model: str, cache_dir: Path):
        from fastembed import TextEmbedding           # imported lazily: tests don't need it
        self._model = TextEmbedding(model_name=model, cache_dir=str(cache_dir))
        self._cache: dict[str, np.ndarray] = {}

    def embed(self, texts: list[str]) -> np.ndarray:
        missing = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if missing:
            vecs = np.array(list(self._model.embed(missing)), dtype=np.float32)
            vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
            self._cache.update(zip(missing, vecs))
        return np.array([self._cache[t] for t in texts])


# ---------- config ----------


@dataclass(frozen=True)
class DriftConfig:
    model: str
    cache_dir: Path
    window_size: int
    event_threshold: float
    window_threshold: float
    run_threshold: float
    run_length: int
    severity: str
    atlas: tuple[str, ...]
    routine: tuple[re.Pattern, ...]

    @classmethod
    def load(cls, path: Path = ROOT / "config" / "drift.yaml") -> "DriftConfig":
        r = yaml.safe_load(Path(path).read_text())
        return cls(r["model"], ROOT / r["cache_dir"], r["window_size"], r["event_threshold"],
                   r["window_threshold"], r["run_threshold"], r["run_length"], r["severity"],
                   tuple(r["atlas"]), tuple(re.compile(p) for p in r["routine_commands"]))

    def make_embedder(self) -> FastEmbedder:
        return FastEmbedder(self.model, self.cache_dir)


# ---------- what gets scored ----------


def is_routine_command(cmd: str, cfg: DriftConfig) -> bool:
    if UNSAFE_SHELL.search(cmd):
        return False
    parts = [p.strip() for p in cmd.split("&&")]
    return all(any(rx.search(p) for rx in cfg.routine) for p in parts)


def skip_reason(ev: Event, cfg: DriftConfig) -> str | None:
    if ev.event_type != EventType.tool_decision or ev.decision != "accept":
        return "not an executed action"
    if ev.tool in READ_TOOLS and ev.trust_level == "user_authored" and ev.path_class == "project":
        return "read of the user's own project file"
    if ev.tool == "Bash" and is_routine_command(str(ev.args.get("command", "")), cfg):
        return "routine command"
    return None


def describe(ev: Event, root: str) -> str:
    """Stated purpose + tool + path + path class. Never the raw command (PRD FR-6)."""
    parts = [ev.stated_purpose or ""]
    parts.append(ev.tool.replace("mcp__", "").replace("__", " ").replace("_", " ") if ev.tool else "")
    parts += [p[len(root) + 1:] if p.startswith(root + "/") else p for p in ev.paths[:3]]
    if ev.path_class:
        parts.append("project file" if ev.path_class == "project" else f"{ev.path_class} file")
    if ev.net_dest:
        parts.append(f"network request to {ev.net_dest}")
    return " ".join(p for p in parts if p)


# ---------- scoring ----------


@dataclass
class DriftResult:
    scores: dict[str, float] = field(default_factory=dict)         # event_id -> distance (scored events only)
    descriptions: dict[str, str] = field(default_factory=dict)
    window_scores: dict[str, float] = field(default_factory=dict)  # keyed by the window's last event
    reasons: dict[str, set] = field(default_factory=dict)          # flagged event_id -> {"event","window","run"}
    hits: list[Hit] = field(default_factory=list)

    @property
    def flagged_event_ids(self) -> set[str]:
        return set(self.reasons)


def compute_drift(events: list[Event], cfg: Config, dcfg: DriftConfig, embedder: Embedder) -> DriftResult:
    events = sorted(events, key=lambda e: e.seq)
    res = DriftResult()
    scored = [e for e in events if skip_reason(e, dcfg) is None and e.intent]
    if not scored:
        return res
    root = {e.project: cfg.projects[e.project].root for e in scored}
    desc = [describe(e, root[e.project]) for e in scored]
    intents = [e.intent for e in scored]

    vecs = embedder.embed(desc)
    ivecs = embedder.embed(intents)
    dist = 1.0 - np.einsum("ij,ij->i", vecs, ivecs)
    for e, d, text in zip(scored, dist, desc):
        res.scores[e.event_id] = float(d)
        res.descriptions[e.event_id] = text
        if d > dcfg.event_threshold:
            res.reasons.setdefault(e.event_id, set()).add("event")

    w = dcfg.window_size
    if len(scored) >= 3:
        spans = [(max(0, i - w + 1), i + 1) for i in range(len(scored))]   # window ending at each event
        wtexts = [" ; ".join(desc[a:b]) for a, b in spans]
        wvecs = embedder.embed(wtexts)
        wd = 1.0 - np.einsum("ij,ij->i", wvecs, ivecs)
        for i, (e, d) in enumerate(zip(scored, wd)):
            if spans[i][1] - spans[i][0] >= 3:            # windows are 3-5 events
                res.window_scores[e.event_id] = float(d)
                if d > dcfg.window_threshold:
                    res.reasons.setdefault(e.event_id, set()).add("window")

    streak = 0
    for e, d in zip(scored, dist):
        streak = streak + 1 if d > dcfg.run_threshold else 0
        if streak >= dcfg.run_length:
            res.reasons.setdefault(e.event_id, set()).add("run")

    by_id = {e.event_id: e for e in scored}
    for eid in sorted(res.reasons, key=lambda i: by_id[i].seq):
        ev = by_id[eid]
        res.hits.append(Hit("D-01", "Drift from the current intent", dcfg.severity, tuple(dcfg.atlas),
                            ev.session_id, eid, ev.seq))
    return res


# ---------- calibration (tuning set only) ----------


def calibrate(results: list[DriftResult], margin: float = 0.01) -> dict[str, float]:
    """Smallest thresholds that would leave every given (benign, tuning) session unflagged.

    event/window: just above the highest score seen. run: just above the best run-of-3
    floor, i.e. the largest t for which some three consecutive events all score above t."""
    ev = [d for r in results for d in r.scores.values()]
    win = [d for r in results for d in r.window_scores.values()]
    floors = []
    for r in results:
        s = list(r.scores.values())
        floors += [min(s[i:i + 3]) for i in range(len(s) - 2)]
    return {"event_threshold": round(max(ev) + margin, 3) if ev else 0.0,
            "window_threshold": round(max(win) + margin, 3) if win else 0.0,
            "run_threshold": round(max(floors) + margin, 3) if floors else 0.0}


# ---------- CLI: look at the scores (used to calibrate on the tuning set) ----------


def main(argv: list[str]) -> int:
    import argparse
    from agenttrail import store
    from agenttrail.score import load_context

    p = argparse.ArgumentParser(description="Show drift scores per session.")
    p.add_argument("--db", type=Path, default=ROOT / "agenttrail.db")
    p.add_argument("-v", "--verbose", action="store_true", help="every scored event")
    p.add_argument("--calibrate", action="store_true", help="suggest thresholds from the tuning sessions")
    a = p.parse_args(argv)

    ctx = load_context(a.db, use_drift=False)
    dcfg = DriftConfig.load()
    emb = dcfg.make_embedder()
    conn = store.connect(a.db)
    if a.calibrate:
        tuning = [compute_drift(store.get_session_events(conn, sid), ctx.cfg, dcfg, emb) for sid in ctx.split["tuning"]]
        print("suggested from the", len(tuning), "tuning sessions (benign only):")
        for k, v in calibrate(tuning).items():
            print(f"  {k}: {v}")
        return 0
    print(f"event>{dcfg.event_threshold}  window>{dcfg.window_threshold}  run>{dcfg.run_threshold}x{dcfg.run_length}\n")
    print(f"{'session':8} {'set':7} {'truth':9} {'n':>3} {'max':>5} {'mean':>5} {'maxwin':>6}  flagged")
    for s in store.list_sessions(conn):
        sid = s["session_id"]
        lab = conn.execute("SELECT malicious FROM labels WHERE session_id=?", (sid,)).fetchone()
        r = compute_drift(store.get_session_events(conn, sid), ctx.cfg, dcfg, emb)
        where = "tuning" if sid in ctx.split["tuning"] else "test" if sid in ctx.split["test"] else "attack"
        sc = list(r.scores.values())
        mx = f"{max(sc):.3f}" if sc else "  -  "
        mean = f"{sum(sc)/len(sc):.3f}" if sc else "  -  "
        mw = f"{max(r.window_scores.values()):.3f}" if r.window_scores else "  -  "
        fl = ", ".join(f"{e.split(':')[1]}({'/'.join(sorted(x[0] for x in rs))})" for e, rs in r.reasons.items())
        print(f"{sid:8} {where:7} {'malicious' if lab and lab['malicious'] else 'benign':9} {len(sc):>3} {mx:>5} {mean:>5} {mw:>6}  {fl}")
        if a.verbose:
            for eid, d in r.scores.items():
                print(f"           {eid.split(':')[1]:>3}  {d:.3f}  {r.descriptions[eid][:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
