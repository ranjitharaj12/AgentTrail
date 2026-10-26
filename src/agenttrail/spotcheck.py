"""Human spot-check of narrative claims (PRD: "cited events actually support the claim", >= 90%, spot-checked).

The automatic validator checks that cited events exist and that named paths, domains and rule IDs appear in
them. It cannot judge whether a claim is a FAIR reading of the evidence. A person can, on a small random sample.

    .venv/bin/python -m agenttrail.spotcheck --sample                # draw the sample and print it
    .venv/bin/python -m agenttrail.spotcheck --record "1Y 2Y 3P 4N"  # save your verdicts (Y supported, P partly, N not)

Only narratives that Claude wrote are sampled; template narratives are rule-generated and prove nothing here.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

from agenttrail import store
from agenttrail.eval import load_narratives
from agenttrail.explain import build_evidence
from agenttrail.score import ROOT, analyze_all, load_context

SAMPLE_FILE = ROOT / "reports" / "spotcheck_sample.json"
RESULT_FILES = {"human": ROOT / "reports" / "spotcheck.json", "claude": ROOT / "reports" / "spotcheck_claude.json"}
LABELS = {"Y": "supported", "P": "partly supported", "N": "not supported"}


def build_sample(db: Path, narratives_dir: Path, n: int = 12, seed: int = 1025, extra: list[tuple[str, int]] = ()) -> list[dict]:
    ctx = load_context(db, use_drift=False)               # rules only: enough to write evidence text, no model needed
    results = {r.session_id: r for r in analyze_all(ctx, db)}
    conn = store.connect(db)
    claude = [x for x in load_narratives(narratives_dir) if x["usage"]["input_tokens"] > 0]
    pool = [(x["session_id"], i) for x in claude for i in range(len(x["claims"]))]
    chosen = random.Random(seed).sample(pool, min(n, len(pool)))
    chosen += [e for e in extra if e not in chosen and any(x["session_id"] == e[0] for x in claude)]
    by_session = {x["session_id"]: x for x in claude}
    evidence = {}
    sample = []
    for k, (sid, i) in enumerate(chosen, 1):
        if sid not in evidence:
            evidence[sid] = {e["id"]: e for e in build_evidence(results[sid], store.get_session_events(conn, sid), ctx.cfg.home).events}
        claim = by_session[sid]["claims"][i]
        sample.append({"n": k, "session": sid, "claim_index": i, "section": claim["section"], "text": claim["text"],
                       "random": (sid, i) not in extra,
                       "cites": [{"id": c, "type": evidence[sid][c]["type"], "text": evidence[sid][c]["summary"]} for c in claim["cites"]]})
    return sample


def render(sample: list[dict]) -> str:
    out = []
    for s in sample:
        tag = "" if s["random"] else "   (one I flagged while reading)"
        out += [f"{s['n']}. {s['session']} · {s['section']}{tag}", f"   CLAIM: {s['text']}", "   EVIDENCE it cites:"]
        out += [f"     [{c['id']}] ({c['type']}) {c['text'][:330]}" for c in s["cites"]]
        out.append("")
    return "\n".join(out)


def record(verdicts: str, sample: list[dict], reviewer: str = "human") -> dict:
    found = dict((int(m.group(1)), m.group(2).upper()) for m in re.finditer(r"(\d+)\s*([YPNypn])", verdicts))
    missing = [s["n"] for s in sample if s["n"] not in found]
    if missing:
        raise SystemExit(f"missing verdicts for items {missing}")
    rows = [{"n": s["n"], "session": s["session"], "claim_index": s["claim_index"], "verdict": found[s["n"]],
             "random": s["random"]} for s in sample]
    rand = [r for r in rows if r["random"]]                 # the headline counts only the random draw
    count = lambda rs, v: sum(r["verdict"] == v for r in rs)
    return {"reviewer": reviewer, "sampled": len(rand), "supported": count(rand, "Y"), "partly": count(rand, "P"), "not_supported": count(rand, "N"),
            "all_items": rows, "flagged_items_not_counted": [r for r in rows if not r["random"]]}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Draw and record a human spot-check of Claude-written claims.")
    p.add_argument("--db", type=Path, default=ROOT / "agenttrail.db")
    p.add_argument("--narratives", type=Path, default=ROOT / "reports" / "narratives")
    p.add_argument("--sample", action="store_true")
    p.add_argument("--n", type=int, default=12)
    p.add_argument("--extra", default="", help="session:claim_index pairs to add, e.g. s-a07:7,s-h02:7")
    p.add_argument("--record", help='verdicts, e.g. "1Y 2Y 3P"')
    p.add_argument("--reviewer", choices=["human", "claude"], default="human",
                   help="who made the judgements. A Claude review is stored apart and never counts as the human check")
    a = p.parse_args(argv)
    if a.sample:
        extra = [(x.split(":")[0], int(x.split(":")[1])) for x in a.extra.split(",") if x]
        sample = build_sample(a.db, a.narratives, a.n, extra=extra)
        SAMPLE_FILE.parent.mkdir(exist_ok=True)
        SAMPLE_FILE.write_text(json.dumps(sample, indent=2, ensure_ascii=False) + "\n")
        print(render(sample))
        return 0
    if a.record:
        res = record(a.record, json.loads(SAMPLE_FILE.read_text()), a.reviewer)
        RESULT_FILES[a.reviewer].write_text(json.dumps(res, indent=2) + "\n")
        print(f"recorded ({a.reviewer}): {res['supported']} supported, {res['partly']} partly, {res['not_supported']} not, "
              f"of {res['sampled']} random claims")
        return 0
    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
