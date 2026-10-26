"""Freeze marker for the detection code, so held-out results can be trusted.

Held-out attack variants only mean something if they were written AFTER the detection logic
stopped changing. `--record` stores a fingerprint (SHA-256 of every file that decides a score).
The evaluator re-checks it and says plainly whether anything changed since.

    .venv/bin/python -m agenttrail.freeze --record     # at the moment you freeze
    .venv/bin/python -m agenttrail.freeze              # show whether the freeze still holds

split.yaml is deliberately not fingerprinted: adding held-out session ids to it is expected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FREEZE_FILE = ROOT / "config" / "freeze.json"

CODE = ["enrich.py", "rules.py", "drift.py", "baseline.py", "score.py", "schema.py"]
CONFIG = ["projects.yaml", "drift.yaml", "scoring.yaml"]


def tracked_files() -> list[Path]:
    return (sorted((ROOT / "rules").glob("*.yaml"))
            + [ROOT / "config" / c for c in CONFIG]
            + [ROOT / "agenttrail" / c for c in CODE])


def fingerprint() -> dict[str, str]:
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_files()}


def record(path: Path = FREEZE_FILE, note: str = "") -> dict:
    files = fingerprint()
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    data = {"frozen_on": date.today().isoformat(), "note": note, "digest": digest, "files": files}
    path.write_text(json.dumps(data, indent=2) + "\n")
    return data


def check(path: Path = FREEZE_FILE) -> dict:
    """{'recorded': bool, 'frozen_on': str|None, 'unchanged': bool, 'changed': [files]}"""
    if not Path(path).exists():
        return {"recorded": False, "frozen_on": None, "unchanged": False, "changed": []}
    saved = json.loads(Path(path).read_text())
    now = fingerprint()
    changed = sorted(f for f in set(saved["files"]) | set(now) if saved["files"].get(f) != now.get(f))
    return {"recorded": True, "frozen_on": saved["frozen_on"], "unchanged": not changed, "changed": changed}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Record or check the detection-code freeze.")
    p.add_argument("--record", action="store_true", help="record the current state as the freeze")
    p.add_argument("--note", default="", help="why this is the freeze point")
    a = p.parse_args(argv)
    if a.record:
        d = record(note=a.note)
        print(f"froze {len(d['files'])} files on {d['frozen_on']} (digest {d['digest'][:12]})")
        return 0
    s = check()
    if not s["recorded"]:
        print("no freeze recorded")
        return 1
    print(f"frozen on {s['frozen_on']}: " + ("unchanged since" if s["unchanged"] else f"CHANGED: {', '.join(s['changed'])}"))
    return 0 if s["unchanged"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
