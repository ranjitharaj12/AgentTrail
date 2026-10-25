"""CLI: validate every fixture and load it into SQLite.

    .venv/bin/python -m agenttrail.load            # loads into agenttrail.db
"""
import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from agenttrail import store
from agenttrail.enrich import Config, enrich_session
from agenttrail.fixtures import load_events, load_label

ROOT = Path(__file__).resolve().parent.parent


def load_all(db_path: Path, fixtures_dir: Path, labels_dir: Path,
             config_path: Path = ROOT / "config" / "projects.yaml") -> int:
    conn = store.connect(db_path)
    cfg = Config.load(config_path)
    failures = 0
    for fx in sorted(fixtures_dir.rglob("*.json")):
        label_file = labels_dir / fx.name  # label shares the fixture's filename
        try:
            events = enrich_session(load_events(fx), cfg)
            label = load_label(label_file)
        except (ValidationError, FileNotFoundError, KeyError) as e:
            failures += 1
            print(f"FAIL {fx.name}: {e}", file=sys.stderr)
            continue
        store.save_events(conn, events)
        store.save_label(conn, label)
        print(f"ok   {fx.name}: {len(events)} events")
    return failures


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=ROOT / "agenttrail.db", type=Path)
    a = p.parse_args()
    sys.exit(1 if load_all(a.db, ROOT / "fixtures", ROOT / "labels") else 0)
