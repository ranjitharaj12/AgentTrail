"""Read a fixture file and validate every event against the schema."""
import json
from pathlib import Path

from agenttrail.schema import Event, Label


def load_events(path: Path) -> list[Event]:
    raw = json.loads(Path(path).read_text())
    return [Event(**e) for e in raw]  # raises ValidationError on a bad event


def load_label(path: Path) -> Label:
    return Label(**json.loads(Path(path).read_text()))
