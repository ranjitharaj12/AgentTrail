from pathlib import Path

import pytest
from pydantic import ValidationError

from agenttrail.fixtures import load_events, load_label
from agenttrail.schema import Event

ROOT = Path(__file__).resolve().parent.parent


def test_sample_fixture_validates():
    events = load_events(ROOT / "fixtures/benign/b00_fix_failing_test.json")
    assert len(events) == 6
    assert events[0].event_id == "s-b00:1"


def test_sample_label_validates():
    label = load_label(ROOT / "labels/b00_fix_failing_test.json")
    assert label.malicious is False


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        Event(session_id="s", seq=1, ts="t", project="p",
              event_type="user_prompt", turn_id="p1", bogus_field=1)


def test_bad_event_type_is_rejected():
    with pytest.raises(ValidationError):
        Event(session_id="s", seq=1, ts="t", project="p",
              event_type="made_up", turn_id="p1")
