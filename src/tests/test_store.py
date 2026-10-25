from pathlib import Path

from agenttrail import store
from agenttrail.fixtures import load_events
from agenttrail.load import load_all

ROOT = Path(__file__).resolve().parent.parent


def test_round_trip(tmp_path):
    events = load_events(ROOT / "fixtures/benign/b00_fix_failing_test.json")
    conn = store.connect(tmp_path / "t.db")
    store.save_events(conn, events)
    back = store.get_session_events(conn, "s-b00")
    assert back == events  # what goes in comes out identical


def test_reload_is_idempotent(tmp_path):
    db = tmp_path / "t.db"
    count = lambda: store.connect(db).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert load_all(db, ROOT / "fixtures", ROOT / "labels") == 0
    first = count()
    assert first > 0
    assert load_all(db, ROOT / "fixtures", ROOT / "labels") == 0
    assert count() == first   # second load adds no duplicates


def test_bad_fixture_is_reported_not_loaded(tmp_path):
    fx = tmp_path / "fixtures"
    fx.mkdir()
    (fx / "bad.json").write_text('[{"session_id": "x"}]')
    assert load_all(tmp_path / "t.db", fx, tmp_path) == 1
