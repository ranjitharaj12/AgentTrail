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


def test_reloading_a_shorter_session_leaves_no_stale_events(tmp_path):
    from agenttrail.schema import Event
    def ev(seq, **kw):
        return Event(session_id="s-x", seq=seq, ts="2026-01-01T00:00:00Z", project="demo-app",
                     event_type="user_prompt", turn_id="p1", prompt_text="hi", **kw)
    conn = store.connect(tmp_path / "t.db")
    store.replace_session(conn, [ev(i) for i in range(1, 9)])
    store.replace_session(conn, [ev(i) for i in range(1, 4)])                 # the edited, shorter version
    assert [e.seq for e in store.get_session_events(conn, "s-x")] == [1, 2, 3]


def test_replacing_one_session_does_not_touch_another(tmp_path):
    from agenttrail.schema import Event
    mk = lambda sid, n: [Event(session_id=sid, seq=i, ts="2026-01-01T00:00:00Z", project="demo-app",
                               event_type="user_prompt", turn_id="p1", prompt_text="hi") for i in range(1, n + 1)]
    conn = store.connect(tmp_path / "t.db")
    store.replace_session(conn, mk("s-a", 3))
    store.replace_session(conn, mk("s-b", 5))
    store.replace_session(conn, mk("s-b", 2))
    assert len(store.get_session_events(conn, "s-a")) == 3 and len(store.get_session_events(conn, "s-b")) == 2
