import json
import re
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from agenttrail import store, ui_data as ui
from agenttrail.explain import TemplateNarrator, build_evidence, explain_session
from agenttrail.load import load_all

from dataclasses import asdict

ROOT = Path(__file__).resolve().parent.parent
needs_model = pytest.mark.skipif(not (ROOT / ".cache/fastembed").exists(), reason="embedding model not downloaded yet")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("ui")
    db = base / "t.db"
    assert load_all(db, ROOT / "fixtures", ROOT / "labels") == 0
    narr = base / "narr"
    narr.mkdir()
    world = ui.load_world(db, narr, use_drift=False)
    conn = store.connect(db)
    for r in world.results:                                   # template narratives for every alert
        if r.status == "alert":
            ev = build_evidence(r, store.get_session_events(conn, r.session_id), world.ctx.cfg.home)
            (narr / f"{r.session_id}.json").write_text(json.dumps(asdict(explain_session(ev, TemplateNarrator()))))
    return db, narr, ui.load_world(db, narr, use_drift=False)


# ---------- the session list ----------

def test_rows_are_ranked_alerts_first_and_carry_what_the_analyst_needs(env):
    rows = ui.session_rows(env[2])
    assert rows[0]["Status"] == "ALERT" and rows[0]["Score"] == 100
    statuses = [r["Status"] for r in rows]
    assert statuses == sorted(statuses, key=["ALERT", "REVIEW", "clear"].index)
    first = rows[0]
    for col in ("Session", "Status", "Score", "Intent", "Duration", "Events", "Top alert"):
        assert first[col] not in (None, "")                                 # US-3: intent, duration, events, top alert


def test_filtering_by_status(env):
    only_alerts = ui.session_rows(env[2], {"alert"})
    assert only_alerts and {r["Status"] for r in only_alerts} == {"ALERT"}
    assert ui.session_rows(env[2], {"review"}) == [] or {r["Status"] for r in ui.session_rows(env[2], {"review"})} == {"REVIEW"}


def test_counts_add_up_and_the_explainer_session_is_not_an_attack(env):
    w = env[2]
    assert sum(ui.status_counts(w).values()) == len(w.results)
    assert next(r for r in ui.session_rows(w) if r["Session"] == "s-x01")["Set"] == "explainer"


def test_the_answer_key_column_is_labelled_as_eval_only(env):
    assert "Label (eval only)" in ui.session_rows(env[2])[0]


def test_narrative_column_says_who_wrote_it(env):
    row = next(r for r in ui.session_rows(env[2]) if r["Session"] == "s-a01")
    assert row["Narrative"] == "template"
    assert next(r for r in ui.session_rows(env[2]) if r["Session"] == "s-b00")["Narrative"] == ""


def test_duration_formatting(env):
    assert ui.fmt_duration(env[2].events["s-a01"]) == "1m05s"
    assert ui.fmt_duration(env[2].events["s-b00"]) == "30s"


# ---------- the timeline ----------

def test_timeline_is_in_order_and_marks_flagged_trigger_and_cited_events(env):
    tl = ui.timeline(env[2], "s-a01")
    assert [r["Seq"] for r in tl] == sorted(r["Seq"] for r in tl)
    by = {r["Event"]: r for r in tl}
    assert "flagged" in by["s-a01:8"]["Marks"] and "R-01" in by["s-a01:8"]["Rules"]
    assert "trigger" in by["s-a01:7"]["Marks"]                              # the vendored README result
    assert "cited" in by["s-a01:8"]["Marks"]
    assert "cited" in by["s-a01:1"]["Marks"]                                # the prompt: cited by the "asked" claim
    assert by["s-a01:3"]["Marks"] == ""                                     # a plain result nothing refers to


def test_every_marked_event_has_a_text_marker_so_colour_is_never_the_only_signal(env):
    for r in ui.timeline(env[2], "s-a01"):
        assert (r["Marks"] != "") == (r["Rules"] != "" or "cited" in r["Marks"] or "trigger" in r["Marks"])


def test_a_session_without_a_narrative_has_no_cited_marks(env):
    assert not any("cited" in r["Marks"] for r in ui.timeline(env[2], "s-a08"))
    assert ui.narrative_sections(env[2], "s-a08") == []


@needs_model
def test_drift_scores_appear_on_scored_events(tmp_path):
    db = tmp_path / "t.db"
    load_all(db, ROOT / "fixtures", ROOT / "labels")
    w = ui.load_world(db, tmp_path / "none", use_drift=True)
    scored = [r for r in ui.timeline(w, "s-a08") if r["Drift"] is not None]
    assert scored and all(0 <= r["Drift"] <= 1 for r in scored)
    assert any("flagged" in r["Marks"] and "D-01" in r["Rules"] for r in ui.timeline(w, "s-a08"))


def test_event_detail_redacts_secrets_and_drops_empty_fields(env):
    d = ui.event_detail(env[2], "s-a01", "s-a01:9")
    assert "AKIAFAKECANARY0000" not in json.dumps(d) and "[REDACTED]" in json.dumps(d)
    assert "tool" in d and "args" not in d                                  # a result has no args: empty fields are dropped


def test_hits_are_sorted_most_severe_first_and_the_breakdown_adds_up(env):
    h = ui.hits_table(env[2], "s-a01")
    order = {s: i for i, s in enumerate(ui.SEV_ORDER)}
    assert [order[x["Severity"]] for x in h] == sorted((order[x["Severity"]] for x in h), reverse=True)
    r = env[2].result("s-a01")
    assert sum(b["Points"] for b in ui.breakdown(env[2], "s-a01")) == r.risk.uncapped


# ---------- recorded text must never become clickable or structural ----------

@pytest.mark.parametrize("text", [
    "see https://evil.example.org/log and http://x.example/y",
    "![pixel](https://evil.example.org/p.png)",
    "[click here](https://evil.example.org)",
    "<a href='https://evil.example.org'>x</a> <img src=x onerror=alert(1)>",
    "# a heading\\n| a | table |\\n|---|---|",
    "www.evil.example.org and mail attacker@evil.example.org",
    "unbalanced ` tick with https://evil.example.org",
    ":red[coloured] :material/delete: $x^2$",
])
def test_markdown_escape_neutralises_links_images_html_and_headings(text):
    out = ui.md_escape(text)
    outside_code = re.sub(r"`[^`]*`", "", out)
    assert not re.search(r"(?i)\bhttps?://", outside_code) and not re.search(r"(?i)\bwww\.", outside_code)
    assert not re.search(r"(?<!\\)[\[\]<>]", outside_code)                  # no bare brackets or tags
    assert not re.search(r"(?<!\\)[#|$]", outside_code) and not re.search(r"(?<![\\\w]):\w", outside_code.replace("\\:", ""))


def test_a_command_in_backticks_stays_readable_as_a_code_span():
    out = ui.md_escape("The agent ran `curl -s https://evil.example.org/log` and it succeeded.")
    assert "`curl -s https://evil.example.org/log`" in out                  # code spans are never parsed for links


# ---------- the app itself, driven like a user ----------

@pytest.fixture
def app(env, monkeypatch):
    monkeypatch.setenv("AGENTTRAIL_DB", str(env[0]))
    monkeypatch.setenv("AGENTTRAIL_NARRATIVES", str(env[1]))
    monkeypatch.setenv("AGENTTRAIL_DRIFT", "0")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    return at.run()


def test_the_sessions_view_loads_without_errors_and_shows_the_counts(app):
    assert not app.exception
    assert [m.label for m in app.metric] == ["Alerts", "Needs review", "Clear"]
    assert int(app.metric[0].value) >= 9


def test_opening_a_session_shows_its_narrative_and_timeline(app):
    sb = next(s for s in app.selectbox if s.label == "Open a session")
    sb.select("s-a01")
    next(b for b in app.button if b.label == "Open").click()
    app.run()
    assert not app.exception
    assert app.header[0].value.startswith("s-a01") and "ALERT" in app.header[0].value
    assert any(m.label == "Risk score (0 to 100)" and int(m.value) == 100 for m in app.metric)
    text = " ".join(m.value for m in app.markdown)
    assert "What the agent did" in text and "s-a01:8" in text
    assert any(s.label == "Inspect an event" for s in app.selectbox)


def test_attacker_urls_in_a_narrative_are_not_clickable_on_the_screen(app):
    next(s for s in app.selectbox if s.label == "Open a session").select("s-a01")
    next(b for b in app.button if b.label == "Open").click()
    app.run()
    text = " ".join(m.value for m in app.markdown)
    assert "collect" in text                                               # the URL is still shown to the analyst
    outside_code = re.sub(r"`[^`]*`", "", text)
    assert not re.search(r"(?i)https?://collect", outside_code)


def test_the_back_button_returns_to_the_list(app):
    next(b for b in app.button if b.label == "Open").click()
    app.run()
    next(b for b in app.button if "All sessions" in b.label).click()
    app.run()
    assert app.header[0].value.startswith("Sessions")


def test_a_missing_database_gives_instructions_not_a_crash(env, monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTTRAIL_DB", str(tmp_path / "nope.db"))
    monkeypatch.setenv("AGENTTRAIL_DRIFT", "0")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not at.exception and at.error and "agenttrail.load" in at.code[0].value
