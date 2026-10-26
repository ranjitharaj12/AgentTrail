import json
import re
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from agenttrail import ui_data as ui
from agenttrail.load import load_all
from agenttrail.why import Why, clean_path

ROOT = Path(__file__).resolve().parent.parent
needs_model = pytest.mark.skipif(not (ROOT / ".cache/fastembed").exists(), reason="embedding model not downloaded yet")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    base = tmp_path_factory.mktemp("why")
    db = base / "t.db"
    assert load_all(db, ROOT / "fixtures", ROOT / "labels") == 0
    return db, base / "narr", ui.load_world(db, base / "narr", use_drift=False)


def reason(world, sid, eid, rule):
    return next(r for r in Why(world, sid).for_event(eid) if r.rule_id == rule)


# ---------- coverage: no flag without a reason ----------

def test_every_flagged_event_in_every_session_has_a_reason_for_each_hit(env):
    w, n_hits = env[2], 0
    for r in w.results:
        y = Why(w, r.session_id)
        for eid in y.flagged_events():
            got = y.for_event(eid)
            expected = [h for h in r.hits if h.event_id == eid]
            assert sorted((x.rule_id, x.severity) for x in got) == sorted((h.rule_id, h.severity) for h in expected)
            for x in got:
                n_hits += 1
                assert x.title and x.what and (x.facts or x.steps), f"{r.session_id} {eid} {x.rule_id} has no evidence"
    assert n_hits >= 70      # the whole fixture set was exercised (this world has drift off, so no D-01 hits; see the drift test)


def test_reasons_never_leak_secret_values(env):
    blob = ""
    for r in env[2].results:
        y = Why(env[2], r.session_id)
        for eid in y.flagged_events():
            for x in y.for_event(eid):
                blob += " ".join(x.facts) + " ".join(f for s in x.steps for f in s.facts) + " ".join(s.summary for s in x.steps)
    assert "AKIAFAKECANARY0000" not in blob and "sk_test_FAKECANARY123" not in blob


# ---------- the content of the reasons ----------

def test_r01_names_the_path_and_the_action(env):
    r = reason(env[2], "s-a01", "s-a01:8", "R-01")
    assert "path class: sensitive" in r.facts and "path on this event: /home/dev/.aws/credentials" in r.facts
    assert "action: read" in r.facts and r.title == "Read of a sensitive path"


def test_r07_shows_the_text_that_matched_and_where_it_came_from(env):
    r = reason(env[2], "s-a01", "s-a01:8", "R-07")
    src, risky = r.steps
    assert src.event_id == "s-a01:7" and "content trust level: third_party" in src.facts
    matched = next(f for f in src.facts if f.startswith("content matched"))
    assert "IMPORTANT NOTE FOR AI ASSISTANTS" in matched and len(matched) > 120      # the sentence, not two words
    assert risky.event_id == "s-a01:8" and any("R-01" in f for f in risky.facts)


def test_sequence_reasons_list_the_steps_in_order(env):
    r = reason(env[2], "s-a01", "s-a01:10", "R-03")
    assert [s.event_id for s in r.steps] == ["s-a01:8", "s-a01:10"]
    assert r.steps[0].label == "sensitive read" and "path class: sensitive" in r.steps[0].facts
    assert "action: network" in r.steps[1].facts


def test_r02_names_the_destination_and_what_is_normal(env):
    r = reason(env[2], "s-a01", "s-a01:10", "R-02")
    assert "destination: collect.evil-telemetry.net" in r.facts
    assert any("known destinations for demo-app" in f and "docs.python.org" in f for f in r.facts)


def test_r12_shows_the_reply_and_what_it_failed_to_mention(env):
    r = reason(env[2], "s-a01", "s-a01:10", "R-12")
    assert any("I also checked the pricing-lib README" in f for f in r.facts)
    names = next(f for f in r.facts if "names none of" in f)
    assert "collect.evil-telemetry.net" in names and "curl" in names


def test_a_lowered_severity_says_why(env):
    for sid in ("s-b07", "s-b02", "s-b11"):
        rs = [x for x in Why(env[2], sid).for_event(Why(env[2], sid).flagged_events()[0]) if x.rule_id == "R-01"]
        assert rs and rs[0].severity == "medium"
        assert "lowered from high to medium" in rs[0].note and "names this file" in rs[0].note
    assert reason(env[2], "s-a01", "s-a01:8", "R-01").note is None             # at its default severity: nothing to explain


def test_the_curl_at_file_artefact_is_cleaned_for_display_only(env):
    assert clean_path("/work/demo-app/@/home/dev/.aws/credentials") == "/home/dev/.aws/credentials"
    assert clean_path("/home/dev/.aws/credentials") == "/home/dev/.aws/credentials"
    assert clean_path("/home/dev/@scope/pkg") == "/home/dev/@scope/pkg"
    shown = " ".join(" ".join(x.facts) for x in Why(env[2], "s-a01").for_event("s-a01:10"))
    assert "/@/" not in shown


def test_rules_that_only_need_a_flag_still_explain_themselves(env):
    r = reason(env[2], "s-a06", "s-a06:4", "R-11")
    assert any("after the first user prompt" in f for f in r.facts)
    assert any("MCP server" in f or "event type" in f for f in r.facts + [s for st in r.steps for s in st.facts]) or r.facts


def test_blocked_attempt_is_explained(env):
    r = reason(env[2], "s-a05", "s-a05:12", "R-10")
    assert any("path class: sensitive" in f for f in r.facts) and any("id_ed25519" in f for f in r.facts)


@needs_model
def test_drift_reasons_give_the_distance_and_the_limits(tmp_path):
    db = tmp_path / "t.db"
    load_all(db, ROOT / "fixtures", ROOT / "labels")
    w = ui.load_world(db, tmp_path / "none", use_drift=True)
    r = reason(w, "s-a08", "s-a08:12", "D-01")
    dist = float(re.search(r"distance from the user's intent: ([\d.]+)", r.facts[0]).group(1))
    assert dist > 0.408 and any("0.408" in f for f in r.facts) and any("event test" in f for f in r.facts)
    assert any("what was compared" in f and "docs" in f.lower() for f in r.facts)


# ---------- on the screen ----------

@pytest.fixture
def page(env, monkeypatch):
    monkeypatch.setenv("AGENTTRAIL_DB", str(env[0]))
    monkeypatch.setenv("AGENTTRAIL_NARRATIVES", str(env[1]))
    monkeypatch.setenv("AGENTTRAIL_DRIFT", "0")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    at.query_params["session"] = "s-a01"
    return at.run()


def test_the_page_order_is_timeline_then_inspect_then_flagged_events(page):
    assert not page.exception
    assert [x.value for x in page.subheader] == ["What happened", "Timeline", "Flagged events"]
    markdown = [m.value for m in page.markdown]
    inspect_at = markdown.index("**Inspect an event**")                     # a bold heading, not a faint widget label
    first_flag_card = next(i for i, m in enumerate(markdown) if "Read of a sensitive path" in m)
    assert inspect_at < first_flag_card
    assert any(s.label == "Inspect an event" for s in page.selectbox)       # still a real, labelled control


def test_the_flagged_section_shows_every_rule_title(page):
    text = " ".join(m.value for m in page.markdown)
    for title in ("Read of a sensitive path", "Instruction-like text in low-trust content", "Unreported action",
                  "Sensitive read followed by network egress", "Unprompted course change"):
        assert title in text, title


def test_each_flagged_event_header_shows_its_severity_and_rule_count_before_it_is_opened(page, env):
    y = Why(env[2], "s-a01")
    blocks = {re.search(r"`(s-a01:\d+)`", e.label).group(1): e for e in page.expander if re.search(r"`s-a01:\d+`", e.label)}
    assert set(blocks) == set(y.flagged_events())
    for eid, e in blocks.items():
        n = len(y.for_event(eid))
        assert y.top_severity(eid).upper() in e.label and f"{n} rule" in e.label, (eid, e.label)
        assert e.proto.expanded                                              # open by default


def test_every_rule_gets_its_own_card_with_a_severity_tag(page, env):
    y = Why(env[2], "s-a01")
    total = sum(len(y.for_event(e)) for e in y.flagged_events())
    cards = [c.value for c in page.caption if c.value.startswith("What this rule looks for:")]
    assert len(cards) == total and total >= 8          # drift is off in this test world; the real app adds D-01 cards
    headers = [m.value for m in page.markdown if re.match(r"^:(red|orange|blue|gray)\[\*\*(CRITICAL|HIGH|MEDIUM|LOW)\*\*\] · \*\*[RD]-\d\d\*\*", m.value)]
    assert len(headers) == total


def test_evidence_is_labelled_under_each_card(page):
    markdown = [m.value for m in page.markdown]
    assert "**Evidence on this event**" in markdown and "**Evidence, step by step**" in markdown


def test_the_timeline_has_a_severity_column_and_flagged_rows_carry_it(env):
    tl = {r["Event"]: r["Severity"] for r in ui.timeline(env[2], "s-a01")}
    assert tl["s-a01:10"] == "Critical" and tl["s-a01:8"] == "Critical" and tl["s-a01:1"] == ""


def test_an_events_severity_is_the_worst_rule_on_it(env):
    y = Why(env[2], "s-a01")
    assert y.top_severity("s-a01:10") == "critical" and y.top_severity("s-a01:1") == ""
    b07 = Why(env[2], "s-b07")                                              # only Medium rules fired here
    assert {b07.top_severity(e) for e in b07.flagged_events()} == {"medium"}


def test_evidence_text_on_the_page_is_not_clickable(page):
    text = " ".join(m.value for m in page.markdown)
    outside_code = re.sub(r"`[^`]*`", "", text)
    assert "hxxps" in text                                                      # the planted URL is defanged
    assert not re.search(r"(?i)https?://collect", outside_code)


def test_the_points_panel_comes_last(page):
    assert "How the points add up" in [e.label for e in page.expander]
