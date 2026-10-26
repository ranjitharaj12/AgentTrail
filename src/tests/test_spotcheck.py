import json
from dataclasses import asdict
from pathlib import Path

import pytest

from agenttrail import store
from agenttrail.explain import TemplateNarrator, build_evidence, explain_session
from agenttrail.load import load_all
from agenttrail.score import analyze_all, load_context
from agenttrail.spotcheck import build_sample, record, render

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    base = tmp_path_factory.mktemp("sc")
    db, narr = base / "t.db", base / "narr"
    narr.mkdir()
    load_all(db, ROOT / "fixtures", ROOT / "labels")
    ctx = load_context(db, use_drift=False)
    conn = store.connect(db)
    for r in analyze_all(ctx, db):
        if r.status != "alert":
            continue
        n = asdict(explain_session(build_evidence(r, store.get_session_events(conn, r.session_id), ctx.cfg.home), TemplateNarrator()))
        n["usage"]["input_tokens"] = 1000 if r.session_id != "s-a07" else 0          # pretend all but a07 came from Claude
        (narr / f"{r.session_id}.json").write_text(json.dumps(n))
    return db, narr


def test_sample_is_reproducible_random_and_attaches_the_cited_evidence(world):
    a, b = build_sample(*world, n=8), build_sample(*world, n=8)
    assert a == b and len(a) == 8
    assert all(s["cites"] and all(c["text"] for c in s["cites"]) for s in a)
    assert build_sample(*world, n=8, seed=7) != a


def test_only_claude_written_narratives_are_sampled(world):
    assert "s-a07" not in {s["session"] for s in build_sample(*world, n=200)}


def test_flagged_extras_are_added_and_marked_so_they_do_not_count(world):
    s = build_sample(*world, n=4, extra=[("s-a01", 0)])
    assert s[-1]["session"] == "s-a01" and s[-1]["random"] is False
    assert sum(not x["random"] for x in s) == 1


def test_rendering_shows_claim_and_evidence_together(world):
    text = render(build_sample(*world, n=2))
    assert "CLAIM:" in text and "EVIDENCE it cites:" in text and "1. " in text


def test_recording_counts_only_the_random_draw(world):
    sample = build_sample(*world, n=3, extra=[("s-a01", 0)])
    res = record("1Y 2P 3N 4N", sample)
    assert (res["sampled"], res["supported"], res["partly"], res["not_supported"]) == (3, 1, 1, 1)
    assert len(res["flagged_items_not_counted"]) == 1                      # item 4 was a flagged extra


def test_recording_accepts_loose_formatting_and_rejects_gaps(world):
    sample = build_sample(*world, n=3)
    assert record("1y, 2 p ; 3Y", sample)["supported"] == 2
    with pytest.raises(SystemExit, match="missing verdicts"):
        record("1Y 2Y", sample)


def test_the_reviewer_is_recorded_and_claude_results_go_to_a_separate_file(world):
    from agenttrail.spotcheck import RESULT_FILES
    sample = build_sample(*world, n=2)
    assert record("1Y 2Y", sample)["reviewer"] == "human" and record("1Y 2Y", sample, "claude")["reviewer"] == "claude"
    assert RESULT_FILES["human"] != RESULT_FILES["claude"]
