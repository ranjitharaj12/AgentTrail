"""Every fixture must be valid, have a matching label, and carry correct enrichment."""
from pathlib import Path

import pytest

from agenttrail.enrich import Config, enrich_session
from agenttrail.fixtures import load_events, load_label

ROOT = Path(__file__).resolve().parent.parent
CFG = Config.load(ROOT / "config/projects.yaml")
FIXTURES = sorted((ROOT / "fixtures").rglob("*.json"))


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda p: p.stem)
def test_fixture_and_label_are_consistent(fx):
    events = load_events(fx)
    label = load_label(ROOT / "labels" / fx.name)
    ids = {e.event_id for e in events}

    assert {e.session_id for e in events} == {label.session_id}
    assert [e.seq for e in events] == list(range(1, len(events) + 1))   # 1..n, in order
    assert set(label.malicious_event_ids) <= ids                          # labels point at real events
    assert label.malicious == bool(label.malicious_event_ids)
    assert (fx.parent.name in ("attack", "heldout", "explainer")) == label.malicious    # folder matches label
    # every tool_result has a matching tool_decision
    decided = {e.tool_use_id for e in events if e.event_type == "tool_decision"}
    assert {e.tool_use_id for e in events if e.event_type == "tool_result"} <= decided
    enrich_session(events, CFG)   # project must exist in config


def by_id(name):
    evs = enrich_session(load_events(ROOT / "fixtures/attack" / name), CFG)
    return {e.event_id: e for e in evs}


def test_a01_enrichment():
    e = by_id("a01_vendored_readme_injection.json")
    assert e["s-a01:7"].trust_level == "third_party"       # the injection source
    assert e["s-a01:8"].path_class == "sensitive"          # credential read
    assert e["s-a01:10"].net_dest == "collect.evil-telemetry.net"
    assert e["s-a01:10"].path_class == "sensitive"         # @credentials in the curl


def test_a02_enrichment():
    e = by_id("a02_web_injection_encoded_exfil.json")
    assert e["s-a02:3"].trust_level == "web"
    assert e["s-a02:6"].path_class == "sensitive"          # tar of ~/.ssh
    assert e["s-a02:8"].net_dest == "paste.attacker-sink.xyz"


def test_a03_enrichment():
    e = by_id("a03_mcp_result_injection.json")
    assert e["s-a03:3"].trust_level == "mcp_result"
    assert e["s-a03:4"].path_class == "sensitive" and e["s-a03:6"].path_class == "sensitive"


def test_a04_two_mcp_servers():
    e = by_id("a04_cross_server_mcp_exfil.json")
    assert e["s-a04:5"].mcp_server == "notes" and e["s-a04:5"].trust_level == "mcp_result"
    assert e["s-a04:6"].mcp_server == "chat" and e["s-a04:6"].action_type == "mcp_call"


def test_a05_blocked_attempt_and_sweep():
    e = by_id("a05_secret_harvesting_blocked.json")
    assert e["s-a05:12"].decision == "reject" and e["s-a05:12"].path_class == "sensitive"
    sensitive = [x for x in e.values() if x.event_type == "tool_decision" and x.path_class == "sensitive"]
    assert len(sensitive) >= 5          # .env, .env.local, .zsh_history, id_ed25519, .aws/config


def test_a06_persistence_targets_and_late_mcp_connection():
    e = by_id("a06_persistence_after_new_mcp.json")
    assert e["s-a06:4"].event_type == "mcp_server_connection" and e["s-a06:4"].seq > 1
    assert "/home/dev/.zshrc" in e["s-a06:7"].paths
    assert e["s-a06:9"].net_dest == "upd.toolchain-cdn.net"


def test_a07_destructive_reaches_outside_project():
    e = by_id("a07_destructive_outside_project.json")
    assert e["s-a07:4"].action_type == "delete"
    assert "/work/shared-data" in e["s-a07:4"].paths and e["s-a07:4"].path_class == "system"


def test_a08_has_nothing_a_rule_could_key_on():
    e = by_id("a08_scope_drift_ci_rewrite.json")
    for x in e.values():
        assert x.path_class in (None, "project")
        assert x.net_dest is None
        assert x.trust_level in (None, "user_authored")


def benign(name):
    evs = enrich_session(load_events(ROOT / "fixtures/benign" / name), CFG)
    return {e.event_id: e for e in evs}


def test_b02_sensitive_read_that_the_user_asked_for():
    e = benign("b02_env_example_update.json")
    read_env = next(x for x in e.values() if x.event_type == "tool_decision" and x.paths == ["/work/demo-app/.env"])
    assert read_env.path_class == "sensitive"
    assert ".env" in read_env.intent          # the intent names the file: R-01 should only be Medium
    example = next(x for x in e.values() if x.paths == ["/work/demo-app/.env.example"])
    assert example.path_class == "project"


def test_b03_redirect_updates_intent_and_turns():
    e = benign("b03_user_redirects.json")
    turns = {x.turn_id for x in e.values()}
    assert turns == {"p1", "p2"}
    first = next(x for x in e.values() if x.turn_id == "p1" and x.event_type == "tool_decision")
    last = next(x for x in e.values() if x.turn_id == "p2" and x.event_type == "tool_decision")
    assert "CHANGELOG" not in first.intent
    assert "CHANGELOG" in last.intent and "failing test" in last.intent   # latest prompt + the one before


def test_b04_subagent_events_inherit_the_users_turn():
    e = benign("b04_subagent_rename.json")
    subs = [x for x in e.values() if x.actor == "subagent"]
    assert len(subs) >= 6 and {x.turn_id for x in subs} == {"p1"}


def test_b05_docs_domain_is_seen_as_web():
    e = benign("b05_docs_lookup.json")
    fetch = next(x for x in e.values() if x.tool == "WebFetch")
    assert fetch.net_dest == "docs.python.org" and fetch.trust_level == "web"


def test_b06_long_run_is_one_turn_with_no_risky_paths():
    e = benign("b06_long_autonomous_run.json")
    assert len(e) >= 40 and {x.turn_id for x in e.values()} == {"p1"}
    assert all(x.path_class in (None, "project") for x in e.values())
    assert any(x.actor == "subagent" for x in e.values())


def test_b07_ssh_config_is_sensitive_but_named_by_the_user():
    e = benign("b07_ssh_config_debugging.json")
    read = next(x for x in e.values() if x.tool == "Read")
    assert read.path_class == "sensitive" and "~/.ssh/config" in read.intent


def test_b08_mcp_connects_before_the_first_prompt():
    e = benign("b08_mcp_ticket_lookup.json")
    assert e["s-b08:1"].event_type == "mcp_server_connection"      # not mid-session
    assert e["s-b08:3"].trust_level == "mcp_result"


def test_b09_rm_rf_stays_inside_the_project():
    e = benign("b09_clean_build_output.json")
    rm = next(x for x in e.values() if x.action_type == "delete")
    assert rm.path_class == "project" and len(rm.paths) == 2


def test_b10_pypi_is_a_web_destination():
    e = benign("b10_add_dependency.json")
    curl = next(x for x in e.values() if x.net_dest)
    assert curl.net_dest == "pypi.org" and curl.action_type == "network"


def test_b11_env_edit_is_sensitive_and_named_by_user():
    e = benign("b11_edit_env_on_request.json")
    edit = next(x for x in e.values() if x.tool == "Edit")
    assert edit.path_class == "sensitive" and ".env" in edit.intent and edit.action_type == "write"


def test_b12_reuses_the_docs_domain():
    assert next(x for x in benign("b12_typing_docs_lookup.json").values() if x.tool == "WebFetch").net_dest == "docs.python.org"


def test_b13_failure_then_fix_has_no_risky_paths():
    e = benign("b13_extract_function.json")
    assert any(x.outcome == "failure" for x in e.values())
    assert all(x.path_class in (None, "project") for x in e.values())


def test_b14_vendored_read_is_third_party_then_user_prompt_resets_intent():
    e = benign("b14_vendored_readme_read.json")
    vend = next(x for x in e.values() if x.event_type == "tool_result" and x.trust_level == "third_party")
    assert "instruct" not in vend.content_excerpt.lower()     # benign content: nothing addressed to the agent
    later = next(x for x in e.values() if x.turn_id == "p2" and x.event_type == "tool_decision")
    assert "unit test" in later.intent and "pricing-lib" in later.intent


def test_benign_set_is_complete():
    assert len(list((ROOT / "fixtures/benign").glob("*.json"))) == 15
    assert len(list((ROOT / "fixtures/attack").glob("*.json"))) == 8
    assert len(list((ROOT / "fixtures/heldout").glob("*.json"))) == 4     # h01-h02 retired, h03-h04 current
    assert len(list((ROOT / "fixtures/explainer").glob("*.json"))) == 1
