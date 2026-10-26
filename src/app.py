"""AgentTrail: a ranked session list and a per-session timeline (PRD FR-12). Two views, nothing else.

    .venv/bin/streamlit run app.py

All the content shown comes from agenttrail.ui_data. Recorded events are attacker-controlled text, so they
only ever reach the screen through tables and plain text, never as markdown or HTML.
"""
import os
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from agenttrail import ui_data as ui
from agenttrail.explain import clip, summarize
from agenttrail.why import Why
from agenttrail.score import ROOT

st.set_page_config(page_title="AgentTrail", page_icon="🔎", layout="wide")

DB = Path(os.environ.get("AGENTTRAIL_DB", ROOT / "agenttrail.db"))
DEFAULT_NARRATIVES = ROOT / "reports" / "narratives"
NARRATIVES = Path(os.environ.get("AGENTTRAIL_NARRATIVES", DEFAULT_NARRATIVES))
# A custom narratives folder (the playground) is layered over the real ones, so the real sessions keep theirs.
BASE_NARRATIVES = DEFAULT_NARRATIVES if NARRATIVES.resolve() != DEFAULT_NARRATIVES.resolve() else None

# Tints work on light and dark themes; every tint also has a text marker, so colour is never the only signal.
TINT = {"flagged": "rgba(220, 53, 69, 0.20)", "trigger": "rgba(255, 193, 7, 0.28)",       # "cited" rows are left untinted
        "ALERT": "rgba(220, 53, 69, 0.20)", "REVIEW": "rgba(255, 193, 7, 0.28)"}
# A flagged row is tinted red, and the deeper the red the more severe the worst rule that fired on it.
SEV_TINT = {"critical": "rgba(220, 53, 69, 0.36)", "high": "rgba(220, 53, 69, 0.24)",
            "medium": "rgba(220, 53, 69, 0.13)", "low": "rgba(220, 53, 69, 0.07)"}
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "gray"}


def sev_tag(severity: str) -> str:
    """A coloured severity word. The word itself carries the meaning; the colour only helps scanning."""
    return f":{SEV_COLOR[severity]}[**{severity.upper()}**]"


# One look per narrative section: a Material icon, a colour, a short label, and the full heading shown on its card.
SECTION_STYLE = {
    "asked": ("person", "blue", "Asked", "What the user asked"),
    "did": ("terminal", "gray", "Did", "What the agent did"),
    "reported": ("campaign", "violet", "Reported", "What the agent reported"),
    "deviation": ("call_split", "red", "Deviated", "Where it deviated"),
    "trigger": ("bolt", "orange", "Trigger", "Likely trigger"),
    "action": ("task_alt", "green", "Do next", "Recommended action"),
}
# A citation badge says what the cited event is: flagged (by severity), the trigger, or an ordinary event.
KIND_COLOR = {"critical": "red", "high": "orange", "medium": "blue", "low": "green", "trigger": "violet", "plain": "gray"}


def badges(ids: list[str], kinds: dict[str, str]) -> str:
    return " ".join(f":{KIND_COLOR.get(kinds.get(i, 'plain'), 'gray')}-badge[{i}]" for i in ids)


def show_banner(h: dict) -> None:
    """The verdict in one box. Every fact in it comes from the detector, none from the narrator."""
    if h["status"] == "alert":
        box, icon, label = st.error, ":material/error:", "ALERT"
    elif h["status"] == "review":
        box, icon, label = st.warning, ":material/visibility:", "NEEDS REVIEW"
    elif h["flagged_events"]:
        box, icon, label = st.info, ":material/info:", "CLEAR"
    else:
        box, icon, label = st.success, ":material/check_circle:", "CLEAR"
    head = f"**{label}**" + (f" · highest severity **{h['severity'].upper()}**" if h["severity"] else "")
    lines = [head + f" · score {h['score']}/100 (alert at {h['threshold']})"]
    if h["top"]:
        n, rules = h["flagged_events"], h["rules"]
        lines.append(f"{n} flagged event{'s' if n != 1 else ''} · {len(rules)} rule{'s' if len(rules) != 1 else ''} fired "
                     f"({', '.join(rules)}) · most serious: **{h['top']['rule_id']}** {ui.md_escape(h['top']['title'])} "
                     f"at `{h['top']['event_id']}`")
    else:
        lines.append("No rule or drift flag fired on this session.")
    if h["trigger"]:
        lines.append(f"Likely trigger: `{h['trigger']['event_id']}`, {h['trigger']['phrase']} the agent read just before.")
    box("  \n".join(lines), icon=icon)


def show_narrative_cards(sections: dict, kinds: dict) -> None:
    for key, claims in sections.items():
        icon, color, _, heading = SECTION_STYLE[key]
        with st.container(border=True):
            st.markdown(f":{color}[:material/{icon}:] **{heading}**")
            for c in claims:
                st.markdown(f"- {ui.md_escape(c['text'])}  \n  {badges(c['cites'], kinds)}")


def stamp(path: Path | None) -> float:
    if path is None or not path.exists():
        return 0.0
    if path.is_dir():
        return max((p.stat().st_mtime for p in path.glob("*.json")), default=0.0)
    return path.stat().st_mtime


USE_DRIFT = os.environ.get("AGENTTRAIL_DRIFT", "1") != "0"        # "0" skips the embedding model (used by tests)


@st.cache_resource(show_spinner="Scoring sessions…")
def get_world(db: str, db_stamp: float, narrative_stamp: float) -> ui.World:
    return ui.load_world(Path(db), NARRATIVES, use_drift=USE_DRIFT, base_narratives=BASE_NARRATIVES)


@st.cache_resource
def started_at() -> float:
    return time.time()                                             # first run after the server starts


def open_session(sid: str) -> None:
    st.session_state.sid = sid
    st.session_state.view = "Session"


def style_rows(df: pd.DataFrame, column: str, severity_column: str | None = None):
    def row_style(row):
        marks = str(row[column])
        key = next((k for k in ("flagged", "trigger", "cited", "ALERT", "REVIEW") if k in marks), None)
        color = TINT.get(key)
        if key == "flagged" and severity_column:
            color = SEV_TINT.get(str(row[severity_column]).lower(), color)
        return [f"background-color: {color}" if color else ""] * len(row)
    return df.style.apply(row_style, axis=1)


# ---------- setup ----------

changed = ui.stale_modules(started_at())
if changed:
    st.error(f"This server is running older code than the files on disk ({', '.join(changed)} changed after it started). "
             "Stop it and start it again, then reload this page.")
    st.code(".venv/bin/streamlit run app.py", language="bash")
    st.stop()

st.session_state.setdefault("view", "Sessions")
st.session_state.setdefault("sid", None)
if "from_url" not in st.session_state:                         # a link like ?session=s-x01 opens that session directly
    st.session_state.from_url = True
    if st.query_params.get("session"):
        st.session_state.sid = st.query_params["session"]
        st.session_state.view = "Session"

with st.sidebar:
    st.title("AgentTrail")
    st.caption("Behavior analytics for AI coding agents")
    st.radio("View", ["Sessions", "Session"], key="view")
    if st.button("Reload data"):
        st.cache_resource.clear()
        st.rerun()
    st.caption("Prototype on synthetic sessions. No real data, no live agent.")

if not DB.exists():
    st.error(f"No event store at {DB}. Load the fixtures first:")
    st.code(".venv/bin/python -m agenttrail.load", language="bash")
    st.stop()

world = get_world(str(DB), stamp(DB), max(stamp(NARRATIVES), stamp(BASE_NARRATIVES)))

# ---------- view 1: ranked sessions ----------

if st.session_state.view == "Sessions":
    st.header("Sessions, riskiest first")
    counts = ui.status_counts(world)
    a, b, c = st.columns(3)
    a.metric("Alerts", counts["alert"], help=f"Score of {world.ctx.scoring.threshold} or more")
    b.metric("Needs review", counts["review"], help="A drift flag, but below the alert threshold")
    c.metric("Clear", counts["clear"])

    shown = st.multiselect("Show", ["alert", "review", "clear"], default=["alert", "review", "clear"],
                           format_func=lambda s: ui.STATUS_LABEL[s])
    rows = ui.session_rows(world, set(shown))
    if not rows:
        st.info("No sessions match this filter.")
        st.stop()
    df = pd.DataFrame(rows)
    picked = st.dataframe(style_rows(df, "Status"), hide_index=True, width="stretch", on_select="rerun",
                          selection_mode="single-row", key="session_table")
    st.caption("Alerts first, then the needs-review list, each by score. The last two columns come from the answer "
               "key and exist only to help read this prototype; the detector never sees them.")

    chosen = df.iloc[picked.selection.rows[0]]["Session"] if picked.selection.rows else None
    options = list(df["Session"])
    left, right = st.columns([3, 1], vertical_alignment="bottom")
    target = left.selectbox("Open a session", options, index=options.index(chosen) if chosen in options else 0)
    right.button("Open", type="primary", on_click=open_session, args=(target,), width="stretch")

# ---------- view 2: one session ----------

else:
    sid = st.session_state.sid
    if not sid:
        st.info("Pick a session on the Sessions view first.")
        st.stop()
    if sid not in {x.session_id for x in world.results}:
        st.warning(f"There is no session called {sid!r}. Pick one from the Sessions view.")
        st.stop()
    r = world.result(sid)
    st.button("← All sessions", on_click=lambda: st.session_state.update(view="Sessions"))
    st.header(f"{sid}  ·  {ui.STATUS_LABEL[r.status]}")
    st.caption(f"Project {r.project} · set: {world.set_label(r)} · answer key says: {'malicious' if r.malicious else 'benign'} (not seen by the detector)")

    m = st.columns(4)
    m[0].metric("Risk score (0 to 100)", r.risk.score)
    m[1].metric("Alert threshold", r.risk.threshold)
    m[2].metric("Events", r.n_events)
    m[3].metric("Duration", ui.fmt_duration(world.events[sid]))

    with st.expander("Verbatim user prompts"):
        st.dataframe(pd.DataFrame(ui.prompts(world, sid)), hide_index=True, width="stretch")

    st.subheader("What happened")
    show_banner(ui.headline(world, sid))
    sections = ui.narrative_by_section(world, sid)
    if sections:
        kinds = ui.cite_kinds(world, sid)
        st.caption(f"Written by {ui.narrative_source(world, sid)}. The banner above is computed by the rules; the story below is "
                   "the narrator's, and every claim cites events from the timeline. Badge colours: red, orange, blue = a flagged "
                   "event (by severity) · violet = the trigger · grey = an ordinary event.")
        show_narrative_cards(sections, kinds)
    else:
        why_none = {"alert": "No narrative yet. Generate one:",
                    "review": "Narratives are written for alerts only. This session is in the needs-review tier: it has a drift "
                              "flag but scored below the alert threshold. The timeline below shows where it drifted.",
                    "clear": "Narratives are written for alerts only, and this session is clear."}[r.status]
        st.info(why_none)
        if r.status == "alert":
            st.code(f".venv/bin/python -m agenttrail.explain --session {sid} --narrator template", language="bash")

    why = Why(world, sid)

    # ---- 1. the timeline, then inspecting one event ----
    st.subheader("Timeline")
    only = st.toggle("Only flagged, trigger and cited events", value=False)
    tl = pd.DataFrame(ui.timeline(world, sid))
    if only:
        tl = tl[tl["Marks"] != ""]
    st.caption("flagged = a rule or drift flag fired · trigger = content the detector names as the likely cause · "
               "cited = used by the narrative · Severity = the most severe rule that fired on the event, and flagged rows "
               "are tinted deeper red the more severe it is · Drift is the distance from the user's intent (higher is further).")
    st.dataframe(style_rows(tl, "Marks", "Severity"), hide_index=True, width="stretch",
                 column_order=["Event", "Marks", "Severity", "Rules", "Time", "Type", "Who", "What happened", "Drift"],
                 column_config={"What happened": st.column_config.TextColumn(width="large"),
                                "Drift": st.column_config.NumberColumn(format="%.3f")})

    ids = list(tl["Event"])
    if ids:
        st.markdown("**Inspect an event**")
        pick = st.selectbox("Inspect an event", ids, index=0, label_visibility="collapsed")
        by = why.for_event(pick)
        if by:
            st.markdown("**Flagged by:** " + "; ".join(f"{x.rule_id} ({x.severity}) {ui.md_escape(x.title)}" for x in by)
                        + ". The reasons are listed under Flagged events, below.")
        st.json(ui.event_detail(world, sid, pick), expanded=True)

    # ---- 2. flagged events: one block per event, one card per rule ----
    st.subheader("Flagged events")
    flagged_ids = why.flagged_events()
    if not flagged_ids:
        st.write("No rule or drift flag fired on this session.")
    else:
        st.caption("Most severe first within each event. Open an event to see each rule that fired, what it looks for, "
                   "and the exact evidence that matched.")
    for eid in flagged_ids:
        reasons = why.for_event(eid)
        n = len(reasons)
        label = (f"{sev_tag(why.top_severity(eid))} · `{eid}` · {n} rule{'s' if n != 1 else ''} · "
                 f"{ui.md_escape(clip(summarize(why.by_id[eid]), 90))}")
        with st.expander(label, expanded=True):
            st.caption("Rules that fired here: " + " · ".join(f"{x.rule_id} ({x.severity})" for x in reasons))
            for rs in reasons:
                with st.container(border=True):
                    st.markdown(f"{sev_tag(rs.severity)} · **{rs.rule_id}** · **{ui.md_escape(rs.title)}**")
                    st.caption(f"What this rule looks for: {rs.what}")
                    if rs.steps:
                        st.markdown("**Evidence, step by step**")
                        for i, step in enumerate(rs.steps, 1):
                            head = f"**Step {i}: {ui.md_escape(step.label)}** · event `{step.event_id}`"
                            body = ui.md_escape(clip(step.summary, 160))
                            bullets = "\n".join(f"- {ui.md_escape(fact)}" for fact in step.facts)
                            st.markdown("\n\n".join(p for p in (head, body, bullets) if p))
                    if rs.facts:
                        st.markdown("**Evidence on this event**")
                        st.markdown("\n".join(f"- {ui.md_escape(fact)}" for fact in rs.facts))
                    if rs.note:
                        st.info(rs.note)

    with st.expander("How the points add up"):
        hits = ui.hits_table(world, sid)
        if hits:
            st.dataframe(pd.DataFrame(hits), hide_index=True, width="stretch")
            st.dataframe(pd.DataFrame(ui.breakdown(world, sid)), hide_index=True, width="stretch")
        else:
            st.write("No rule or drift hits. Nothing contributed to the score.")
