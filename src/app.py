"""AgentTrail: a ranked session list and a per-session timeline (PRD FR-12). Two views, nothing else.

    .venv/bin/streamlit run app.py

All the content shown comes from agenttrail.ui_data. Recorded events are attacker-controlled text, so they
only ever reach the screen through tables and plain text, never as markdown or HTML.
"""
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from agenttrail import ui_data as ui
from agenttrail.score import ROOT

st.set_page_config(page_title="AgentTrail", page_icon="🔎", layout="wide")

DB = Path(os.environ.get("AGENTTRAIL_DB", ROOT / "agenttrail.db"))
NARRATIVES = Path(os.environ.get("AGENTTRAIL_NARRATIVES", ROOT / "reports" / "narratives"))

# Tints work on light and dark themes; every tint also has a text marker, so colour is never the only signal.
TINT = {"flagged": "rgba(220, 53, 69, 0.20)", "trigger": "rgba(255, 193, 7, 0.28)", "cited": "rgba(13, 110, 253, 0.18)",
        "ALERT": "rgba(220, 53, 69, 0.20)", "REVIEW": "rgba(255, 193, 7, 0.28)"}


def stamp(path: Path) -> float:
    if not path.exists():
        return 0.0
    if path.is_dir():
        return max((p.stat().st_mtime for p in path.glob("*.json")), default=0.0)
    return path.stat().st_mtime


USE_DRIFT = os.environ.get("AGENTTRAIL_DRIFT", "1") != "0"        # "0" skips the embedding model (used by tests)


@st.cache_resource(show_spinner="Scoring sessions…")
def get_world(db: str, db_stamp: float, narrative_stamp: float) -> ui.World:
    return ui.load_world(Path(db), NARRATIVES, use_drift=USE_DRIFT)


def open_session(sid: str) -> None:
    st.session_state.sid = sid
    st.session_state.view = "Session"


def style_rows(df: pd.DataFrame, column: str):
    def row_style(row):
        marks = str(row[column])
        key = next((k for k in ("flagged", "trigger", "cited", "ALERT", "REVIEW") if k in marks), None)
        return [f"background-color: {TINT[key]}" if key else ""] * len(row)
    return df.style.apply(row_style, axis=1)


# ---------- setup ----------

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

world = get_world(str(DB), stamp(DB), stamp(NARRATIVES))

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
    sections = ui.narrative_sections(world, sid)
    if sections:
        st.caption(f"Written by {ui.narrative_source(world, sid)}. Status, score and severity come from the rules, "
                   "not from the narrator, and every claim cites events from the timeline below.")
        for heading, claims in sections:
            st.markdown(f"**{heading}**")
            for c in claims:
                ids = " ".join(f"`{x}`" for x in c["cites"])
                st.markdown(f"- {ui.md_escape(c['text'])} {ids}")
    else:
        why = {"alert": "No narrative yet. Generate one:",
               "review": "Narratives are written for alerts only. This session is in the needs-review tier: it has a drift "
                         "flag but scored below the alert threshold. The timeline below shows where it drifted.",
               "clear": "Narratives are written for alerts only, and this session is clear."}[r.status]
        st.info(why)
        if r.status == "alert":
            st.code(f".venv/bin/python -m agenttrail.explain --session {sid} --narrator template", language="bash")

    with st.expander("Why it scored this way"):
        hits = ui.hits_table(world, sid)
        if hits:
            st.dataframe(pd.DataFrame(hits), hide_index=True, width="stretch")
            st.dataframe(pd.DataFrame(ui.breakdown(world, sid)), hide_index=True, width="stretch")
        else:
            st.write("No rule or drift hits. Nothing contributed to the score.")

    st.subheader("Timeline")
    only = st.toggle("Only flagged, trigger and cited events", value=False)
    tl = pd.DataFrame(ui.timeline(world, sid))
    if only:
        tl = tl[tl["Marks"] != ""]
    st.caption("flagged = a rule or drift flag fired · trigger = content the detector names as the likely cause · "
               "cited = used by the narrative. Drift is the distance from the user's intent; higher is further away.")
    st.dataframe(style_rows(tl, "Marks"), hide_index=True, width="stretch",
                 column_order=["Event", "Marks", "Rules", "Time", "Type", "Who", "What happened", "Drift"],
                 column_config={"What happened": st.column_config.TextColumn(width="large"),
                                "Drift": st.column_config.NumberColumn(format="%.3f")})

    ids = list(tl["Event"])
    if ids:
        pick = st.selectbox("Inspect an event", ids, index=0)
        st.json(ui.event_detail(world, sid, pick), expanded=True)
