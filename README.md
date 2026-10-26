# AgentTrail

**Behavior analytics and cited incident narratives for AI coding agents.**

AgentTrail watches what a coding agent does, decides whether a session stayed within what the user asked, and explains the sessions that did not. It plays the role for agents that UEBA tools play for people and service accounts.

> **Status: a prototype on synthetic data.** It runs on 28 scripted sessions written in the shape of Claude Code's OpenTelemetry events. There is no live agent and no collector. The results below are honest about what that does and does not prove.

![The session list, riskiest first](docs/img/sessions.jpg)

## Why agents need their own monitoring

- They act with the developer's credentials, so their file reads and commands look like the developer in the logs.
- Their goals are open-ended, so fixed allow-lists either block useful work or miss misuse.
- Content they read (a README, a web page, a tool result) can carry instructions that redirect them. This is prompt injection.
- Their logs run to thousands of lines that nobody reads until something has already gone wrong.

## What it answers

1. **Is this out of character?** Compared with what is normal for the project and with known-bad patterns.
2. **Is this off-intent?** Compared with what the user currently wants, especially when the agent changes course with no new prompt after reading untrusted content.
3. **What happened?** A short narrative where every claim cites the events behind it.

## Results

Run `python -m agenttrail.eval` to reproduce. Layers are cumulative. "Alerted" means the session scored 50 or more **and** a flagged event is in the ground-truth set.

| Layer | Attacks alerted | Held-out alerted | Benign test alerts | Needs review |
|---|---|---|---|---|
| Rules only | 7 / 8 | 0 / 2 | 0 / 5 | 0 |
| + Per-project baseline | 7 / 8 | 0 / 2 | 0 / 5 | 0 |
| + Intent drift (local embeddings) | 7 / 8 | 0 / 2 (1 surfaced for review) | 0 / 5 | 1 attack, plus 1 held-out; 0 benign |
| + Session judge | *not built* | | | |

What the numbers mean, plainly:

- **7 of 8 scripted attacks alert, and no benign test session does.** But the same author wrote the attacks and the rules, so this is the weaker kind of evidence.
- **The held-out result is the honest one: 0 of 2.** Two variants written *after* the detection code was frozen were missed, so the rules did not generalise. One was surfaced for review by the drift layer and one was missed entirely. An earlier pair of held-out variants was also missed. I fixed the gaps they exposed (credential-store paths, more network and delete commands, concealment wording), retired those two as regression tests, froze again, and wrote the fresh pair above.
- **The baseline layer added no detections.** Every session it touched already scored 100.
- **Drift is useful but modest.** It lifts one attack from a borderline 50 to 95 and puts two attacks that never reach the alert threshold into a *needs review* list (one of them is invisible to every rule). It cannot raise an alert on its own, by design.
- **The narratives** (10 written by Claude Sonnet 5.5, an estimated $0.16 in total): 91 of 92 claims passed the automatic citation check on the first draft; the injection source was named in 3 of 3 scenarios; text planted to tell the explainer to call a session benign was quoted as an observation and not followed.
- **A person has not yet checked the narratives.** A review by Claude is recorded separately and clearly labelled as not a human check.

The full report, including per-attack scores and every target from the spec, is generated at `src/reports/eval.md`.

## How it works

```mermaid
flowchart LR
  A[Agent events<br/>OTel-shaped JSON] --> B[Validate and enrich]
  B --> C[(SQLite event store)]
  C --> D[Single-event rules]
  D --> E[Intent drift<br/>local embeddings]
  E --> F[Sequence rules]
  F --> G[Reply check]
  G --> H[Risk score 0 to 100]
  H --> I{Status}
  I -->|alert| J[Cited narrative]
  I -->|needs review| K[Review list]
  I -->|clear| L[No action]
```

- **Enrichment** adds meaning the raw event does not state: path class (project, home, system, sensitive), network destination, action type, a trust level for ingested content (your file, vendored code, web, MCP result), and the user's current intent.
- **Twelve YAML rules** (plus a drift flag) cover credential reads, persistence, destructive commands, encoding before egress, instruction-like text in untrusted content, cross-server MCP flows, blocked attempts, environment changes, and an agent reply that leaves out what it did. They are plain files; no code changes are needed to tune them.
- **The headline rule, R-08,** flags an *unprompted course change*: low-trust content comes in, then a rule hit or an off-intent action follows with no new user prompt in between. It names the content as the likely cause.
- **Intent drift** embeds each action's stated purpose, tool and path with a small local model (`bge-small`, no API key) and measures its distance from what the user asked.
- **The risk score** is a deterministic sum: Critical 40, High 25, Medium 10, Low 5 per rule hit, drift capped at 20, total capped at 100, alert at 50. Nothing can lower it.
- **The explainer** writes cited narratives with Claude. The model never sets severity or score. A narrative is accepted only if every claim cites real events, everything it names appears in them, and it contains no motive language or "this is benign" verdicts; otherwise it is regenerated, and after repeated failure a deterministic template is used.

## The interface

| | |
|---|---|
| ![A session page: narrative, with the planted text quoted and not followed](docs/img/session.jpg) | ![The timeline: flagged, trigger and cited events highlighted](docs/img/timeline.jpg) |

Two views: the ranked list, and one session with its narrative, score breakdown and a timeline. Recorded text is attacker-controlled, so it only ever reaches the screen as plain table cells; URLs in narratives are defanged (`hxxps://`) so they cannot be clicked.

## Quickstart

Developed and tested on macOS (Apple silicon). Linux should work but is untested. **Python 3.12 is required** for the drift layer: the embedding runtime has no build for 3.15 yet.

```bash
cd src
uv venv --python 3.12 .venv          # or: python3.12 -m venv .venv
uv pip install --python .venv/bin/python -r requirements.txt   # or: .venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/python -m agenttrail.load        # validate and enrich the 28 sessions into SQLite
.venv/bin/python -m pytest -q              # 339 tests
.venv/bin/python -m agenttrail.score       # ranked sessions (first run downloads a 64 MB embedding model)
.venv/bin/python -m agenttrail.eval        # the evaluation report
.venv/bin/streamlit run app.py             # the interface; open ?session=s-x01 to jump to one session
```

Write narratives without any key, using the deterministic template:

```bash
.venv/bin/python -m agenttrail.explain --all --narrator template
```

Or with Claude (needs a key in your own shell; the tool never prints or stores it, and stops at a $1 spend cap by default):

```bash
export ANTHROPIC_API_KEY="..."
.venv/bin/python -m agenttrail.explain --all --narrator claude --model claude-sonnet-5-5
```

## Using the interface

Start it with `.venv/bin/streamlit run app.py` (from `src`) and open <http://localhost:8501>.

- **Sessions view.** Riskiest first: alerts, then the needs-review list, then the rest. Each row shows what the user asked, how long it ran, how many events, and the top alert. Filter by status, click a row (or use the picker underneath) and press **Open**.
- **Session view.** The narrative, with every claim tagged by the events it cites; a *Why it scored this way* panel with each rule hit and its points; and the timeline. In the timeline, **flagged** rows fired a rule or a drift flag, the **trigger** row is the content the detector blames, and **cited** rows are the ones the narrative used. Tick *Only flagged, trigger and cited events* to cut a long session down, and use *Inspect an event* for the full redacted record.
- **Links.** `?session=s-x01` opens a session directly. Good ones to start with: `s-a01` (a README tells the agent to send credentials out), `s-x01` (the planted text also tries to talk the explainer out of the alert), `s-a08` (needs review, no rule fires) and `s-b07` (a sensitive file the user asked about, so it stays clear).
- **Reload data** in the sidebar picks up a changed database or new narratives.

To try your own session without touching the real evaluation, see [`src/playground/README.md`](src/playground/README.md).

## Honest limitations

- **Same author, same assumptions.** Fixtures, labels and rules were written by one person, so catching scripted attacks is weak evidence of catching real ones. The held-out misses show it.
- **Synthetic data.** The sessions follow Claude Code's event format but were not captured from a live agent.
- **Hand-written pattern lists are brittle.** Which paths count as secrets, which commands count as network or destructive: every list has gaps, and new attacks will find them.
- **Drift is a weak signal.** Benign work tops out at a distance of 0.40 and attacks at 0.45 to 0.49. One scope-drift case clears its threshold by 0.001. The score uses the agent's own *stated* purpose, which a misleading agent can shape.
- **Naming a file in the prompt softens the alert.** When the user's own prompt names a credentials file, the read and the "toxic flow" rule drop to Medium even if the file is then uploaded. The upload command itself stays High, so the example in the playground still alerts (80), but the rule is softer than it should be.
- **Shell parsing is heuristic.** Paths and commands are inferred from text, so wildcards and nested subshells can be misread, and a curl-style `@file` argument is turned into a wrong path (the sensitive-path check still catches it, but "the user named this file" cannot match it).
- **A few labels are judgement calls.** For example the "agent overreach" case (`find ~ -delete`) is a reasonable-people-could-differ label.
- **MITRE ATLAS technique IDs on the rules are provisional** and need checking against the current catalog.
- **Narratives are checked mechanically**, plus a Claude review. A human spot-check is still pending.

## Not built yet

The session-level LLM judge (designed; its score slot and evaluation column exist), live ingestion through an OpenTelemetry Collector, and detection of changed MCP tool descriptions (needs a proxy, since telemetry carries only tool calls).

## Layout

- `src/agenttrail/` the detector, scorer, explainer and data layer
- `src/rules/` the YAML rules; `src/config/` projects, scoring, drift and the data split
- `src/fixtures/` the 28 synthetic sessions and `src/labels/` their answer keys (all fake canary secrets, safe to publish)
- `src/tests/` the test suite; `src/app.py` the interface; `src/reports/` generated reports
- `docs/` screenshots and the [demo plan](docs/DEMO.md)

## A note on how the evaluation is kept honest

Held-out attack variants only mean something if they were written after the detection logic stopped changing. `python -m agenttrail.freeze` records a fingerprint of every file that decides a score, and the evaluation report says whether it still holds. Sessions used to fix a miss are retired into a separate column, because they are no longer evidence of generalisation.
