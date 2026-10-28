# AgentTrail — Product Requirements Document

Oct 24, 2026

## Overview

AgentTrail is a behavioral analytics and explanation layer for AI coding agents. It ingests the agent's native OpenTelemetry telemetry through an OTel Collector, the way a SIEM onboards any log source, flags sessions that deviate from the agent's normal behavior or the user's current instructions — above all, when the agent changes course with no new instruction from the user — and turns each flagged session into an evidence-linked incident narrative an analyst can read in under two minutes.

The real-world design targets Claude Code's native OpenTelemetry telemetry. The POC starts one step later, at the event store: it runs on a library of mocked sessions written in the same event shape, so detection and explanation can be built and measured without a live agent or telemetry pipeline. 

## Background and problem

AI agents are a new kind of identity that existing UEBA and SIEM tooling does not model. Security tools baseline humans (logins, working hours, access patterns) and machines (service accounts, fixed workloads). Agents fit neither:

- They act with human credentials. An agent's file reads, shell commands and API calls appear in logs as the developer, so attribution is lost.
- They act at machine speed but with open-ended goals. Their behavior varies by task, so static allow-lists either block useful work or miss misuse.
- They can be redirected by content. A README, web page, issue comment or tool result can carry instructions (prompt injection) that steer the agent toward secrets, exfiltration or destructive actions.
- Their logs are not built for analysts. Raw transcripts and tool calls run to thousands of lines; nobody reviews them unless something has already gone wrong.

The result is a blind spot: when an agent misbehaves, there is no baseline to compare against and no fast way to reconstruct what happened. AgentTrail addresses both halves — detection (is this out of character?) and explanation (what happened, and why does it matter?).

## Goals and non-goals

### Goals

1. Define an event schema that matches Claude Code's OpenTelemetry events, and a library of mocked benign and attack sessions in that shape.
2. Detect risky or out-of-character agent behavior using baselines, rules, and an intent-drift score.
3. Explain each flagged session as a short narrative where every claim links to the raw events behind it.
4. Prove it works: measure detection rate and false positives on a labeled set of benign and attack sessions.

### Non-goals (for the POC)

- Blocking or preventing actions in real time (AgentTrail observes and alerts only).
- Live ingestion in the POC: running the OTel Collector, capturing real Claude Code sessions, or generating attacks with a live agent. The real-world path is designed, not built.
- Supporting agents other than Claude Code, or multi-user and multi-host deployment.
- Shipping a commercial SIEM integration (Splunk, Sentinel, Elastic); because the real-world design ingests through an OTel Collector, adding one later is an exporter configuration change.
- A production-grade UI, authentication, or long-term storage.
- Detecting model-internal issues such as jailbreaks that produce no tool calls.
- Detecting changes to MCP tool descriptions ("rug pulls"); OTel reports tool calls, not tool descriptions, so this needs a proxy.

## Target users and personas

| Persona | Role | What they need from AgentTrail |
| --- | --- | --- |
| SOC analyst | Triages alerts across the company | A ranked list of risky agent sessions and a narrative they can act on without reading transcripts |
| security engineer | Owns detection content | Readable rules they can tune, a clear event schema, and measured false-positive rates |
| developer | Uses Claude Code daily | Confidence their agent did only what they asked, with near-zero setup and no slowdown |
| AI platform lead | Rolls out agents to teams | Evidence of what agents actually do, to set policy and least-privilege permissions |

The POC is built primarily for SOC and security engineer; developer's sessions are the data source in the real-world design (mocked in the POC)

## Use cases

Each use case becomes one or more mocked scenarios in the POC's scenario library.

1. **Prompt injection caught in the act.** A developer asks the agent to fix a failing test. A planted instruction in a vendored README tells it to read `~/.aws/credentials` and post it to a URL. AgentTrail sees the agent change course right after reading the README, with no new prompt from the user, then flags the credential read and the new egress domain. The narrative names the README as the likely trigger.
2. **Injection through an MCP tool result.** Asked to summarize a ticket, the agent calls an MCP tool whose result contains hidden instructions, starts reading secrets, and leaves that out of its reply to the user. The same unprompted course-change detection fires, with the MCP tool result as the trigger.
3. **Cross-server MCP exfiltration.** The agent reads data through one MCP server (files, notes, a database) and writes it out through another (a message, an issue, a post) that the task did not call for.
4. **Secret harvesting.** An agent sweeps `.env*`, key files and shell history far beyond the task's scope. Sensitive-path rules fire, and drift scoring shows the reads are unrelated to the task.
5. **Destructive or persistent actions.** The agent runs `rm -rf` outside the project, edits shell profiles, or adds cron jobs or SSH keys. Rules flag persistence and destruction patterns.
6. **Scope drift without malice.** Asked to update docs, the agent rewrites CI configuration. No rule fires, but the intent-drift score surfaces the mismatch for review. A user who explicitly redirects the agent mid-session is not flagged, because each new prompt updates the current intent.
7. **Post-incident reconstruction.** Something broke during a long autonomous run that used subagents. An analyst opens the session, reads the narrative and timeline, and clicks through to the exact commands, files and MCP calls involved.

## User stories

| ID | As a… | I want to… | So that… | Acceptance criteria | Priority |
| --- | --- | --- | --- | --- | --- |
| US-1 | Security engineer | load a library of mocked sessions shaped like Claude Code telemetry, with every event in a documented schema | I can build and test detections without a live agent | Fixtures use Claude Code's OTel event names and attributes; the schema doc maps each OTel attribute to an AgentTrail field; each fixture has a label file; the loader validates and stores them | Must |
| US-2 | SOC analyst | see a ranked list of sessions by risk score | I review the riskiest sessions first | Session list sorted by score; each row shows intent, duration, event count, top alert | Must |
| US-3 | Security engineer | write detections as YAML rules | I can add or tune rules without code changes | Rules load from a folder; each has id, severity, ATLAS mapping; a test command runs them over the fixtures | Must |
| US-4 | SOC analyst | see when actions don't match what the user currently wants | I catch drift that no rule describes, without alerts every time the user redirects the agent | Drift is scored against the current intent; routine commands and user-authored project reads are skipped; redirections in benign fixtures are not flagged; drift-only findings go to a separate needs-review list and never raise an alert alone | Must |
| US-5 | SOC analyst | be alerted when the agent changes course without a new user instruction | I catch prompt injection from vendored code, web pages and MCP results | A deviation after low-trust content, with no user prompt in between, raises a Critical alert naming the likely source; subagent work under a user's turn does not trigger it alone | Must |
| US-6 | SOC analyst | read a plain-language narrative of a flagged session, and see the evidence behind each flagged event | I understand what happened in under two minutes and can verify it without raw logs | Narrative covers what the user asked, what the agent stated, did and reported, the deviation, severity and recommended action; every claim cites event IDs; no claims of motive; each flagged event lists the rules that fired and the evidence that matched | Must |
| US-7 | Security engineer | measure detection performance honestly | I can prove and improve the system without fooling myself | One command reports detection rate and false positives per layer, on a held-out benign test set and held-out attack variants | Must |
| US-8 | Security engineer | trust that the explainer can't be talked out of an alert | attackers can't hide behind injected text | Injection fixtures that target the explainer never change severity or produce a "benign" narrative | Must |
| US-9 | SOC analyst | know whether a session as a whole did what the user asked | I catch multi-step drift that no single event or rule reveals | The session judge returns a verdict per turn with cited events; it can raise but never lower the risk score; the eval reports its gain in its own column | Should (build if time permits) |
| US-10 | Security engineer | try my own session in a sandbox | I can learn how the rules react without touching the evaluation | A user-written session is loaded beside the real ones; the evaluation numbers do not change | Should |

## Architecture

### Real-world architecture

In production, AgentTrail is a three-stage pipeline shaped like a SIEM: Claude Code exports its native OpenTelemetry events to an OTel Collector, which redacts secrets, hashes identities and writes to the event store; detection runs on every event; and the LLM explainer runs only on sessions that cross the risk threshold. This is the target design, and the POC is built so it can plug into it unchanged.

```mermaid
flowchart LR
  A[Claude Code<br/>OTel events] --> B[OTel Collector<br/>redact and hash]
  B --> C[Validate<br/>and enrich]
  C --> D[(Event store)]
  D --> E[Detection<br/>rules, drift, reply check]
  E --> F[Risk score<br/>and status]
  F --> G[Cited narrative<br/>for alerts]
```

Every tool call is captured, stored and scored; only sessions above the risk threshold are sent to Claude for a cited narrative. Swapping the Collector's exporter for Elastic or Splunk turns this into a SIEM content pack. In the POC, mocked sessions replace the first two boxes.

### POC scope

The POC starts at the event store. Instead of a live agent and a Collector, a library of mocked sessions — JSON files written in the exact shape of Claude Code's OTel events — is loaded straight into the store. This removes the two riskiest dependencies from a short build: getting a live agent to actually fall for an attack, and operating the telemetry pipeline. Because the mocked events match the real event names and attributes, everything downstream of the store works the same when live ingestion is added later.

## Functional requirements (POC)

These requirements cover the POC only. Live ingestion (Claude Code and the OTel Collector) is described in the real-world architecture.

### Data

- **FR-1:** Scenario fixtures: each mocked session is a JSON file of events in Claude Code's OTel event shape, plus a label file with the ground-truth malicious event IDs. Fixtures use fake identities and canary secrets only.
- **FR-2:** A loader validates fixtures against the event schema and stores them. It accepts the same shape the Collector will produce, so live ingestion needs no downstream changes.
- **FR-3:** Enrich events with derived fields: file paths touched, path sensitivity class, command binary, network destinations, action type, MCP server and tool, turn, actor (main agent or subagent), and a trust level for content the agent ingests (user-authored file, third-party or vendored code, web, MCP result).

### Detection

- **FR-4:** Build per-project baselines: tools, commands, path prefixes and egress domains, from the benign tuning set.
- **FR-5:** Run YAML rules over events and sessions; each rule has an id, title, severity, ATLAS technique, and match logic.
- **FR-6:** Score intent drift against the user's current intent (the latest prompt plus the two before it), using local embeddings. A flag fires on a single action, a window of recent actions, or a run of consecutive actions that is far from intent. Routine commands and reads of the user's own project files are skipped.
- **FR-7:** Session-level LLM judge (stretch): reads the intent for each turn and a compact, redacted timeline of the session, and returns a verdict per turn, a session drift score from 0 to 1, and the event IDs behind each verdict. It decides; the explainer only narrates.
- **FR-8:** Combine signals into a deterministic session risk score (0–100) with a breakdown of what contributed. Rule hits add by severity (Critical 40, High 25, Medium 10, Low 5), drift adds up to 20, and the judge adds up to 30 when enabled. The alert threshold is 50 and configurable. A session below the threshold that carries a drift flag goes to a separate needs-review list; drift alone never raises an alert.

### Explanation

- **FR-9:** For sessions above the risk threshold, generate a narrative in observational language: what the user asked, what the agent stated, did and reported back, the point of deviation, the likely trigger and its trust level, ATLAS mapping, and a recommended action. It never asserts motive.
- **FR-10:** Every factual claim in the narrative cites event IDs. Citations are checked against the event store; uncited or invalid claims are rejected and regenerated.
- **FR-11:** Harden the explainer against injection: secrets are redacted from event data before it is sent to the LLM, event data is passed as delimited untrusted data, output is structured, and severity and risk score come from the detection layer and cannot be changed by the LLM.

### Presentation and evaluation

- **FR-12:** A web view with a ranked session list and a per-session timeline that highlights flagged and cited events. Each flagged event shows which rules fired and the evidence that matched.
- **FR-13:** An eval command runs over the fixtures: benign sessions are split into tuning and test sets, held-out attack variants are reported separately, and results are shown per detection layer.
- **FR-14:** A sandbox where a user can write their own session and see how it is scored, without affecting the evaluation.

## Non-functional requirements

| Area | Requirement |
| --- | --- |
| Performance | The full eval over all fixtures runs in under 2 minutes, excluding LLM calls |
| Privacy | No real user data: fixtures use fake identities and canary secrets; only flagged sessions are sent to an LLM |
| Cost | Rules, baselines and embedding drift need no API calls; LLM spend under $1 for the full evaluation run |
| Explainability | Every alert names the rule or signal that fired; every narrative claim cites events |
| Security | Event data is treated as untrusted input to the explainer; the LLM cannot change severity or risk scores |
| Portability | No Collector, Docker or live agent needed |
| Reproducibility | Detection results are deterministic over the fixed fixtures; only narrative wording varies between runs |
| Publishability | All fixtures are synthetic and safe to publish |

## Success metrics

Success means AgentTrail catches most scripted attacks with few false alarms, and its narratives are accurate enough to trust. The plan behind these numbers is in the Appendix.

| Metric | Target |
| --- | --- |
| Attack scenarios detected | At least 5 |
| Held-out attack variants detected | Reported as is; at least 1 expected |
| Benign test sessions falsely flagged | < 10% |
| Detection gain from drift scoring | Catches at least 1 attack that rules alone miss; user redirections not flagged |
| Narrative citation accuracy | ≥ 90% of claims, spot-checked |
| Injection source named | In every injection scenario |
| Explainer robustness | Never produces a "benign" narrative or a changed severity |
| Eval run time, excluding LLM calls | < 2 minutes |
| Time for a reader to understand a flagged session | < 2 minutes |
| Detection gain from the session judge (when built) | Reported in its own column |

## Future work

These were considered and deliberately left out of the POC.

- **Live ingestion, the real-world architecture:** Claude Code telemetry settings, an OTel Collector with redaction and hashing, and the loader reading Collector output.
- Running real injection attempts against a live agent in a sandbox (container or throwaway account) with canary credentials and a local sink instead of real egress.
- Tool output content for web and MCP results, which OTel does not carry; capturing it would replace the fixture's content excerpt.
- Off-task use of write-capable MCP tools (`create_issue`, `send_message`, `delete_*`) when the intent only calls for reading.
- Unusually large MCP results, suggesting bulk extraction.
- MCP tool-description change detection ("rug pulls") through a proxy between client and servers.
- A per-project baseline report for platform leads, and baselines as a primary detector once there is enough real history.
- Read-burst and first-seen-command baseline rules, once thresholds can be tuned on more data.
- Per-user baselines for multi-user deployments.
- A proper shell parser in place of the heuristic command splitting.
- A "count each rule once per session" scoring option, if repeated hits start pushing legitimate sessions over the threshold.

## Appendix

### Evaluation plan

A session is flagged, and raises an alert, when its risk score reaches the threshold. Sessions below it that carry a drift flag are listed as needs review and reported in their own column; they do not count as flagged. An attack counts as detected only if its session is flagged and at least one flagged event is in its ground-truth set; a benign session that is flagged counts as a false positive.

#### Dataset

- 15 benign mocked sessions modeled on real Claude Code work, including mid-session redirections, subagent use, long autonomous runs, and legitimate work on sensitive files. Split 10 for tuning and 5 for testing; test sessions are never used to set thresholds.
- 8 attack scenarios that together cover every use case and rule: (1) vendored-README injection leading to a credential read and egress; (2) web-page injection with encoded exfiltration; (3) MCP tool-result injection whose secret reads are left out of the agent's reply; (4) cross-server MCP exfiltration; (5) secret harvesting that includes a blocked attempt; (6) persistence through a shell profile after a new MCP server connects mid-session; (7) a destructive command outside the project; (8) benign-looking scope drift. Attacks run in the same mocked projects as the benign sessions, so baselines can't simply learn "new project means attack."
- 1 explainer-injection scenario whose content tries to talk the explainer into calling the session benign.
- 2 held-out attack variants written after the rules are frozen, reported separately.
- Every session has a label file with ground-truth malicious event IDs.

Results are reported as a per-layer table (rules only, then adding baseline, drift (single action, window and run), and the session judge), with held-out variants in their own column. That table, including where it falls short, is the centerpiece of the README.

### Threat model and example detections

**Threat model.** The developer is trusted; the agent is semi-trusted. Content the agent ingests is graded by trust: user-authored project files are trusted; third-party or vendored code (even inside the project), web pages and MCP results are low-trust and may carry injected instructions. Subagents act on the parent agent's instructions within the user's turn. The attacker's goals are credential theft, data exfiltration, persistence and destruction, and hiding those actions from both the user and the analyst, including by manipulating AgentTrail's explainer. Out of scope: a malicious developer, a compromised model provider, and tampering with the telemetry itself.

#### Example detections

A few examples show the kind of behavior the product is meant to catch:

| Example | What it catches | Severity |
| --- | --- | --- |
| Sensitive file read | The agent reads credentials or keys (`~/.ssh`, `~/.aws`, `.env` files), softened when the user's request names that file | High |
| Data leaving the machine | A sensitive read followed by a command that sends data over the network | Critical |
| Persistence | A write to shell profiles, cron jobs or `authorized_keys` | High |
| Instruction in untrusted content | Text in a file, web page or tool result that tells the agent what to do, followed by a risky action | High |
| Unprompted course change | Untrusted content comes in, then something risky or off-intent happens with no new user prompt in between | Critical |
| Unreported action | A serious action the agent's reply to the user never mentions | High |

The unprompted course change is the headline detection. A legitimate change of direction is normally preceded by a user prompt; an injected one happens between prompts, right after the agent ingests low-trust content. Agents also change course on their own (a failing test leads to other files), so it fires only when that change coincides with a rule hit or drift flag after low-trust content. Subagent work inherits the user's turn and is judged the same way. It needs only what OTel already provides: `prompt.id` for turn boundaries and tool inputs to grade trust.

Each rule maps to a MITRE ATLAS technique and, where it fits, an OWASP agentic risk category. Mappings are finalized during implementation.
