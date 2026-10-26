# Demo plan

Two deliverables: a **3-minute walkthrough** (screen recording, with narration) and a **15 to 20 second GIF** for the top of the README. Both use the real app on the 28 synthetic sessions, so everything shown is reproducible.

The aim is to show the product working *and* to show where it falls short. A demo that hides the held-out miss would contradict the README.

## Before recording

```bash
cd src
.venv/bin/python -m agenttrail.load
.venv/bin/python -m agenttrail.explain --all --narrator template      # or --narrator claude, if you have a key
.venv/bin/python -m agenttrail.eval                                   # refreshes reports/eval.md
.venv/bin/streamlit run app.py
```

- Use the **Claude** narratives if you have them: the planted-text beat (shot 3) is stronger. The template narrator never reads content as instructions, so it cannot show that.
- Browser at about 1280 px wide, zoom 100%, light theme (the row tints read best), bookmarks bar hidden.
- Each session has a direct link, so you never have to click through menus:
  `http://localhost:8501/?session=s-a01`
- Close anything with real credentials or personal data. The sessions use fake canary secrets, but your screen may not be clean.

## The 3-minute walkthrough

| Time | On screen | What to say |
|---|---|---|
| 0:00 to 0:20 | **Sessions list.** Point at the counts (10 alerts, 2 needs review, 16 clear), then the red rows. | "Agents act with a developer's credentials and nobody reads their logs. AgentTrail ranks sessions by how far they strayed from what the user asked." |
| 0:20 to 1:10 | Open **`?session=s-a01`**. Read the narrative top to bottom, then scroll to the timeline. | "The user asked for a test fix. The agent read a vendored README, which told it to send the AWS credentials to a domain. Then it did, and its reply never mentioned it. Every sentence here cites events, and the timeline marks the flagged ones, the trigger, and what the story used." |
| 1:10 to 1:50 | Open **`?session=s-x01`**. Point at "Likely trigger". | "This README also tries to talk the *explainer* into calling the session benign. It is quoted as an observation, not followed. The severity and score come from the rules, so the model cannot change them. The URL is defanged so nobody clicks it." |
| 1:50 to 2:20 | Open **`?session=s-a08`** (needs review, score 5). Show the timeline with no rule hits and one drift flag. | "A docs task that quietly edits CI config. No rule fires. Only the intent-drift layer sees it, and it cannot reach an alert by design, so it goes to a review list for a person." |
| 2:20 to 2:40 | Open **`?session=s-b07`** (clear). | "A developer asked the agent to look at their own SSH config. It reads a sensitive file, but the user named it, so it is downgraded and stays below the threshold. False alarms matter as much as misses." |
| 2:40 to 3:00 | Open `src/reports/eval.md` (or the table in the README). Land on the **held-out row: 0 of 2**. | "Seven of eight scripted attacks alert, but the two attacks written *after* the rules were frozen were missed. That is the honest number, and it tells me which pattern lists to broaden." |

## The README GIF (15 to 20 seconds)

Silent, loops, no narration. Three beats:

1. The sessions list for 4 seconds (counts and red rows visible).
2. Click **Open** on s-x01 for the session page, hold on the narrative for 6 seconds.
3. Scroll to the timeline and hold for 5 seconds on the coloured, marked rows.

Save it as `docs/img/demo.gif` and put it directly under the title in the README, replacing or sitting above the static screenshot.

## Recording and shrinking it

These are suggestions I have not run for you:

- macOS screen recorders such as Kap or LICEcap can export a GIF directly. Record only the browser window.
- If you record a video first, `ffmpeg` can convert it:

```bash
ffmpeg -i demo.mov -vf "fps=10,scale=900:-1:flags=lanczos" -loop 0 docs/img/demo.gif
```

- Aim for under about 5 MB so the README loads quickly. Lower the fps or the width if it is larger.

## What not to claim

- Do not say it "detects prompt injection" in general. Say it caught the scripted ones and missed two held-out variants.
- Do not present the Claude review of the narratives as a human check. Say a person has not yet checked them, unless you have.
- Do not imply it ran on a live agent. Every session is synthetic.
