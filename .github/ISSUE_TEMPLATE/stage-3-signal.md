---
name: Stage 3 signal
about: Report a "share policy across team", "see audit from another machine", or "hand-rolled
  cross-process audit" signal that counts toward the Stage 3 gate
title: "[Stage 3 signal] "
labels: stage-3-signal
assignees: ''

---

## Signal type

<!-- Check the one that applies: -->

- [ ] **Team-sharing ask** — "How do I share this policy file across the team?" or "How do I enforce the same rules for every developer?"
- [ ] **Remote-audit ask** — "How do I see what the agent did last week from my laptop?" or "How do I query the audit log from a different machine?"
- [ ] **Hand-rolled audit** — My team has already implemented our own cross-process MCP audit/enforcement equivalent and we're looking to migrate.

## What you're trying to do

<!-- A clear description of the workflow you need. What does your team's setup look like? -->

## Current workaround (if any)

<!-- If you've worked around the limitation (e.g. copying policy files manually,
     exporting logs to a shared drive, a custom wrapper), describe it here. -->

## Team size and setup

<!-- Approximately how many people on your team use the agent/tool?
     No need for exact numbers — rough ranges are fine (e.g. "2–5 engineers"). -->

## Environment

- `@euno/mcp` version:
- Transport: stdio / HTTP
- Upstream MCP server (if known):
- Agent framework (LangChain.js, raw MCP client, Claude Desktop, Cursor, other):
- OS:
- Node.js version:

---

> **Why this template?** Unsolicited requests for cross-team policy sharing,
> remote audit access, or migration from hand-rolled enforcement are the three
> primary signals for deciding when Stage 3 development begins.
> Tagging issues with `stage-3-signal` lets us count them.
> See [docs/mvp.md](../../docs/mvp.md) §"Gate to Stage 3".
