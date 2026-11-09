# taint-sentry — status and roadmap

## Shipped

Provenance and taint tracking at the tool boundary: ten tunable rules, a receipts ledger, the
`hermes taint-sentry` CLI, and a Desktop half shipped inside the same package:

- status-bar chip — `taint-sentry: clean` / `taint-sentry: tainted · N`
- pane console — live receipt feed: rule, tool, what was refused, what tainted the session
- per-rule toggles in the UI
- ⌘K palette — "Taint Sentry: explain last block", "Taint Sentry: clear taint"
- backend `plugin_api.py` → `/api/plugins/taint-sentry`, reading the same live state the hooks use

Listed in the Hermes marketplace: https://hermes-agent.nousresearch.com/marketplace/taint-sentry

- tests 88/88 — `python tests/test_taint_sentry.py`, no runner needed
- `hermes plugins doctor . --ci` and `hermes plugins validate .` clean
- 62 adversarial cases through the real hook layer: 0 missed, 0 false positives
- a 69-call workflow sweep (138 clean/tainted evaluations): 0 gated in a clean session
- catalog entry merged: NousResearch/hermes-agent#149412

## Open

- [ ] demo video ≤ 90 s on X, tagging `@NousResearch`
- [ ] submit both links: https://form.typeform.com/to/FwJLvOln
- deadline: 5 PM EST, Nov 11

## Next, when there is time

- **Gate persistence through the tool surface.** A tainted session can still write a standing
  instruction with the `memory` tool, or create a cron job: `instruction_write` covers *files*, not
  those APIs.
- **Query-mode sessions are inert.** `hermes chat -q` does not deliver plugin hook callbacks in this
  build, so enforcement does not run there. That is a host-side gap, not a plugin one — interactive,
  TUI, Desktop and gateway sessions are enforced normally.

## Parked: entry #2 — session flight recorder

Record every tool call and result to a local DB, then give it a timeline, replay and undo: "what did
my agent do overnight", "put that file back the way it was". Hooks + `plugin_db` + a Desktop timeline.
Parked on purpose — this entry is at the finish line, and splitting the remaining days risks both.

## Notes for anyone extending the desktop half

`desktop/plugin.js` may import only `@hermes/plugin-sdk`, `react` and `react/jsx-runtime`; no `eval`,
no prototype patching, and it must not query the app's own markup (`data-slot` / `data-tour` /
`data-testid`) or restyle core UI — the catalog's `desktop surface` check enforces that. There is no
build step: the file loads uncompiled, so the UI is `jsx()` / `jsxs()` calls rather than JSX syntax.
