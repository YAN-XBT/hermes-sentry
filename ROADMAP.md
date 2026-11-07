# Sentry — roadmap

## Now: make it visible

Sentry's engine is done (69 tests, `doctor` + `validate` clean, PR open). What it lacks is a
*visible* surface — everything it does today is a refusal in a log line. Add the Desktop half
(`desktop/plugin.js` in this folder = unified package, no build step, hot reload):

- status-bar chip — `sentry: clean` / `sentry: tainted · N`
- pane console — live receipt feed: rule, tool, what was refused, what tainted the session
- per-rule toggles in the UI (today only `hermes sentry policy` / config)
- ⌘K palette — "Sentry: explain last block", "Sentry: clear taint"
- settings page under Settings → Plugins
- backend `plugin_api.py` → `/api/plugins/sentry`, reading the existing `receipts.db`

Constraints: `desktop/plugin.js` may import only `@hermes/plugin-sdk`, `react`,
`react/jsx-runtime`; no `eval`; no prototype patching; never query the app's own markup
(`data-slot` / `data-tour` / `data-testid`) or restyle core UI (catalog rule 8 — the
`desktop surface` check enforces it). No JSX syntax: the file loads uncompiled, so UI is
`jsx()` / `jsxs()` calls.

Adding the Desktop surface changes the manifest's declared capabilities, so the catalog entry
needs a fresh pin and a disclosure line after it lands.

## Then: test to destruction

Find bugs before a judge does. Both directions, through the real hook layer:

- **Bypasses** — every wrapper that reaches the policy (`tool_call`, `execute_code`,
  `process_manage`, `delegate_task`), plus encoded/obfuscated payloads and multi-step splits.
- **False positives** — an ordinary working session on a tainted session: build, test, commit,
  push, install, browse, `gh`, `docker`, `ssh`. Every block here costs more than a miss.
- **Live** — the plugin policing its own repository is the harshest test there is.

## Parked: entry #2 (build after Sentry ships)

**Session flight recorder.** Record every tool call and result to a local DB, then give it a
timeline, replay and undo: "what did my agent do overnight", "put that file back the way it was".
Hooks + `plugin_db` + a Desktop timeline. Differentiator: nothing in the 977-plugin marketplace
does session-level replay with rollback. Parked on purpose — Sentry is at the finish line and
splitting the remaining days risks both entries.

## Submission checklist

- [x] public repo — https://github.com/YAN-XBT/hermes-sentry
- [x] catalog PR — NousResearch/hermes-agent#149412 (pin `671c3e5`)
- [x] Desktop console (pane, chip, ⌘K, backend, live feed) + fresh pin
- [ ] live pass after a gateway restart (API routes + pane in the app)
- [ ] demo video ≤ 90 s on X, tagging @NousResearch
- [ ] submit both links: https://form.typeform.com/to/FwJLvOln
- deadline: 5 PM EST, Nov 11
