/**
 * Sentry — desktop half. Ships inside the agent package as `desktop/plugin.js`
 * (the app copies it to <hermes home>/desktop-plugins/sentry/ and loads it through the normal
 * disk door). Plain ESM, loaded uncompiled: UI is jsx() calls, not JSX syntax.
 * Only `@hermes/plugin-sdk`, `react` and `react/jsx-runtime` resolve here.
 *
 * Everything it shows comes from the Python half's own namespace
 * (`api.rest('/…')` → `/api/plugins/sentry/…`). The gateway pushes each decision over the plugin
 * event stream, so the console updates the moment a call is refused; the 5 s poll is the fallback
 * (a socket can always drop, and this has to keep working).
 */

import {
  Badge,
  Button,
  cn,
  haptic,
  host,
  PALETTE_AREA,
  PANES_AREA,
  queryClient,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  Tip,
  useQuery
} from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'sentry'

// Set in register(ctx). The components below only run after it, so this is populated by then.
let api = null

// The rule list comes from the backend, so a rule added to the policy shows up here without a
// front-end change — a hardcoded list silently hid the last two.
const ACTIONS = ['allow', 'monitor', 'escalate', 'block']

const ACTION_TONE = {
  block: 'text-(--ui-accent)',
  escalate: 'text-(--ui-text-secondary)',
  monitor: 'text-(--ui-text-tertiary)',
  allow: 'text-(--ui-text-quaternary)'
}

function refresh() {
  queryClient.invalidateQueries({ queryKey: [ID, 'state'] })
  queryClient.invalidateQueries({ queryKey: [ID, 'receipts'] })
}

function useSentryState() {
  const query = useQuery({
    queryKey: [ID, 'state'],
    queryFn: () => api.rest('/state'),
    refetchInterval: 5000
  })
  return query.data
}

function useReceipts() {
  const query = useQuery({
    queryKey: [ID, 'receipts'],
    queryFn: () => api.rest('/receipts?limit=40'),
    refetchInterval: 5000
  })
  return query.data
}

function Row({ label, children, mono }) {
  return jsxs('div', {
    className: 'flex items-baseline gap-2 text-[0.6875rem] leading-4',
    children: [
      jsx('span', { className: 'w-16 shrink-0 text-(--ui-text-quaternary)', children: label }),
      jsx('span', { className: cn('min-w-0 flex-1 truncate', mono && 'font-mono'), children })
    ]
  })
}

function SentryChip() {
  const state = useSentryState()
  const tainted = state?.tainted?.length ?? 0
  const mode = state?.mode ?? '…'
  return jsx(Tip, {
    label: tainted
      ? `Sentry: ${tainted} session(s) carrying untrusted content — ${state.tainted.map(s => s.labels).join(', ')}`
      : `Sentry: no untrusted content in play (mode: ${mode})`,
    children: jsx('button', {
      type: 'button',
      className: cn(
        'inline-flex h-full items-center gap-1.5 px-1.5 text-[0.6875rem] transition-colors',
        'hover:bg-(--chrome-action-hover)',
        tainted ? 'text-(--ui-accent)' : 'text-(--ui-text-tertiary)'
      ),
      onClick: () => {
        haptic('tap')
        host.navigate('/sentry')
      },
      children: [
        jsx('span', {
          className: cn(
            'inline-block size-1.5 rounded-full',
            tainted ? 'bg-(--ui-accent)' : 'bg-(--ui-text-quaternary)'
          )
        }),
        jsx('span', { children: tainted ? `sentry · tainted ${tainted}` : 'sentry' })
      ]
    })
  })
}

function SentryPane() {
  const state = useSentryState()
  const receipts = useReceipts()
  const items = receipts?.items ?? []
  const tainted = state?.tainted ?? []

  return jsxs('div', {
    className: 'flex h-full flex-col gap-3 p-3 text-xs',
    children: [
      jsxs('div', {
        className: 'flex items-center gap-2',
        children: [
          jsx('span', { className: 'font-medium', children: 'Sentry' }),
          jsx(Badge, { children: state?.mode ?? '…' }),
          jsx('span', { className: 'flex-1' }),
          jsx(Button, {
            onClick: () => {
              haptic('tap')
              api.rest('/taint/clear', { method: 'POST', body: {} }).then(() => {
                refresh()
                host.notify({ kind: 'info', message: 'Sentry: taint cleared' })
              })
            },
            children: 'Clear taint'
          })
        ]
      }),

      jsx('div', {
        className: 'text-(--ui-text-tertiary)',
        children: tainted.length
          ? `${tainted.length} session(s) carrying untrusted content`
          : 'No untrusted content in play.'
      }),
      ...tainted.map((session, index) =>
        jsxs(
          'div',
          {
            className: 'flex flex-col gap-1 rounded border border-(--ui-stroke-secondary) p-2',
            children: [
              jsx(Row, { label: 'session', mono: true, children: session.session_id }),
              jsx(Row, { label: 'tainted by', children: session.labels }),
              jsx(Row, { label: 'age', children: `${session.age_s}s` })
            ]
          },
          `session-${index}`
        )
      ),

      jsx('div', { className: 'h-px bg-(--ui-stroke-secondary)' }),
      jsx('div', { className: 'font-medium', children: 'Rules' }),
      ...Object.keys(state?.rules ?? {}).map(rule =>
        jsxs(
          'div',
          {
            className: 'flex items-center gap-1',
            children: [
              jsx('span', {
                className: 'min-w-0 flex-1 truncate font-mono text-[0.6875rem] text-(--ui-text-secondary)',
                children: rule
              }),
              ...ACTIONS.map(action =>
                jsx(
                  'button',
                  {
                    type: 'button',
                    className: cn(
                      'rounded px-1 py-0.5 text-[0.625rem] transition-colors hover:bg-(--chrome-action-hover)',
                      state?.rules?.[rule] === action
                        ? cn('font-medium', ACTION_TONE[action])
                        : 'text-(--ui-text-quaternary)'
                    ),
                    onClick: () => {
                      haptic('tap')
                      api.rest('/rules', { method: 'POST', body: { rule, action } }).then(() => {
                        refresh()
                        host.notify({ kind: 'info', message: `Sentry: ${rule} → ${action}` })
                      })
                    },
                    children: action
                  },
                  `${rule}-${action}`
                )
              )
            ]
          },
          rule
        )
      ),

      jsx('div', { className: 'h-px bg-(--ui-stroke-secondary)' }),
      jsxs('div', {
        className: 'flex items-center gap-2',
        children: [
          jsx('span', { className: 'font-medium', children: 'Decisions' }),
          jsx('span', { className: 'text-(--ui-text-quaternary)', children: `${items.length}` })
        ]
      }),
      jsx('div', {
        className: 'min-h-0 flex-1 overflow-auto',
        children: items.length
          ? items.map((row, index) =>
              jsxs(
                'div',
                {
                  className: 'flex items-baseline gap-2 border-b border-(--ui-stroke-secondary) py-1',
                  children: [
                    jsx('span', {
                      className: 'shrink-0 text-(--ui-text-quaternary)',
                      children: new Date((row.ts ?? 0) * 1000).toLocaleTimeString()
                    }),
                    jsx('span', {
                      className: cn('w-14 shrink-0 font-medium', ACTION_TONE[row.action]),
                      children: row.action
                    }),
                    jsx('span', {
                      className: 'w-28 shrink-0 truncate font-mono text-(--ui-text-tertiary)',
                      children: row.rule || row.kind
                    }),
                    jsx('span', {
                      className: 'min-w-0 flex-1 truncate text-(--ui-text-secondary)',
                      title: `${row.tool_name} · ${row.detail}`,
                      children: `${row.tool_name}${row.detail ? ` · ${row.detail}` : ''}`
                    })
                  ]
                },
                `row-${index}`
              )
            )
          : jsx('div', { className: 'py-2 text-(--ui-text-quaternary)', children: 'Nothing yet.' })
      })
    ]
  })
}

export default {
  id: ID, // must match the folder name
  name: 'Sentry',
  register(ctx) {
    api = ctx

    // The Python half broadcasts on every decision and every taint; one subscription each,
    // retired with the plugin. The components' poll is the fallback.
    ctx.onEvent('plugin.sentry.decision', refresh)
    ctx.onEvent('plugin.sentry.provenance', refresh)

    ctx.register({
      id: 'pane',
      area: PANES_AREA,
      title: 'sentry',
      data: { placement: 'right', width: '320px' },
      render: () => jsx(SentryPane, {})
    })

    ctx.register({
      id: 'chip',
      area: STATUSBAR_AREAS.right,
      order: 120,
      render: () => jsx(SentryChip, {})
    })

    ctx.registerMany([
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        data: { path: '/sentry', label: 'Sentry', codicon: 'shield' }
      },
      {
        id: 'route',
        area: ROUTES_AREA,
        data: { path: '/sentry' },
        render: () => jsx(SentryPane, {})
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'sentry.open',
          label: 'Sentry: open console',
          keywords: ['sentry', 'security', 'taint'],
          run: () => host.navigate('/sentry')
        }
      },
      {
        id: 'clear',
        area: PALETTE_AREA,
        data: {
          id: 'sentry.clear',
          label: 'Sentry: clear taint',
          keywords: ['sentry', 'taint', 'clear'],
          run: () =>
            api.rest('/taint/clear', { method: 'POST', body: {} }).then(() => {
              refresh()
              host.notify({ kind: 'info', message: 'Sentry: taint cleared' })
            })
        }
      },
      {
        id: 'explain',
        area: PALETTE_AREA,
        data: {
          id: 'sentry.explain',
          label: 'Sentry: explain the last block',
          keywords: ['sentry', 'explain', 'block'],
          run: () =>
            api.rest('/explain').then(data => {
              const last = data?.decision
              host.notify({
                kind: last ? 'warning' : 'info',
                message: last
                  ? `${last.rule} · ${last.tool_name} · ${last.detail || last.reason}`
                  : 'Sentry: nothing has been blocked in this session.'
              })
            })
        }
      }
    ])
  }
}
