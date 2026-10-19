import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { Icon } from '../components/Icon.jsx'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  PageHeader,
  Select,
  Skeleton,
  tdClass,
  thClass,
  tableClass,
} from '../components/ui.jsx'
import {
  formatDateTime,
  formatDurationMs,
  formatNumber,
  outcomeLabel,
  outcomeTone,
  shorten,
} from '../utils/format.js'

const RANGE_SECONDS = {
  '1h': 3600,
  '24h': 86400,
  '7d': 7 * 86400,
}

const OUTCOMES = [
  ['', '全部结果'],
  ['ok', '成功'],
  ['error', '失败'],
  ['blocked', '已阻断'],
  ['incomplete', '不完整'],
  ['idempotent_replay', '幂等重放'],
  ['provider_test', '连通性测试'],
  ['provider_config', '上游配置'],
  ['confirmation_pending', '待确认'],
  ['confirmation_released', '已释放'],
]

export default function Requests() {
  const [clientId, setClientId] = useState('')
  const [outcome, setOutcome] = useState('')
  const [range, setRange] = useState('24h')
  const [limit, setLimit] = useState(25)
  const [offset, setOffset] = useState(0)
  const [auto, setAuto] = useState(false)
  const [chain, setChain] = useState({ busy: false, result: null, error: null })

  const clients = useResource(() => api.clients.list(), [])
  const audit = useResource(
    () => {
      const since = RANGE_SECONDS[range]
        ? Date.now() / 1000 - RANGE_SECONDS[range]
        : undefined
      return api.audit.list({
        limit,
        offset,
        client_id: clientId || undefined,
        outcome: outcome || undefined,
        since,
      })
    },
    [clientId, outcome, range, limit, offset],
    { pollMs: auto ? 5000 : 0 },
  )

  const verifyChain = async () => {
    setChain({ busy: true, result: null, error: null })
    try {
      const result = await api.audit.verify(true)
      setChain({ busy: false, result, error: null })
    } catch (error) {
      setChain({ busy: false, result: null, error })
    }
  }

  const data = audit.data
  const items = data?.items || []
  const total = data?.total || 0
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))
  const chainView = data?.chain || {}
  const chainIntact = chain.result?.intact ?? chainView.intact

  const applyFilter = (setter) => (event) => {
    setter(event.target.value)
    setOffset(0)
  }

  return (
    <div>
      <PageHeader
        title="请求日志"
        description="审计记录只包含摘要、类别与决策，不含原始 Prompt、原始敏感值或可还原映射。"
        actions={(
          <>
            <label className="flex items-center gap-2 text-[12px] text-ink-soft">
              <input type="checkbox" className="h-4 w-4 accent-accent-500"
                checked={auto} onChange={(event) => setAuto(event.target.checked)} />
              自动刷新
            </label>
            <Button size="sm" icon="refresh" onClick={() => audit.reload()}>刷新</Button>
          </>
        )}
      />

      <div className="space-y-4 p-6">
        <Card bodyClass="p-3">
          <div className="flex flex-wrap items-end gap-3">
            <Field label="客户端" className="w-[220px]">
              <Select value={clientId} onChange={applyFilter(setClientId)}>
                <option value="">全部客户端</option>
                {(clients.data?.clients || []).map((client) => (
                  <option key={client.id} value={client.id}>{client.name}</option>
                ))}
              </Select>
            </Field>
            <Field label="结果" className="w-[180px]">
              <Select value={outcome} onChange={applyFilter(setOutcome)}>
                {OUTCOMES.map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </Select>
            </Field>
            <Field label="时间范围" className="w-[160px]">
              <Select value={range} onChange={applyFilter(setRange)}>
                <option value="1h">最近 1 小时</option>
                <option value="24h">最近 24 小时</option>
                <option value="7d">最近 7 天</option>
                <option value="all">全部</option>
              </Select>
            </Field>
            <Field label="每页" className="w-[120px]">
              <Select value={limit} onChange={(event) => { setLimit(Number(event.target.value)); setOffset(0) }}>
                {[25, 50, 100].map((value) => (
                  <option key={value} value={value}>{value} 条</option>
                ))}
              </Select>
            </Field>
            <div className="ml-auto flex items-center gap-2 pb-0.5">
              <Badge tone={chainIntact === false ? 'bad' : chainIntact ? 'ok' : 'neutral'} dot>
                审计链：{chainIntact === false ? '异常' : chainIntact ? '完整' : '未知'}
              </Badge>
              <Button size="sm" icon="check" busy={chain.busy} onClick={verifyChain}>
                校验链
              </Button>
            </div>
          </div>
          {chain.error ? (
            <p className="mt-2 text-[11.5px] text-bad">链校验失败：{chain.error.message}</p>
          ) : chain.result ? (
            <p className="mt-2 text-[11.5px] text-ink-faint">
              校验完成：{formatNumber(chain.result.records)} 条记录，
              {chain.result.failures?.length
                ? `发现 ${chain.result.failures.length} 处异常`
                : '未发现异常'}。
            </p>
          ) : null}
        </Card>

        {!data && audit.loading ? (
          <div className="space-y-2"><Skeleton className="h-12" /><Skeleton className="h-64" /></div>
        ) : !data && audit.error ? (
          <ErrorState error={audit.error} onRetry={() => audit.reload()} />
        ) : (
          <Card
            title={`${formatNumber(total)} 条记录`}
            description={`第 ${page} / ${pages} 页${auto ? ' · 每 5 秒自动刷新' : ''}`}
            bodyClass="p-0"
          >
            {audit.error ? (
              <div className="flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-2 text-[12px] text-warn">
                <Icon name="alert" size={14} />
                刷新失败，显示旧数据：{audit.error.message}
              </div>
            ) : null}
            {items.length ? (
              <div className="overflow-x-auto">
                <table className={tableClass}>
                  <thead>
                    <tr>
                      <th className={thClass}>seq</th>
                      <th className={thClass}>时间</th>
                      <th className={thClass}>request_id</th>
                      <th className={thClass}>客户端</th>
                      <th className={thClass}>入口</th>
                      <th className={thClass}>Provider / 模型</th>
                      <th className={thClass}>结果</th>
                      <th className={thClass}>延迟</th>
                      <th className={thClass}>检出</th>
                      <th className={thClass} />
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.request_id || item.seq} className="hover:bg-canvas/60">
                        <td className={`${tdClass} mono text-[11px] text-ink-faint`}>{item.seq ?? '—'}</td>
                        <td className={`${tdClass} whitespace-nowrap text-[11.5px] text-ink-soft`}>
                          {formatDateTime(item.ts_epoch)}
                        </td>
                        <td className={tdClass}>
                          <span className="mono text-[11.5px]" title={item.request_id}>
                            {shorten(item.request_id, 10, 4)}
                          </span>
                        </td>
                        <td className={tdClass}>{item.client_name || item.client_id || '—'}</td>
                        <td className={`${tdClass} mono text-[11px] text-ink-soft`}>{item.endpoint || '—'}</td>
                        <td className={tdClass}>
                          <div>{item.provider || '—'}</div>
                          <div className="mono text-[10.5px] text-ink-faint">{item.upstream_model || item.requested_model || ''}</div>
                        </td>
                        <td className={tdClass}>
                          <Badge tone={outcomeTone(item.outcome)}>{outcomeLabel(item.outcome)}</Badge>
                          {item.error_kind ? (
                            <div className="mt-1 text-[10.5px] text-bad">{item.error_kind}</div>
                          ) : null}
                        </td>
                        <td className={`${tdClass} tabular whitespace-nowrap`}>{formatDurationMs(item.latency_ms)}</td>
                        <td className={`${tdClass} tabular`}>{formatNumber(item.detections?.total || 0)}</td>
                        <td className={tdClass}>
                          <Link className="text-[12px] text-accent-700 hover:underline"
                            to={`/requests/${encodeURIComponent(item.request_id)}`}>
                            详情
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="没有匹配的请求"
                description="调整筛选条件，或让 Agent / SDK 通过网关发起请求。"
              />
            )}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3">
              <span className="text-[11px] text-ink-faint">
                {offset + 1}–{Math.min(offset + limit, total)} / {formatNumber(total)}
              </span>
              <div className="flex gap-2">
                <Button size="sm" disabled={offset <= 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}>上一页</Button>
                <Button size="sm" disabled={offset + limit >= total}
                  onClick={() => setOffset(offset + limit)}>下一页</Button>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
