import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { BarList, Sparkline, StatusBar } from '../components/charts.jsx'
import { Icon } from '../components/Icon.jsx'
import {
  Badge,
  Button,
  Card,
  CopyButton,
  EmptyState,
  ErrorState,
  Kpi,
  PageHeader,
  Skeleton,
  StatusDot,
} from '../components/ui.jsx'
import {
  formatDurationMs,
  formatNumber,
  formatPercent,
  formatTime,
  outcomeLabel,
  outcomeTone,
  shorten,
} from '../utils/format.js'

function sortedBars(record, limit = 6) {
  return Object.entries(record || {})
    .map(([label, value]) => ({ label, value: Number(value) || 0 }))
    .filter((item) => item.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, limit)
}

function providerTone(provider) {
  if (provider.configured) return 'ok'
  if (provider.has_key) return 'warn'
  return 'bad'
}

export default function Dashboard() {
  const dashboard = useResource(() => api.dashboard(), [], { pollMs: 2500 })
  const activity = useResource(() => api.audit.list({ limit: 8 }), [], { pollMs: 10000 })
  const [rateHistory, setRateHistory] = useState([])
  const [p95History, setP95History] = useState([])
  const [chain, setChain] = useState({ busy: false, result: null, error: null, at: null })
  const lastSample = useRef(0)

  const data = dashboard.data

  useEffect(() => {
    if (!data) return
    const at = Number(data.generated_at) || Date.now() / 1000
    if (at <= lastSample.current) return
    lastSample.current = at
    setRateHistory((prev) => {
      const total = Number(data.requests?.total) || 0
      const next = [...prev, { t: at, total }].filter((sample) => at - sample.t <= 180)
      return next.slice(-60)
    })
    setP95History((prev) => {
      const value = Number(data.durations?.p95_ms) || 0
      const next = [...prev, value]
      return next.slice(-60)
    })
  }, [data])

  const ratePerMinute = useMemo(() => {
    if (rateHistory.length < 2) return null
    const first = rateHistory[0]
    const last = rateHistory[rateHistory.length - 1]
    const seconds = last.t - first.t
    if (seconds <= 0) return null
    return ((last.total - first.total) / seconds) * 60
  }, [rateHistory])

  const verifyChain = useCallback(async () => {
    setChain((prev) => ({ ...prev, busy: true, error: null }))
    try {
      const result = await api.audit.verify(true)
      setChain({ busy: false, result, error: null, at: Date.now() })
    } catch (error) {
      setChain({ busy: false, result: null, error, at: Date.now() })
    }
  }, [])

  useEffect(() => {
    verifyChain()
  }, [verifyChain])

  if (!data && dashboard.loading) {
    return (
      <div>
        <PageHeader title="概览" description="中转站实时状态 · 本次网关进程启动以来的计数" />
        <div className="grid gap-3 p-6 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <Skeleton key={index} className="h-[92px]" />
          ))}
        </div>
      </div>
    )
  }

  if (!data && dashboard.error) {
    return (
      <div>
        <PageHeader title="概览" description="中转站实时状态" />
        <ErrorState error={dashboard.error} onRetry={() => dashboard.reload()} />
      </div>
    )
  }

  const requests = data.requests || {}
  const durations = data.durations || {}
  const detections = data.detections || {}
  const blocked = data.blocked || {}
  const restored = data.restored || {}
  const upstream = data.upstream || {}
  const confirmations = data.confirmations || {}
  const audit = data.audit || {}
  const providers = data.providers || []
  const configuredProviders = providers.filter((provider) => provider.configured).length
  const empty = (requests.total || 0) === 0

  return (
    <div>
      <PageHeader
        title="概览"
        description="业务请求（/v1/*）的实时状态。计数来自网关进程内存，口径为本次进程启动以来；控制台自身的轮询不计入；审计条数为落盘记录数。"
        actions={(
          <>
            <span className="text-[11px] text-ink-faint">
              {dashboard.lastUpdated ? `更新于 ${formatTime(dashboard.lastUpdated / 1000)}` : '等待数据'}
            </span>
            <Button size="sm" icon="refresh" onClick={() => dashboard.reload()}>刷新</Button>
          </>
        )}
      />

      <div className="space-y-4 p-6">
        {dashboard.error ? (
          <div className="flex items-center gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12px] text-warn">
            <Icon name="alert" size={14} />
            看板刷新失败，当前显示的是上一次成功数据：{dashboard.error.message}
            <button type="button" className="ml-auto underline" onClick={() => dashboard.reload()}>重试</button>
          </div>
        ) : null}

        {empty ? (
          <Card>
            <EmptyState
              icon="activity"
              title="还没有经过网关的请求"
              description="把 Agent / SDK 的 base_url 指向本网关，或在「链路测试」里用客户端密钥发一次请求。之后这里的计数、延迟和敏感检出会实时出现。"
              action={(
                <div className="flex gap-2">
                  <Link to="/playground"><Button variant="primary" icon="terminal">去链路测试</Button></Link>
                  <Link to="/clients"><Button icon="key">签发客户端密钥</Button></Link>
                </div>
              )}
            />
          </Card>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Kpi label="总请求" value={formatNumber(requests.total)} hint="本次进程启动以来 · /v1/*" icon="activity" />
          <Kpi label="请求速率" value={ratePerMinute == null ? '—' : `${ratePerMinute.toFixed(1)}/min`}
            hint="最近采样窗口" icon="clock" />
          <Kpi label="错误率" value={formatPercent(requests.error_rate || 0)}
            hint={`${formatNumber(requests.errors || 0)} 个 4xx/5xx`}
            tone={(requests.error_rate || 0) > 0.05 ? 'bad' : 'neutral'} icon="alert" />
          <Kpi label="P95 延迟" value={durations.count ? formatDurationMs(durations.p95_ms) : '—'}
            hint={durations.count ? `P50 ${formatDurationMs(durations.p50_ms)} · P99 ${formatDurationMs(durations.p99_ms)}` : '暂无样本'}
            icon="clock" />
          <Kpi label="敏感检出" value={formatNumber(detections.total)} hint="按实体类型计数" icon="shield" />
          <Kpi label="阻断" value={formatNumber(blocked.total)} tone={blocked.total ? 'bad' : 'neutral'}
            hint="高风险内容拒绝转发" icon="alert" />
          <Kpi label="待确认" value={formatNumber(confirmations.pending)}
            tone={confirmations.pending ? 'warn' : 'neutral'} hint="高风险数据释放申请" icon="check" />
          <Kpi label="可用 Provider" value={`${configuredProviders}/${providers.length}`}
            hint={`默认 ${data.defaults?.provider || '—'} / ${data.defaults?.model || '—'}`} icon="server" />
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="请求速率" description="按轮询样本差值计算，单位：请求/分钟" className="lg:col-span-2">
            <Sparkline points={rateHistory.map((sample, index) => {
              if (index === 0) return 0
              const previous = rateHistory[index - 1]
              const seconds = sample.t - previous.t
              return seconds > 0 ? ((sample.total - previous.total) / seconds) * 60 : 0
            })} />
            <div className="mt-2 flex items-center justify-between text-[11px] text-ink-faint">
              <span>{rateHistory.length >= 2 ? `采样 ${rateHistory.length} 次` : '正在采样…'}</span>
              <span>最近 3 分钟</span>
            </div>
          </Card>

          <Card title="P95 延迟趋势" description="最近 60 个采样点">
            <Sparkline points={p95History} stroke="#15803d" fill="rgba(21,128,61,0.10)" />
            <div className="mt-2 flex items-center justify-between text-[11px] text-ink-faint">
              <span>当前 {durations.count ? formatDurationMs(durations.p95_ms) : '—'}</span>
              <span>样本 {formatNumber(durations.count)}</span>
            </div>
          </Card>

          <Card title="响应状态" description="按 HTTP 状态码聚合">
            <StatusBar counts={requests.by_status || {}} />
          </Card>

          <Card title="敏感检出" description="按实体类型">
            <BarList items={sortedBars(detections.by_type)} />
          </Card>

          <Card title="出站还原" description="按实体类型（只统计白名单类别）">
            <BarList items={sortedBars(restored.by_type)} tone="ok" />
          </Card>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <Card
            title="上游健康"
            description="配置来源与密钥状态；密钥值永不显示"
            actions={<Link to="/upstreams"><Button size="sm">管理</Button></Link>}
            className="lg:col-span-2"
          >
            {providers.length ? (
              <div className="divide-y divide-line/70">
                {providers.map((provider) => (
                  <div key={provider.name} className="flex flex-wrap items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                    <StatusDot tone={providerTone(provider)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[12.5px] font-medium text-ink">{provider.display_name || provider.name}</span>
                        <Badge tone={provider.source === 'managed' ? 'accent' : 'neutral'}>
                          {provider.source === 'managed' ? '托管' : '环境变量'}
                        </Badge>
                        {provider.overrides_env ? <Badge tone="warn">覆盖环境变量</Badge> : null}
                      </div>
                      <div className="mono mt-0.5 truncate text-[11px] text-ink-faint">{provider.base_url || 'mock'}</div>
                    </div>
                    <div className="text-right text-[11px] text-ink-faint">
                      <div>{provider.models?.length || 0} 个模型</div>
                      <div>{provider.configured ? '可用' : provider.has_key ? '密钥已配置但缺 base_url' : '缺少密钥'}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="尚未配置 Provider" description="登录后在「上游配置」中创建第一个上游。"
                action={<Link to="/upstreams"><Button size="sm" icon="plus">新建 Provider</Button></Link>} />
            )}
          </Card>

          <Card
            title="审计链"
            description="链尾摘要；完整校验按需执行"
            actions={<Button size="sm" icon="check" busy={chain.busy} onClick={verifyChain}>校验</Button>}
          >
            <div className="space-y-1.5 text-[12px]">
              <div className="flex justify-between gap-3">
                <span className="text-ink-faint">记录数</span>
                <span className="tabular">{formatNumber(audit.records)}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-ink-faint">链尾 seq</span>
                <span className="mono">{audit.tip_seq ?? '—'}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-ink-faint">tip_hash</span>
                <span className="mono truncate text-[11px]" title={audit.tip_hash || ''}>
                  {audit.tip_hash ? shorten(audit.tip_hash, 10, 6) : '—'}
                </span>
                {audit.tip_hash ? <CopyButton value={audit.tip_hash} label="复制" /> : null}
              </div>
              <div className="flex items-center justify-between gap-3 border-t border-line/70 pt-2">
                <span className="text-ink-faint">上次校验</span>
                {chain.busy ? <Badge tone="neutral">校验中…</Badge>
                  : chain.error ? <Badge tone="bad">{chain.error.message}</Badge>
                    : chain.result ? (
                      <Badge tone={chain.result.intact ? 'ok' : 'bad'} dot>
                        {chain.result.intact ? '完整' : `${chain.result.failures?.length || 0} 处异常`}
                      </Badge>
                    ) : <Badge tone="neutral">未校验</Badge>}
              </div>
              {chain.at ? <p className="text-[10.5px] text-ink-faint">{formatTime(chain.at / 1000)}</p> : null}
            </div>
          </Card>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="上游调用结果" description="按 provider / outcome 聚合">
            <BarList items={sortedBars(upstream.by_provider)} />
            <div className="mt-3 border-t border-line/70 pt-3">
              <BarList items={sortedBars(upstream.by_outcome)} tone={
                (upstream.by_outcome?.error || 0) > 0 ? 'bad' : 'ok'
              } />
            </div>
          </Card>

          <Card
            title="最近请求"
            description="来自审计日志（不含明文）"
            actions={<Link to="/requests"><Button size="sm">全部</Button></Link>}
          >
            {activity.error && !activity.data ? (
              <ErrorState compact error={activity.error} onRetry={() => activity.reload()} />
            ) : activity.data?.items?.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="text-[10.5px] uppercase tracking-wide text-ink-faint">
                      <th className="pb-1.5 pr-2 font-medium">时间</th>
                      <th className="pb-1.5 pr-2 font-medium">客户端</th>
                      <th className="pb-1.5 pr-2 font-medium">结果</th>
                      <th className="pb-1.5 pr-2 text-right font-medium">延迟</th>
                      <th className="pb-1.5 text-right font-medium">详情</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line/70">
                    {activity.data.items.map((item) => (
                      <tr key={item.request_id || item.seq}>
                        <td className="py-2 pr-2 text-ink-soft">{formatTime(item.ts_epoch)}</td>
                        <td className="max-w-[120px] truncate py-2 pr-2 text-ink-soft">{item.client_name || item.client_id || '—'}</td>
                        <td className="py-2 pr-2">
                          <Badge tone={outcomeTone(item.outcome)}>{outcomeLabel(item.outcome)}</Badge>
                        </td>
                        <td className="tabular py-2 pr-2 text-right text-ink-soft">{formatDurationMs(item.latency_ms)}</td>
                        <td className="py-2 text-right">
                          <Link className="text-accent-700 hover:underline" to={`/requests/${item.request_id}`}>查看</Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="暂无请求记录" description="请求经过网关后会出现在这里。" />
            )}
          </Card>
        </div>

        <p className="text-[11px] text-ink-faint">
          计数口径：请求/延迟/检出/阻断为本次进程内存计数，重启清零；审计记录为封缄落盘，重启保留。
        </p>
      </div>
    </div>
  )
}
