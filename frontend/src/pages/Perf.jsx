import { useEffect, useState } from 'react'
import ReactECharts from 'echarts-for-react'
import { PageHeader, Card, Badge, HashLine } from '../components/ui'
import { api } from '../api'
import { useStore } from '../store'

export default function Perf() {
  const [perf, setPerf] = useState(null)
  const [stats, setStats] = useState(null)
  const { lastResult } = useStore()

  useEffect(() => {
    api.perf().then(setPerf)
    api.stats().then(setStats).catch(() => {})
  }, [])

  const targets = perf?.targets || []
  const actualPipeline = lastResult?.pipeline || []

  const AXIS = { axisLabel: { color: '#8b92a5', fontSize: 10 }, splitLine: { lineStyle: { color: '#eee9e0' } } }

  const barOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 130, right: 50, top: 16, bottom: 28 },
    xAxis: { type: 'value', name: 'ms', nameTextStyle: { color: '#8b92a5' }, ...AXIS },
    yAxis: {
      type: 'category',
      data: targets.map((t) => t.op),
      axisLabel: { color: '#4b5568', fontSize: 10 },
    },
    series: [
      {
        name: '性能预算（目标）',
        type: 'bar',
        data: targets.map((t) => t.target_ms),
        itemStyle: { color: '#4361ee', borderRadius: [0, 5, 5, 0] },
        barWidth: 12,
        label: { show: true, position: 'right', color: '#4361ee', fontSize: 9, formatter: '{c}ms' },
      },
    ],
  }

  const stepOption = {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 150, right: 55, top: 16, bottom: 28 },
    xAxis: { type: 'value', name: 'ms', nameTextStyle: { color: '#8b92a5' }, ...AXIS },
    yAxis: { type: 'category', data: actualPipeline.map((s) => s.step), axisLabel: { color: '#4b5568', fontSize: 10 } },
    series: [
      {
        type: 'bar',
        data: actualPipeline.map((s) => s.duration_ms),
        itemStyle: { color: '#7048e8', borderRadius: [0, 5, 5, 0] },
        barWidth: 12,
        label: { show: true, position: 'right', color: '#7048e8', fontSize: 9, formatter: '{c}ms' },
      },
    ],
  }

  return (
    <div>
      <PageHeader icon="📊" title="性能仪表盘" subtitle="各密码操作耗时 vs 性能预算 · 端到端延迟分解 · 主链路预算 < 500ms" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        {/* KPI 卡片 */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: '端到端延迟', value: lastResult ? lastResult.total_ms + ' ms' : '—', icon: '⚡', tone: 'vault' },
            { label: '累计安全查询', value: stats ? stats.queries : '—', icon: '🔍', tone: 'violet' },
            { label: '敏感实体保护', value: stats ? stats.entities_protected : '—', icon: '🛡️', tone: 'ok' },
            { label: '平均延迟', value: stats ? stats.avg_latency_ms + ' ms' : '—', icon: '📉', tone: 'warn' },
          ].map((s) => (
            <div key={s.label} className="p-4 rounded-xl border border-line bg-surface shadow-card">
              <div className="text-[11px] text-ink-faint">{s.icon} {s.label}</div>
              <div className={`display text-2xl font-bold mt-1 ${
                s.tone === 'ok' ? 'text-ok' : s.tone === 'warn' ? 'text-warn' : s.tone === 'violet' ? 'text-crypto-violet' : 'text-vault-600'
              }`}>{s.value}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card title="性能预算对照（目标）" icon="🎯" accent="vault">
            <ReactECharts option={barOption} style={{ height: 280 }} />
          </Card>
          <Card title="本次流水线实际耗时" icon="⚡" accent="violet">
            {actualPipeline.length ? (
              <ReactECharts option={stepOption} style={{ height: 280 }} />
            ) : (
              <div className="text-sm text-ink-faint text-center py-20">
                <div className="text-3xl mb-2">📊</div>
                执行查询后展示实际耗时分解
              </div>
            )}
          </Card>
        </div>

        <Card title="系统密钥信息" icon="🔑" accent="warn">
          <div className="receipt p-3">
            <HashLine label="服务商公钥" value={perf?.provider_public_key || '…'} shorten />
            <HashLine label="审计机构公钥" value={perf?.auditor_public_key || '…'} shorten />
            <HashLine label="AES 主密钥" value={perf?.aead_key_b64 || '…'} shorten />
          </div>
          <div className="mt-2">
            <Badge color="warn" icon="⚠">主密钥仅演示展示，真实部署由 KMS / 硬件密钥托管，绝不出本地</Badge>
          </div>
        </Card>
      </div>
    </div>
  )
}
