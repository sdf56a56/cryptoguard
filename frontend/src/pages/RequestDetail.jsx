import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import {
  Badge,
  Button,
  Card,
  CopyButton,
  ErrorState,
  KeyValue,
  Mono,
  PageHeader,
  Skeleton,
} from '../components/ui.jsx'
import {
  formatDateTime,
  formatDurationMs,
  formatNumber,
  outcomeLabel,
  outcomeTone,
} from '../utils/format.js'

function ValueView({ value }) {
  if (value === null || value === undefined || value === '') return <span className="text-ink-faint">—</span>
  if (typeof value === 'object') {
    return (
      <span className="mono break-all text-[11.5px] text-ink-soft">
        {JSON.stringify(value)}
      </span>
    )
  }
  return <span>{String(value)}</span>
}

function JsonTable({ value, empty = '无' }) {
  if (!value || typeof value !== 'object' || !Object.keys(value).length) {
    return <span className="text-[12px] text-ink-faint">{empty}</span>
  }
  return (
    <div className="divide-y divide-line/60">
      {Object.entries(value).map(([key, item]) => (
        <div key={key} className="grid grid-cols-[180px_minmax(0,1fr)] gap-3 py-1.5">
          <span className="mono text-[11px] text-ink-faint">{key}</span>
          <ValueView value={item} />
        </div>
      ))}
    </div>
  )
}

export default function RequestDetail() {
  const { rid } = useParams()
  const navigate = useNavigate()
  const record = useResource(() => api.audit.get(rid), [rid])

  if (!record.data && record.loading) {
    return (
      <div>
        <PageHeader title="请求详情" description={rid} />
        <div className="space-y-3 p-6"><Skeleton className="h-32" /><Skeleton className="h-64" /></div>
      </div>
    )
  }

  if (!record.data && record.error) {
    return (
      <div>
        <PageHeader
          title="请求详情"
          description={rid}
          actions={<Button size="sm" icon="arrowLeft" onClick={() => navigate('/requests')}>返回列表</Button>}
        />
        <ErrorState error={record.error} onRetry={() => record.reload()} />
      </div>
    )
  }

  if (record.data && record.data.found === false) {
    return (
      <div>
        <PageHeader title="请求详情" description={rid} />
        <div className="p-6 text-[13px] text-ink-soft">
          {record.data.reason || '没有找到该 request_id 的审计记录。'}
        </div>
      </div>
    )
  }

  const item = record.data?.record || {}
  const detections = item.detections || {}

  return (
    <div>
      <PageHeader
        title="请求详情"
        description="审计记录只含摘要、类别与决策；不包含原始 Prompt 或原始敏感值。"
        actions={(
          <>
            <Link to="/requests"><Button size="sm" icon="arrowLeft">返回列表</Button></Link>
            <CopyButton value={item.request_id || rid} label="复制 request_id" />
          </>
        )}
      />

      <div className="space-y-4 p-6">
        <Card>
          <div className="flex flex-wrap items-center gap-3">
            <span className="mono text-[13px] font-medium text-ink">{item.request_id || rid}</span>
            <Badge tone={outcomeTone(item.outcome)} dot>{outcomeLabel(item.outcome)}</Badge>
            {item.error_kind ? <Badge tone="bad">{item.error_kind}</Badge> : null}
            {record.data?.record_mac_valid === false ? <Badge tone="bad">记录 MAC 校验失败</Badge>
              : record.data?.record_mac_valid ? <Badge tone="ok">记录 MAC 有效</Badge> : null}
            <span className="ml-auto text-[11px] text-ink-faint">seq {item.seq ?? '—'}</span>
          </div>

          <div className="mt-4 grid gap-x-8 gap-y-0 sm:grid-cols-2">
            <div>
              <KeyValue label="时间">{formatDateTime(item.ts_epoch)}</KeyValue>
              <KeyValue label="客户端">{item.client_name || item.client_id || '—'}</KeyValue>
              <KeyValue label="入口"><Mono>{item.endpoint || '—'}</Mono></KeyValue>
              <KeyValue label="请求模型"><Mono>{item.requested_model || '—'}</Mono></KeyValue>
              <KeyValue label="Provider"><Mono>{item.provider || '—'}</Mono></KeyValue>
              <KeyValue label="上游模型"><Mono>{item.upstream_model || '—'}</Mono></KeyValue>
            </div>
            <div>
              <KeyValue label="延迟">{item.latency_ms != null ? formatDurationMs(item.latency_ms) : '—'}</KeyValue>
              <KeyValue label="上游状态">{item.upstream_status ?? '—'}</KeyValue>
              <KeyValue label="流式">{item.stream ? '是' : '否'}</KeyValue>
              <KeyValue label="策略版本"><Mono>{item.policy_version || '—'}</Mono></KeyValue>
              <KeyValue label="保护模式"><Mono>{item.protection_mode || '—'}</Mono></KeyValue>
              <KeyValue label="检出总数">{formatNumber(detections.total || 0)}</KeyValue>
            </div>
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="摘要" description="RFC 8785 (JCS) 规范化 + SHA-256">
            <KeyValue label="请求摘要" mono copy={item.request_digest}>
              {item.request_digest ? `${item.request_digest.slice(0, 32)}…` : '—'}
            </KeyValue>
            <KeyValue label="响应摘要" mono copy={item.response_digest}>
              {item.response_digest ? `${item.response_digest.slice(0, 32)}…` : '—'}
            </KeyValue>
          </Card>

          <Card title="审计链位置">
            <KeyValue label="seq">{item.seq ?? '—'}</KeyValue>
            <KeyValue label="prev_hash" mono copy={item.prev_hash}>
              {item.prev_hash ? `${item.prev_hash.slice(0, 24)}…` : '—'}
            </KeyValue>
            <KeyValue label="chain_hash" mono copy={item.chain_hash}>
              {item.chain_hash ? `${item.chain_hash.slice(0, 24)}…` : '—'}
            </KeyValue>
          </Card>

          <Card title="检测" description="按实体类型 / 风险等级统计">
            <div className="grid gap-4 sm:grid-cols-2">
              <JsonTable value={detections.by_type} empty="未检出敏感实体" />
              <JsonTable value={detections.by_risk} empty="无风险分级" />
            </div>
          </Card>

          <Card title="决策与还原">
            <JsonTable value={item.actions} empty="无动作记录" />
            <div className="mt-3 border-t border-line/70 pt-3">
              <p className="mb-1 text-[11px] font-medium text-ink-faint">还原结果</p>
              <JsonTable value={item.restored} empty="未还原任何令牌" />
            </div>
          </Card>
        </div>

        {item.usage && Object.keys(item.usage).length ? (
          <Card title="用量" description="上游返回的 usage（若有）">
            <JsonTable value={item.usage} />
          </Card>
        ) : null}

        <Card title="原始记录" description="审计落盘字段的完整视图（不含明文）">
          <details>
            <summary className="cursor-pointer text-[12px] text-ink-soft">展开原始 JSON</summary>
            <pre className="mono mt-2 max-h-[420px] overflow-auto rounded-md border border-line bg-canvas p-3 text-[11px] leading-5 text-ink-soft">
{JSON.stringify(item, null, 2)}
            </pre>
          </details>
        </Card>
      </div>
    </div>
  )
}
