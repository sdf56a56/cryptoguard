import { useState } from 'react'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { useToast } from '../state/ToastContext.jsx'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  ErrorState,
  KeyValue,
  Mono,
  PageHeader,
  Skeleton,
} from '../components/ui.jsx'
import { formatBytes, formatDateTime, formatNumber, shorten } from '../utils/format.js'

function ChipList({ items = [], tone = 'neutral', limit = 40 }) {
  if (!items.length) return <span className="text-[12px] text-ink-faint">无</span>
  const shown = items.slice(0, limit)
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map((item) => (
        <span key={item} className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10.5px] text-ink-soft">
          {item}
        </span>
      ))}
      {items.length > limit ? <span className="text-[10.5px] text-ink-faint">+{items.length - limit}</span> : null}
    </div>
  )
}

export default function Policies() {
  const toast = useToast()
  const resource = useResource(() => api.policies(), [])
  const [chain, setChain] = useState({ busy: false, result: null, error: null })
  const [purge, setPurge] = useState({ busy: false, result: null, error: null })
  const [purgeConfirm, setPurgeConfirm] = useState(false)

  const verify = async () => {
    setChain({ busy: true, result: null, error: null })
    try {
      setChain({ busy: false, result: await api.audit.verify(true), error: null })
    } catch (error) {
      setChain({ busy: false, result: null, error })
    }
  }

  const runPurge = async (dryRun) => {
    setPurge((prev) => ({ ...prev, busy: true, error: null }))
    try {
      const result = await api.audit.purge(dryRun)
      setPurge({ busy: false, result, error: null })
      if (!dryRun) {
        toast.push('已按保留期清理审计段', 'ok')
        resource.reload()
      }
    } catch (error) {
      setPurge({ busy: false, result: null, error })
      toast.push(error.message, 'bad')
    }
  }

  if (!resource.data && resource.loading) {
    return (
      <div>
        <PageHeader title="策略与审计" description="当前生效的安全策略与审计链状态" />
        <div className="grid gap-3 p-6 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-40" />)}
        </div>
      </div>
    )
  }

  if (!resource.data && resource.error) {
    return (
      <div>
        <PageHeader title="策略与审计" />
        <ErrorState error={resource.error} onRetry={() => resource.reload()} />
      </div>
    )
  }

  const data = resource.data
  const policy = data.policy || {}
  const detection = data.detection || {}
  const deployment = data.deployment || {}
  const limits = data.limits || {}
  const audit = data.audit || {}
  const idempotency = data.idempotency || {}
  const chainResult = chain.result

  return (
    <div>
      <PageHeader
        title="策略与审计"
        description="策略由后端环境变量决定，控制台只读展示。客户端级策略只能在「客户端密钥」里收紧，不能扩大。"
        actions={<Button size="sm" icon="refresh" onClick={() => resource.reload()}>刷新</Button>}
      />

      <div className="space-y-4 p-6">
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="保护策略" description={`策略版本 ${policy.policy_version || '—'}`}>
            <div className="grid gap-x-6 sm:grid-cols-2">
              <KeyValue label="保护模式"><Mono>{policy.protection_mode || '—'}</Mono></KeyValue>
              <KeyValue label="还原模式"><Mono>{policy.restore_mode || '—'}</Mono></KeyValue>
              <KeyValue label="阻断阈值"><Mono>{policy.block_on || '—'}</Mono></KeyValue>
              <KeyValue label="同值同令牌">{policy.stable_tokens ? '是' : '否'}</KeyValue>
              <KeyValue label="响应侧扫描"><Mono>{policy.response_scan || '—'}</Mono></KeyValue>
              <KeyValue label="匿名调用">{policy.allow_anonymous ? '允许' : '拒绝'}</KeyValue>
            </div>
            <div className="mt-3 grid gap-3 border-t border-line/70 pt-3">
              <div>
                <p className="mb-1 text-[11px] font-medium text-ink-faint">允许自动还原</p>
                <ChipList items={policy.restore_categories} tone="ok" />
              </div>
              <div>
                <p className="mb-1 text-[11px] font-medium text-ink-faint">禁止自动还原</p>
                <ChipList items={policy.never_auto_restore} />
              </div>
            </div>
          </Card>

          <Card title="内容面策略" description="不静默放行，也不静默丢弃">
            <div className="grid gap-x-6 sm:grid-cols-2">
              <KeyValue label="图片"><Mono>{policy.image_policy || '—'}</Mono></KeyValue>
              <KeyValue label="文档"><Mono>{policy.document_policy || '—'}</Mono></KeyValue>
              <KeyValue label="Anthropic thinking"><Mono>{policy.anthropic_thinking || '—'}</Mono></KeyValue>
              <KeyValue label="cache_control"><Mono>{policy.cache_control || '—'}</Mono></KeyValue>
            </div>
            <div className="mt-3 border-t border-line/70 pt-3">
              <div className="grid gap-x-6 sm:grid-cols-2">
                <KeyValue label="全局限流">{formatNumber(limits.rate_limit_per_min || 0)}/min</KeyValue>
                <KeyValue label="最大并发">{formatNumber(limits.max_concurrency || 0)}</KeyValue>
                <KeyValue label="请求体上限">{formatBytes(limits.max_request_bytes || 0)}</KeyValue>
                <KeyValue label="SSE 心跳">{limits.sse_heartbeat_s ?? '—'} s</KeyValue>
                <KeyValue label="幂等 TTL">{limits.idempotency_ttl_s ?? '—'} s</KeyValue>
                <KeyValue label="幂等容量">{formatNumber(limits.idempotency_max || 0)}</KeyValue>
              </div>
              {idempotency && Object.keys(idempotency).length ? (
                <p className="mt-2 text-[11px] text-ink-faint">
                  幂等缓存：追踪 {formatNumber(idempotency.tracked || 0)} 条，命中 {formatNumber(idempotency.hits || 0)}，
                  冲突 {formatNumber(idempotency.conflicts || 0)}。
                </p>
              ) : null}
            </div>
          </Card>

          <Card title="检测规则" description={detection.config_path ? `自定义规则：${detection.config_path}` : '内置规则'}>
            <div className="grid gap-x-6 sm:grid-cols-2">
              <KeyValue label="内置规则">{formatNumber((detection.builtin_rules || []).length)}</KeyValue>
              <KeyValue label="自定义规则">{formatNumber((detection.custom_rules || []).length)}</KeyValue>
              <KeyValue label="敏感词">{formatNumber(detection.sensitive_words || 0)}</KeyValue>
              <KeyValue label="抑制模式">{formatNumber(detection.suppress_patterns || 0)}</KeyValue>
              <KeyValue label="复核阈值"><Mono>{detection.review_threshold ?? '—'}</Mono></KeyValue>
              <KeyValue label="禁用类型">{formatNumber((detection.disabled_types || []).length)}</KeyValue>
            </div>
            <details className="mt-3">
              <summary className="cursor-pointer text-[11.5px] text-ink-soft">查看内置规则 ID</summary>
              <div className="mt-2"><ChipList items={detection.builtin_rules} limit={80} /></div>
            </details>
          </Card>

          <Card title="部署形态" description="单进程网关">
            <KeyValue label="模式"><Mono>{deployment.mode || '—'}</Mono></KeyValue>
            <KeyValue label="实例锁">{deployment.instance_lock ? '开启' : '关闭'}</KeyValue>
            <KeyValue label="客户端密钥">{formatNumber(data.clients?.length || 0)} 个</KeyValue>
            <div className="mt-3 rounded-md border border-warn/25 bg-warn-soft px-3 py-2 text-[11.5px] leading-5 text-warn">
              {deployment.note || '确认、金库、限流与审计均为进程内状态；不支持多 worker / 多副本。'}
            </div>
          </Card>
        </div>

        <Card
          title="审计链"
          description="链尾摘要与完整性校验；清理只按保留期整段删除"
          actions={(
            <Button size="sm" icon="check" busy={chain.busy} onClick={verify}>校验整链</Button>
          )}
        >
          <div className="grid gap-x-8 sm:grid-cols-2">
            <div>
              <KeyValue label="记录数">{formatNumber(audit.records || 0)}</KeyValue>
              <KeyValue label="链尾 seq"><Mono>{audit.last_seq ?? '—'}</Mono></KeyValue>
              <KeyValue label="tip_hash" mono copy={audit.tip_hash}>
                {audit.tip_hash ? shorten(audit.tip_hash, 14, 8) : '—'}
              </KeyValue>
              <KeyValue label="锚点">{audit.anchor ? shorten(audit.anchor, 14, 8) : '无'}</KeyValue>
            </div>
            <div>
              <KeyValue label="起始 seq"><Mono>{audit.first_seq ?? '—'}</Mono></KeyValue>
              <KeyValue label="MAC 校验">{audit.mac_verified ? '通过' : '失败'}</KeyValue>
              <KeyValue label="保留期">{policy.audit_retention_days ?? '—'} 天</KeyValue>
              {chainResult ? (
                <KeyValue label="本次校验">
                  <Badge tone={chainResult.intact ? 'ok' : 'bad'} dot>
                    {chainResult.intact ? '完整' : `${chainResult.failures?.length || 0} 处异常`}
                  </Badge>
                  <span className="ml-2 text-[11px] text-ink-faint">
                    {formatDateTime(Date.now() / 1000)}
                  </span>
                </KeyValue>
              ) : chain.error ? (
                <KeyValue label="本次校验"><span className="text-bad">{chain.error.message}</span></KeyValue>
              ) : null}
            </div>
          </div>
          {chainResult?.failures?.length ? (
            <div className="mt-3 rounded-md border border-bad/25 bg-bad-soft px-3 py-2">
              <p className="text-[12px] font-medium text-bad">校验发现异常</p>
              <ul className="mt-1 max-h-40 space-y-1 overflow-y-auto text-[11px] text-bad">
                {chainResult.failures.slice(0, 20).map((failure, index) => (
                  <li key={index} className="mono break-all">
                    {failure.kind} · {failure.request_id || failure.scope || ''} · {failure.detail || ''}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {audit.scope_note ? (
            <p className="mt-3 text-[11px] leading-4 text-ink-faint">{audit.scope_note}</p>
          ) : null}
        </Card>

        <Card title="危险操作" description="按保留期清理审计段：被删除的记录不可恢复">
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" busy={purge.busy} onClick={() => runPurge(true)}>
              预览可清理范围
            </Button>
            <Button size="sm" variant="danger" onClick={() => setPurgeConfirm(true)}
              disabled={!purge.result || purge.result.dry_run === false}>
              执行清理
            </Button>
            {purge.result ? (
              <span className="text-[12px] text-ink-soft">
                可清理 {formatNumber(purge.result.purged_records || 0)} 条 /
                {purge.result.purged_segments?.length || 0} 个段
                {purge.result.reason ? `（${purge.result.reason}）` : ''}
              </span>
            ) : null}
            {purge.error ? <span className="text-[12px] text-bad">{purge.error.message}</span> : null}
          </div>
          <p className="mt-2 text-[11px] text-ink-faint">
            清理只会删除整段过期记录，并把删除前最后一条 chain_hash 写入锚点；保留期内的记录不会被删除。
          </p>
        </Card>

        <p className="text-[11px] text-ink-faint">
          需要修改保护模式、还原类别或限额时，请修改后端环境变量并重启网关；客户端级收紧在「客户端密钥」中完成。
        </p>
      </div>

      <ConfirmDialog
        open={purgeConfirm}
        onClose={() => setPurgeConfirm(false)}
        onConfirm={async () => {
          setPurgeConfirm(false)
          await runPurge(false)
        }}
        title="执行审计清理"
        description={`将永久删除约 ${formatNumber(purge.result?.purged_records || 0)} 条过期记录。此操作不可恢复。`}
        confirmLabel="确认清理"
        danger
        busy={purge.busy}
      >
        <p className="text-[12px] leading-5 text-ink-soft">
          只有整段过期记录会被删除；保留期内的记录不受影响。建议先复制当前 tip_hash 到站外作为锚点。
        </p>
      </ConfirmDialog>
    </div>
  )
}
