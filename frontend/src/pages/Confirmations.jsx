import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { useToast } from '../state/ToastContext.jsx'
import { Icon } from '../components/Icon.jsx'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Field,
  Kpi,
  Modal,
  PageHeader,
  Select,
  Skeleton,
  Textarea,
  tdClass,
  thClass,
  tableClass,
} from '../components/ui.jsx'
import { formatDateTime, formatNumber, formatRelativeTime, shorten, sumValues } from '../utils/format.js'

const STATUSES = [
  ['', '全部状态'],
  ['pending', '待确认'],
  ['approved', '已批准'],
  ['denied', '已拒绝'],
  ['consumed', '已释放'],
  ['expired', '已过期'],
]

const STATUS_TONES = {
  pending: 'warn',
  approved: 'ok',
  denied: 'bad',
  consumed: 'accent',
  expired: 'neutral',
}

export default function Confirmations() {
  const toast = useToast()
  const [status, setStatus] = useState('pending')
  const [clientId, setClientId] = useState('')
  const [confirm, setConfirm] = useState(null)
  const [denyTarget, setDenyTarget] = useState(null)
  const [denyReason, setDenyReason] = useState('')
  const [busy, setBusy] = useState(false)

  const clients = useResource(() => api.clients.list(), [])
  const queue = useResource(
    () => api.confirmations.list({ status, client_id: clientId || undefined, limit: 100 }),
    [status, clientId],
    { pollMs: 15000 },
  )

  const data = queue.data
  const items = data?.data || []
  const stats = data?.stats || {}

  const approve = async () => {
    if (!confirm) return
    setBusy(true)
    try {
      await api.confirmations.approve(confirm.confirmation_id)
      toast.push('已批准该确认申请', 'ok')
      setConfirm(null)
      queue.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setBusy(false)
    }
  }

  const deny = async () => {
    if (!denyTarget) return
    setBusy(true)
    try {
      await api.confirmations.deny(denyTarget.confirmation_id, denyReason)
      toast.push('已拒绝该确认申请', 'ok')
      setDenyTarget(null)
      setDenyReason('')
      queue.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="待确认"
        description="高风险数据默认扣留。客户端只能申请，批准与释放由管理员在网关侧完成；确认凭据一次性有效。"
        actions={<Button size="sm" icon="refresh" onClick={() => queue.reload()}>刷新</Button>}
      />

      <div className="space-y-4 p-6">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Kpi label="待确认" value={formatNumber(stats.pending)} tone={stats.pending ? 'warn' : 'neutral'} icon="clock" />
          <Kpi label="已批准" value={formatNumber(stats.approved)} icon="check" />
          <Kpi label="已拒绝" value={formatNumber(stats.denied)} tone={stats.denied ? 'bad' : 'neutral'} icon="x" />
          <Kpi label="已释放" value={formatNumber(stats.consumed)} icon="key" />
        </div>

        <Card bodyClass="p-3">
          <div className="flex flex-wrap items-end gap-3">
            <Field label="状态" className="w-[180px]">
              <Select value={status} onChange={(event) => setStatus(event.target.value)}>
                {STATUSES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </Select>
            </Field>
            <Field label="客户端" className="w-[240px]">
              <Select value={clientId} onChange={(event) => setClientId(event.target.value)}>
                <option value="">全部客户端</option>
                {(clients.data?.clients || []).map((client) => (
                  <option key={client.id} value={client.id}>{client.name}</option>
                ))}
              </Select>
            </Field>
            <span className="ml-auto pb-1 text-[11px] text-ink-faint">每 15 秒自动刷新</span>
          </div>
        </Card>

        {!data && queue.loading ? (
          <div className="space-y-2"><Skeleton className="h-16" /><Skeleton className="h-64" /></div>
        ) : !data && queue.error ? (
          <ErrorState error={queue.error} onRetry={() => queue.reload()} />
        ) : (
          <Card
            title={`${formatNumber(items.length)} 条确认记录`}
            description={`待确认 ${formatNumber(stats.pending)} 条 · TTL ${stats.ttl_s ?? '—'} 秒`}
            bodyClass="p-0"
          >
            {queue.error ? (
              <div className="flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-2 text-[12px] text-warn">
                <Icon name="alert" size={14} />
                刷新失败，显示旧数据：{queue.error.message}
              </div>
            ) : null}
            {items.length ? (
              <div className="overflow-x-auto">
                <table className={tableClass}>
                  <thead>
                    <tr>
                      <th className={thClass}>创建时间</th>
                      <th className={thClass}>request_id</th>
                      <th className={thClass}>客户端</th>
                      <th className={thClass}>令牌</th>
                      <th className={thClass}>原因</th>
                      <th className={thClass}>过期</th>
                      <th className={thClass}>状态</th>
                      <th className={thClass}>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => {
                      const tokenTypes = Object.entries(item.token_types || {})
                      const pending = item.status === 'pending'
                      return (
                        <tr key={item.confirmation_id} className="align-top">
                          <td className={tdClass}>
                            <div className="text-[11.5px]">{formatDateTime(item.created_epoch)}</div>
                            <div className="text-[10.5px] text-ink-faint">
                              {formatRelativeTime(item.created_epoch)}
                            </div>
                          </td>
                          <td className={tdClass}>
                            <Link className="mono text-[11.5px] text-accent-700 hover:underline"
                              to={`/requests/${encodeURIComponent(item.request_id)}`}>
                              {shorten(item.request_id, 10, 4)}
                            </Link>
                          </td>
                          <td className={tdClass}>{item.client_id ? shorten(item.client_id, 8, 4) : '—'}</td>
                          <td className={tdClass}>
                            <div className="font-medium">{item.token_count ?? sumValues(item.token_types)} 个</div>
                            <div className="mt-1 flex max-w-[220px] flex-wrap gap-1">
                              {tokenTypes.map(([type, count]) => (
                                <span key={type} className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10.5px] text-ink-soft">
                                  {type} × {count}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className={`${tdClass} max-w-[220px] text-[11.5px] text-ink-soft`}>
                            {item.reason || <span className="text-ink-faint">—</span>}
                          </td>
                          <td className={tdClass}>
                            <div className="text-[11.5px]">{formatDateTime(item.expires_epoch)}</div>
                            <div className="text-[10.5px] text-ink-faint">{formatRelativeTime(item.expires_epoch)}</div>
                          </td>
                          <td className={tdClass}>
                            <Badge tone={STATUS_TONES[item.status] || 'neutral'} dot>{item.status}</Badge>
                          </td>
                          <td className={tdClass}>
                            {pending ? (
                              <div className="flex flex-wrap gap-1.5">
                                <Button size="sm" variant="primary" onClick={() => setConfirm(item)}>批准</Button>
                                <Button size="sm" variant="danger" onClick={() => setDenyTarget(item)}>拒绝</Button>
                              </div>
                            ) : <span className="text-[11px] text-ink-faint">—</span>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title={status === 'pending' ? '没有待确认项' : '没有匹配的确认记录'}
                description={status === 'pending'
                  ? '当客户端申请释放被扣留的高风险数据时，会出现在这里。'
                  : '切换筛选条件查看其它状态的记录。'}
              />
            )}
          </Card>
        )}
      </div>

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={approve}
        title="批准确认申请"
        description={`request_id：${confirm?.request_id || ''}。批准只表示授权释放，不代表内容已被逐字审阅。`}
        confirmLabel="批准"
        busy={busy}
      />

      <Modal
        open={Boolean(denyTarget)}
        onClose={() => setDenyTarget(null)}
        title="拒绝确认申请"
        description={`request_id：${denyTarget?.request_id || ''}`}
        size="sm"
        footer={(
          <>
            <Button onClick={() => setDenyTarget(null)} disabled={busy}>取消</Button>
            <Button variant="danger" busy={busy} onClick={deny}>拒绝</Button>
          </>
        )}
      >
        <Field label="拒绝原因" hint="可选，最多 200 字符">
          <Textarea rows={3} maxLength={200} value={denyReason}
            onChange={(event) => setDenyReason(event.target.value)}
            placeholder="例如：无法确认业务必要性" />
        </Field>
      </Modal>
    </div>
  )
}
