import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { useToast } from '../state/ToastContext.jsx'
import KeyRevealModal from '../components/KeyRevealModal.jsx'
import { Icon } from '../components/Icon.jsx'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  Skeleton,
  tdClass,
  thClass,
  tableClass,
} from '../components/ui.jsx'
import {
  clientActive,
  clientExpired,
  formatDateTime,
  formatNumber,
  formatRelativeTime,
  shorten,
} from '../utils/format.js'

const BASE_RESTORE_CHOICES = ['EMAIL', 'IP', 'URL', 'ORG']

const EMPTY_FORM = {
  name: '',
  models: [],
  rate_limit_per_min: '0',
  protection_mode: '',
  restore_categories: [],
  expires_in_days: '',
}

function ClientForm({ open, mode, initial, models, restoreChoices, defaultTtlDays, onClose, onSubmit, busy, error }) {
  const [form, setForm] = useState(EMPTY_FORM)
  const [localError, setLocalError] = useState(null)

  useEffect(() => {
    if (!open) return
    setForm({
      ...EMPTY_FORM,
      name: initial?.name || '',
      models: [...(initial?.models || [])],
      rate_limit_per_min: String(initial?.rate_limit_per_min ?? 0),
      protection_mode: initial?.protection_mode || '',
      restore_categories: [...(initial?.restore_categories || [])],
      expires_in_days: '',
    })
    setLocalError(null)
  }, [open, initial])

  const toggle = (key, value) => {
    setForm((prev) => {
      const current = prev[key]
      return {
        ...prev,
        [key]: current.includes(value)
          ? current.filter((item) => item !== value)
          : [...current, value],
      }
    })
  }

  const submit = () => {
    setLocalError(null)
    if (!form.name.trim()) return setLocalError('请输入客户端名称')
    const rate = Number(form.rate_limit_per_min)
    if (!Number.isFinite(rate) || rate < 0) return setLocalError('限流必须是 ≥0 的整数')
    const payload = {
      name: form.name.trim(),
      models: form.models,
      rate_limit_per_min: rate,
      protection_mode: form.protection_mode,
      restore_categories: form.restore_categories,
    }
    if (form.expires_in_days !== '') {
      const days = Number(form.expires_in_days)
      if (!Number.isFinite(days) || days < 0) return setLocalError('有效期必须是 ≥0 的整数')
      payload.expires_in_days = days
    }
    onSubmit(payload)
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === 'create' ? '签发客户端密钥' : `编辑客户端 ${initial?.name || ''}`}
      description={mode === 'create'
        ? '新密钥的完整值只显示一次；服务端只保存 HMAC 摘要。'
        : '不会改变密钥材料；如需换钥请使用「轮换」。'}
      size="lg"
      footer={(
        <>
          <Button onClick={onClose} disabled={busy}>取消</Button>
          <Button variant="primary" busy={busy} onClick={submit}>
            {mode === 'create' ? '签发' : '保存'}
          </Button>
        </>
      )}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="名称" required>
          <Input value={form.name} onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
            placeholder="claude-code" />
        </Field>
        <Field label="限流（请求/分钟）" hint="0 = 跟随全局">
          <Input type="number" min="0" value={form.rate_limit_per_min}
            onChange={(e) => setForm((prev) => ({ ...prev, rate_limit_per_min: e.target.value }))} />
        </Field>
        <Field label="保护模式" hint="空 = 跟随全局；客户端只能收紧">
          <Select value={form.protection_mode}
            onChange={(e) => setForm((prev) => ({ ...prev, protection_mode: e.target.value }))}>
            <option value="">跟随全局</option>
            <option value="placeholder">placeholder（可读占位符）</option>
            <option value="token">token（令牌化）</option>
            <option value="encrypt">encrypt（加密令牌）</option>
          </Select>
        </Field>
        <Field label={mode === 'create' ? '有效期（天）' : '重置有效期（天）'}
          hint={mode === 'create'
            ? `0 = 永不过期；留空 = 后端默认（${defaultTtlDays || 0} 天，0 表示永不过期）`
            : '留空 = 不修改；0 = 永不过期'}>
          <Input type="number" min="0" value={form.expires_in_days}
            onChange={(e) => setForm((prev) => ({ ...prev, expires_in_days: e.target.value }))}
            placeholder={mode === 'edit' ? '不修改' : '0'} />
        </Field>
      </div>

      <div className="mt-4">
        <p className="mb-1.5 text-[12px] font-medium text-ink">允许的模型</p>
        {models.length ? (
          <div className="grid max-h-40 gap-1 overflow-y-auto rounded-md border border-line bg-canvas p-2 sm:grid-cols-2">
            {models.map((model) => (
              <Checkbox key={model} label={model}
                checked={form.models.includes(model)}
                onChange={() => toggle('models', model)} />
            ))}
          </div>
        ) : (
          <p className="rounded-md border border-dashed border-line px-3 py-2 text-[12px] text-ink-faint">
            当前没有可用模型；请先在「上游配置」里添加 Provider 和模型。
          </p>
        )}
        <p className="mt-1 text-[11px] text-ink-faint">不勾选 = 不限制模型（跟随全局）。</p>
      </div>

      <div className="mt-4">
        <p className="mb-1.5 text-[12px] font-medium text-ink">允许自动还原的类别</p>
        <div className="grid gap-1 rounded-md border border-line bg-canvas p-2 sm:grid-cols-2">
          {restoreChoices.map((category) => (
            <Checkbox key={category} label={category}
              checked={form.restore_categories.includes(category)}
              onChange={() => toggle('restore_categories', category)} />
          ))}
        </div>
        <p className="mt-1 text-[11px] text-ink-faint">
          高风险类别（PHONE / ID / CARD / 密钥等）不能自动还原，只能走人工确认释放。
        </p>
      </div>

      {initial?.prefix ? (
        <p className="mt-3 text-[11px] text-ink-faint">
          当前密钥前缀：<span className="mono">{initial.prefix}</span>
        </p>
      ) : null}
      {localError ? <p className="mt-3 text-[12px] text-bad">{localError}</p> : null}
      {error ? <p className="mt-2 text-[12px] text-bad">{error.message}</p> : null}
    </Modal>
  )
}

export default function Clients() {
  const toast = useToast()
  const clients = useResource(() => api.clients.list(), [])
  const policies = useResource(() => api.policies(), [])
  const [editing, setEditing] = useState(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState(null)
  const [keyModal, setKeyModal] = useState({ open: false, key: '', title: '客户端密钥' })
  const [confirm, setConfirm] = useState(null)
  const [confirmBusy, setConfirmBusy] = useState(false)

  const models = policies.data?.models || []
  const neverRestore = policies.data?.policy?.never_auto_restore || []
  const restoreChoices = useMemo(() => {
    const choices = new Set([
      ...BASE_RESTORE_CHOICES,
      ...(policies.data?.policy?.restore_categories || []),
      ...((clients.data?.clients || []).flatMap((client) => client.restore_categories || [])),
    ])
    return [...choices].filter((category) => !neverRestore.includes(category)).sort()
  }, [policies.data, clients.data, neverRestore])

  const openCreate = () => {
    setFormError(null)
    setEditing({ mode: 'create', initial: null })
  }
  const openEdit = (client) => {
    setFormError(null)
    setEditing({ mode: 'edit', initial: client })
  }

  const save = async (payload) => {
    setSaving(true)
    setFormError(null)
    try {
      if (editing.mode === 'create') {
        const result = await api.clients.create(payload)
        setKeyModal({
          open: true,
          key: result.api_key,
          title: `客户端「${result.client?.name || payload.name}」的密钥`,
        })
        toast.push('客户端密钥已签发', 'ok')
      } else {
        await api.clients.update(editing.initial.id, payload)
        toast.push('客户端配置已更新', 'ok')
      }
      setEditing(null)
      clients.reload()
    } catch (error) {
      setFormError(error)
    } finally {
      setSaving(false)
    }
  }

  const runConfirm = async () => {
    if (!confirm) return
    setConfirmBusy(true)
    try {
      if (confirm.kind === 'revoke') {
        await api.clients.revoke(confirm.client.id)
        toast.push(`已撤销「${confirm.client.name}」`, 'ok')
      } else {
        const result = await api.clients.rotate(confirm.client.id)
        setKeyModal({
          open: true,
          key: result.api_key,
          title: `客户端「${confirm.client.name}」的新密钥`,
        })
        toast.push('密钥已轮换，旧密钥立即失效', 'ok')
      }
      setConfirm(null)
      clients.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setConfirmBusy(false)
    }
  }

  if (!clients.data && clients.loading) {
    return (
      <div>
        <PageHeader title="客户端密钥" description="签发、收紧与撤销调用网关的身份" />
        <div className="space-y-3 p-6"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
      </div>
    )
  }

  if (!clients.data && clients.error) {
    return (
      <div>
        <PageHeader title="客户端密钥" />
        <ErrorState error={clients.error} onRetry={() => clients.reload()} />
      </div>
    )
  }

  const items = clients.data?.clients || []

  return (
    <div>
      <PageHeader
        title="客户端密钥"
        description="每个 Agent / SDK 使用一个客户端密钥。密钥只显示一次；可随时撤销或轮换。"
        actions={(
          <>
            <Button size="sm" icon="refresh" onClick={() => clients.reload()}>刷新</Button>
            <Button size="sm" variant="primary" icon="plus" onClick={openCreate}>签发密钥</Button>
          </>
        )}
      />

      <div className="space-y-4 p-6">
        {clients.error ? (
          <div className="flex items-center gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12px] text-warn">
            <Icon name="alert" size={14} />
            刷新失败：{clients.error.message}
            <button type="button" className="ml-auto underline" onClick={() => clients.reload()}>重试</button>
          </div>
        ) : null}

        <Card title="客户端列表" description={`${items.length} 个客户端`} bodyClass="p-0">
          {items.length ? (
            <div className="overflow-x-auto">
              <table className={tableClass}>
                <thead>
                  <tr>
                    <th className={thClass}>名称 / ID</th>
                    <th className={thClass}>密钥前缀</th>
                    <th className={thClass}>模型</th>
                    <th className={thClass}>限流 / 保护</th>
                    <th className={thClass}>还原类别</th>
                    <th className={thClass}>有效期</th>
                    <th className={thClass}>最后使用</th>
                    <th className={thClass}>状态</th>
                    <th className={thClass}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((client) => {
                    const expired = clientExpired(client)
                    const active = clientActive(client)
                    return (
                      <tr key={client.id} className="align-top">
                        <td className={tdClass}>
                          <div className="font-medium text-ink">{client.name}</div>
                          <div className="mono text-[10.5px] text-ink-faint" title={client.id}>
                            {shorten(client.id, 10, 4)}
                          </div>
                        </td>
                        <td className={tdClass}>
                          <span className="mono text-[11.5px] text-ink-soft">{client.prefix}…</span>
                        </td>
                        <td className={tdClass}>
                          {(client.models || []).length ? (
                            <div className="flex max-w-[220px] flex-wrap gap-1">
                              {client.models.slice(0, 4).map((model) => (
                                <span key={model} className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10.5px] text-ink-soft">
                                  {model}
                                </span>
                              ))}
                              {client.models.length > 4 ? (
                                <span className="text-[10.5px] text-ink-faint">+{client.models.length - 4}</span>
                              ) : null}
                            </div>
                          ) : <span className="text-ink-faint">跟随全局</span>}
                        </td>
                        <td className={tdClass}>
                          <div className="tabular">{formatNumber(client.rate_limit_per_min || 0)}/min</div>
                          <div className="text-[11px] text-ink-faint">
                            {client.protection_mode || '跟随全局'}
                          </div>
                        </td>
                        <td className={tdClass}>
                          {(client.restore_categories || []).length
                            ? client.restore_categories.join(', ')
                            : <span className="text-ink-faint">默认</span>}
                        </td>
                        <td className={tdClass}>
                          {client.expires_epoch
                            ? formatDateTime(client.expires_epoch)
                            : <span className="text-ink-faint">永不过期</span>}
                        </td>
                        <td className={tdClass}>
                          {client.last_used ? formatRelativeTime(client.last_used) : <span className="text-ink-faint">从未</span>}
                        </td>
                        <td className={tdClass}>
                          {client.revoked ? <Badge tone="bad" dot>已撤销</Badge>
                            : expired ? <Badge tone="warn" dot>已过期</Badge>
                              : <Badge tone="ok" dot>有效</Badge>}
                        </td>
                        <td className={tdClass}>
                          <div className="flex flex-wrap gap-1.5">
                            <Button size="sm" icon="edit" onClick={() => openEdit(client)}>编辑</Button>
                            <Button size="sm" onClick={() => setConfirm({ kind: 'rotate', client })}
                              disabled={!active}>轮换</Button>
                            <Button size="sm" variant="danger" icon="trash"
                              onClick={() => setConfirm({ kind: 'revoke', client })}
                              disabled={client.revoked}>撤销</Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="还没有客户端密钥"
              description="签发一个密钥给 Agent / SDK；也可以先在「链路测试」中使用它验证中转链路。"
              action={<Button variant="primary" icon="plus" onClick={openCreate}>签发密钥</Button>}
            />
          )}
        </Card>

        <p className="text-[11px] text-ink-faint">
          完整密钥只在签发/轮换时返回一次；本页只显示前缀。限流 0 表示跟随全局（{policies.data?.policy?.rate_limit_per_min ?? '—'}/分钟）。
        </p>
      </div>

      <ClientForm
        open={Boolean(editing)}
        mode={editing?.mode || 'create'}
        initial={editing?.initial || null}
        models={models}
        restoreChoices={restoreChoices}
        defaultTtlDays={policies.data?.policy?.client_key_ttl_days}
        onClose={() => setEditing(null)}
        onSubmit={save}
        busy={saving}
        error={formError}
      />

      <KeyRevealModal
        open={keyModal.open}
        apiKey={keyModal.key}
        title={keyModal.title}
        onClose={() => setKeyModal({ open: false, key: '', title: '客户端密钥' })}
      />

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={runConfirm}
        title={confirm?.kind === 'revoke' ? `撤销「${confirm?.client?.name}」` : `轮换「${confirm?.client?.name}」`}
        description={confirm?.kind === 'revoke'
          ? '撤销后该密钥立即失效，使用它的 Agent 会收到 401。该操作不可撤销。'
          : '轮换会立即让旧密钥失效，并返回一个新密钥（只显示一次）。'}
        confirmLabel={confirm?.kind === 'revoke' ? '撤销密钥' : '轮换密钥'}
        danger={confirm?.kind === 'revoke'}
        busy={confirmBusy}
      />
    </div>
  )
}
