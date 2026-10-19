import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { useToast } from '../state/ToastContext.jsx'
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
  StatusDot,
  Textarea,
  tdClass,
  thClass,
  tableClass,
} from '../components/ui.jsx'
import { formatDurationMs, splitList } from '../utils/format.js'

const EMPTY_FORM = {
  name: '',
  type: 'openai-compatible',
  display_name: '',
  base_url: '',
  models: '',
  api_key: '',
  api_key_env: '',
  clear_api_key: false,
  trust_env: false,
  timeout_connect: '10',
  timeout_read: '120',
  max_retries: '2',
  token_limit_field: 'max_tokens',
  stream_options: '',
  extra_headers: '',
}

function formFromProvider(provider) {
  if (!provider) return { ...EMPTY_FORM }
  return {
    ...EMPTY_FORM,
    name: provider.name || '',
    type: provider.type || 'openai-compatible',
    display_name: provider.display_name || '',
    base_url: provider.base_url || '',
    models: (provider.models || []).join(', '),
    api_key_env: provider.key_env || '',
    trust_env: Boolean(provider.trust_env),
    timeout_connect: String(provider.timeout_connect ?? 10),
    timeout_read: String(provider.timeout_read ?? 120),
    max_retries: String(provider.max_retries ?? 2),
    token_limit_field: provider.token_limit_field || 'max_tokens',
    stream_options: provider.stream_options
      ? JSON.stringify(provider.stream_options, null, 2)
      : '',
  }
}

function ProviderForm({ open, mode, initial, onClose, onSubmit, busy, error }) {
  const [form, setForm] = useState(EMPTY_FORM)
  const [localError, setLocalError] = useState(null)

  useEffect(() => {
    if (!open) return
    setForm(formFromProvider(initial))
    setLocalError(null)
  }, [open, initial])

  const set = (key, value) => setForm((prev) => ({ ...prev, [key]: value }))
  const isMock = form.type === 'mock'

  const submit = () => {
    setLocalError(null)
    const name = form.name.trim()
    if (!name) return setLocalError('请输入 Provider 名称')
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
      return setLocalError('名称只能包含字母、数字、点、下划线与连字符，且不超过 64 字符')
    }
    if (!isMock && !form.base_url.trim()) {
      return setLocalError('openai-compatible / anthropic 上游必须填写 base_url')
    }
    const numbers = {
      timeout_connect: Number(form.timeout_connect),
      timeout_read: Number(form.timeout_read),
      max_retries: Number(form.max_retries),
    }
    if (Object.values(numbers).some((value) => !Number.isFinite(value))) {
      return setLocalError('超时与重试次数必须是数字')
    }
    if (numbers.timeout_connect < 1 || numbers.timeout_connect > 600
      || numbers.timeout_read < 1 || numbers.timeout_read > 600) {
      return setLocalError('连接/读取超时必须在 1..600 秒之间')
    }
    if (numbers.max_retries < 0 || numbers.max_retries > 5) {
      return setLocalError('max_retries 必须在 0..5 之间')
    }

    const payload = {
      name,
      type: form.type,
      display_name: form.display_name.trim(),
      base_url: form.base_url.trim(),
      models: splitList(form.models),
      api_key_env: form.api_key_env.trim(),
      trust_env: Boolean(form.trust_env),
      timeout_connect: numbers.timeout_connect,
      timeout_read: numbers.timeout_read,
      max_retries: numbers.max_retries,
      token_limit_field: form.token_limit_field,
    }
    if (form.api_key.trim()) payload.api_key = form.api_key.trim()
    if (mode === 'edit' && form.clear_api_key) payload.clear_api_key = true
    if (form.stream_options.trim()) {
      try {
        payload.stream_options = JSON.parse(form.stream_options)
      } catch (parseError) {
        return setLocalError(`stream_options 不是合法 JSON：${parseError.message}`)
      }
    }
    if (form.extra_headers.trim()) {
      try {
        payload.extra_headers = JSON.parse(form.extra_headers)
      } catch (parseError) {
        return setLocalError(`extra_headers 不是合法 JSON：${parseError.message}`)
      }
    }
    onSubmit(payload)
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === 'create' ? '新增上游 Provider' : `编辑 ${initial?.name || ''}`}
      description={mode === 'create'
        ? '保存后立即生效，无需重启网关。API Key 会加密落盘，任何接口都不会回显。'
        : '留空 API Key 表示保持现有密钥；修改 base_url 会立即影响后续请求的路由。'}
      size="lg"
      footer={(
        <>
          <Button onClick={onClose} disabled={busy}>取消</Button>
          <Button variant="primary" busy={busy} onClick={submit}>
            {mode === 'create' ? '创建' : '保存'}
          </Button>
        </>
      )}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="名称" required hint={mode === 'edit' ? '不可修改' : '用于 model / provider 前缀'}>
          <Input value={form.name} onChange={(e) => set('name', e.target.value)}
            disabled={mode === 'edit'} mono placeholder="deepseek" />
        </Field>
        <Field label="类型" required>
          <Select value={form.type} onChange={(e) => set('type', e.target.value)}>
            <option value="openai-compatible">openai-compatible</option>
            <option value="anthropic">anthropic</option>
            <option value="mock">mock（离线演练）</option>
          </Select>
        </Field>
        <Field label="显示名称" hint="可选">
          <Input value={form.display_name} onChange={(e) => set('display_name', e.target.value)}
            placeholder="DeepSeek" />
        </Field>
        <Field label="Base URL" required={!isMock} hint={isMock ? 'mock 可留空' : '必须 http(s)://'}>
          <Input value={form.base_url} onChange={(e) => set('base_url', e.target.value)}
            mono placeholder="https://api.deepseek.com" disabled={isMock} />
        </Field>
        <Field label="模型列表" hint="逗号或换行分隔" className="sm:col-span-2">
          <Textarea rows={2} value={form.models} onChange={(e) => set('models', e.target.value)}
            mono placeholder="deepseek-chat, deepseek-reasoner" />
        </Field>
        <Field label="API Key" hint={mode === 'edit' ? '留空保持不变' : '可选；也可以只填下面的环境变量名'}>
          <Input type="password" autoComplete="off" value={form.api_key}
            onChange={(e) => set('api_key', e.target.value)}
            mono placeholder={initial?.has_key ? '已保存（留空保持不变）' : 'sk-...'} />
        </Field>
        <Field label="密钥环境变量名" hint="可选；托管 Key 优先">
          <Input value={form.api_key_env} onChange={(e) => set('api_key_env', e.target.value)}
            mono placeholder="CG_PROVIDER_DEEPSEEK_API_KEY" />
        </Field>
        {mode === 'edit' ? (
          <div className="sm:col-span-2">
            <Checkbox
              label="清除已保存的 API Key"
              hint={initial?.key_env ? '清除后会回退到该环境变量（若已设置）' : '清除后该 Provider 将不可用'}
              checked={form.clear_api_key}
              onChange={(e) => set('clear_api_key', e.target.checked)}
            />
          </div>
        ) : null}
        <Field label="连接超时（秒）">
          <Input type="number" min="1" max="600" value={form.timeout_connect}
            onChange={(e) => set('timeout_connect', e.target.value)} />
        </Field>
        <Field label="读取超时（秒）">
          <Input type="number" min="1" max="600" value={form.timeout_read}
            onChange={(e) => set('timeout_read', e.target.value)} />
        </Field>
        <Field label="最大重试次数" hint="0..5，禁止无限重试">
          <Input type="number" min="0" max="5" value={form.max_retries}
            onChange={(e) => set('max_retries', e.target.value)} />
        </Field>
        <Field label="token 上限字段">
          <Select value={form.token_limit_field}
            onChange={(e) => set('token_limit_field', e.target.value)}>
            <option value="max_tokens">max_tokens</option>
            <option value="max_completion_tokens">max_completion_tokens</option>
          </Select>
        </Field>
        <div className="sm:col-span-2">
          <Checkbox
            label="允许上游请求走环境/系统代理（trust_env）"
            hint="代理可以读取 Authorization 头与上游响应体；仅在确认代理可信时开启。"
            checked={form.trust_env}
            onChange={(e) => set('trust_env', e.target.checked)}
          />
        </div>
      </div>

      <details className="mt-4 rounded-md border border-line bg-canvas px-3 py-2">
        <summary className="cursor-pointer text-[12px] font-medium text-ink-soft">高级（可选）</summary>
        <div className="mt-3 grid gap-3">
          <Field label="stream_options（JSON）" hint="例如 include_usage: true">
            <Textarea rows={2} mono value={form.stream_options}
              onChange={(e) => set('stream_options', e.target.value)} placeholder="留空表示不设置" />
          </Field>
          <Field
            label="extra_headers（JSON）"
            hint={mode === 'edit'
              ? `现有 header：${(initial?.extra_header_names || []).join(', ') || '无'}；值不回显，输入 JSON 会整体替换`
              : '值只加密落盘，接口只回显 header 名'}
          >
            <Textarea rows={2} mono value={form.extra_headers}
              onChange={(e) => set('extra_headers', e.target.value)}
              placeholder='例如 {"anthropic-version": "2023-06-01"}' />
          </Field>
        </div>
      </details>

      {localError ? <p className="mt-3 text-[12px] text-bad">{localError}</p> : null}
      {error ? <p className="mt-2 text-[12px] text-bad">{error.message}</p> : null}
    </Modal>
  )
}

export default function Upstreams() {
  const toast = useToast()
  const providers = useResource(() => api.providers.list(), [])
  const [editing, setEditing] = useState(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState(null)
  const [testing, setTesting] = useState({})
  const [confirmDelete, setConfirmDelete] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const [defaults, setDefaults] = useState({ provider: '', model: '' })
  const [defaultsBusy, setDefaultsBusy] = useState(false)

  const data = providers.data

  useEffect(() => {
    if (!data) return
    setDefaults({
      provider: data.default_provider || '',
      model: data.default_model || '',
    })
  }, [data?.default_provider, data?.default_model])

  const modelOptions = useMemo(() => {
    const provider = (data?.providers || []).find((item) => item.name === defaults.provider)
    return provider?.models || []
  }, [data?.providers, defaults.provider])

  const openCreate = (initial = null) => {
    setFormError(null)
    setEditing({ mode: 'create', initial })
  }

  const openEdit = (provider) => {
    setFormError(null)
    setEditing({ mode: 'edit', initial: provider })
  }

  const save = async (payload) => {
    setSaving(true)
    setFormError(null)
    try {
      if (editing.mode === 'create') {
        await api.providers.create(payload)
      } else {
        await api.providers.update(editing.initial.name, payload)
      }
      toast.push('Provider 已保存并生效', 'ok')
      setEditing(null)
      providers.reload()
    } catch (error) {
      setFormError(error)
    } finally {
      setSaving(false)
    }
  }

  const test = async (name) => {
    setTesting((prev) => ({ ...prev, [name]: { busy: true } }))
    try {
      const result = await api.providers.test(name)
      setTesting((prev) => ({ ...prev, [name]: { result } }))
    } catch (error) {
      setTesting((prev) => ({ ...prev, [name]: { error } }))
    }
  }

  const remove = async () => {
    if (!confirmDelete) return
    setDeleting(true)
    try {
      await api.providers.remove(confirmDelete.name)
      toast.push(`已删除托管 Provider「${confirmDelete.name}」`, 'ok')
      setConfirmDelete(null)
      providers.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setDeleting(false)
    }
  }

  const saveDefaults = async () => {
    setDefaultsBusy(true)
    try {
      await api.providers.setDefaults(defaults.provider, defaults.model)
      toast.push('默认 Provider / 模型已更新', 'ok')
      providers.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setDefaultsBusy(false)
    }
  }

  const resetDefaults = async () => {
    setDefaultsBusy(true)
    try {
      await api.providers.setDefaults('', '')
      toast.push('已清除托管默认项，回退环境变量默认值', 'ok')
      providers.reload()
    } catch (error) {
      toast.push(error.message, 'bad')
    } finally {
      setDefaultsBusy(false)
    }
  }

  if (!data && providers.loading) {
    return (
      <div>
        <PageHeader title="上游配置" description="管理 Provider、模型与上游密钥；保存即生效" />
        <div className="space-y-3 p-6">
          <Skeleton className="h-24" />
          <Skeleton className="h-64" />
        </div>
      </div>
    )
  }

  if (!data && providers.error) {
    return (
      <div>
        <PageHeader title="上游配置" />
        <ErrorState error={providers.error} onRetry={() => providers.reload()} />
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="上游配置"
        description="控制台托管的 Provider 会加密落盘并立即生效；同名托管项覆盖环境变量配置，删除后环境变量项恢复。"
        actions={(
          <>
            <Button size="sm" icon="refresh" onClick={() => providers.reload()}>刷新</Button>
            <Button size="sm" variant="primary" icon="plus" onClick={() => openCreate()}>
              新增 Provider
            </Button>
          </>
        )}
      />

      <div className="space-y-4 p-6">
        {providers.error ? (
          <div className="flex items-center gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12px] text-warn">
            <Icon name="alert" size={14} />
            刷新失败，显示的是上一次数据：{providers.error.message}
            <button type="button" className="ml-auto underline" onClick={() => providers.reload()}>重试</button>
          </div>
        ) : null}

        <Card
          title="默认路由"
          description="未显式指定 model 或 model 无法解析时使用的默认 Provider / 模型"
          actions={(
            <Button size="sm" variant="ghost" onClick={resetDefaults} disabled={defaultsBusy}>
              恢复环境变量默认
            </Button>
          )}
        >
          <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
            <Field label="默认 Provider">
              <Select
                value={defaults.provider}
                onChange={(event) => {
                  const provider = (data.providers || []).find((item) => item.name === event.target.value)
                  setDefaults({ provider: event.target.value, model: provider?.models?.[0] || '' })
                }}
              >
                <option value="">（未设置）</option>
                {(data.providers || []).map((provider) => (
                  <option key={provider.name} value={provider.name}>{provider.display_name || provider.name}</option>
                ))}
              </Select>
            </Field>
            <Field label="默认模型">
              <Select
                value={defaults.model}
                onChange={(event) => setDefaults((prev) => ({ ...prev, model: event.target.value }))}
                disabled={!defaults.provider}
              >
                <option value="">（选择模型）</option>
                {modelOptions.map((model) => (
                  <option key={model} value={model}>{model}</option>
                ))}
              </Select>
            </Field>
            <div className="flex items-end">
              <Button variant="primary" busy={defaultsBusy} onClick={saveDefaults}>保存默认</Button>
            </div>
          </div>
        </Card>

        <Card
          title="Provider 列表"
          description={`${(data.providers || []).length} 个 Provider · 托管配置 ${data.managed?.count ?? 0} 项`}
          bodyClass="p-0"
        >
          {(data.providers || []).length ? (
            <div className="overflow-x-auto">
              <table className={tableClass}>
                <thead>
                  <tr>
                    <th className={thClass}>Provider</th>
                    <th className={thClass}>地址 / 模型</th>
                    <th className={thClass}>密钥</th>
                    <th className={thClass}>来源</th>
                    <th className={thClass}>默认</th>
                    <th className={thClass}>连通性</th>
                    <th className={thClass}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.providers || []).map((provider) => {
                    const state = testing[provider.name]
                    const isDefault = data.default_provider === provider.name
                    return (
                      <tr key={provider.name} className="align-top">
                        <td className={tdClass}>
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium text-ink">{provider.display_name || provider.name}</span>
                            <span className="mono text-[11px] text-ink-faint">{provider.name}</span>
                            <Badge tone="neutral">{provider.type}</Badge>
                          </div>
                          {provider.overrides_env ? (
                            <div className="mt-1"><Badge tone="warn">覆盖环境变量</Badge></div>
                          ) : null}
                          {provider.trust_env ? (
                            <div className="mt-1 text-[11px] text-warn">trust_env 已开启</div>
                          ) : null}
                        </td>
                        <td className={tdClass}>
                          <div className="mono max-w-[280px] truncate text-[11.5px] text-ink-soft" title={provider.base_url}>
                            {provider.base_url || 'mock'}
                          </div>
                          <div className="mt-1 flex max-w-[320px] flex-wrap gap-1">
                            {(provider.models || []).slice(0, 4).map((model) => (
                              <span key={model} className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10.5px] text-ink-soft">
                                {model}
                              </span>
                            ))}
                            {(provider.models || []).length > 4 ? (
                              <span className="text-[10.5px] text-ink-faint">+{(provider.models || []).length - 4}</span>
                            ) : null}
                          </div>
                        </td>
                        <td className={tdClass}>
                          {provider.type === 'mock' ? (
                            <>
                              <StatusDot tone="ok">无需密钥</StatusDot>
                              <div className="mt-0.5 text-[11px] text-ink-faint">mock 提供商</div>
                            </>
                          ) : (
                            <>
                              <StatusDot tone={provider.has_key ? 'ok' : 'bad'}>
                                {provider.has_key ? '已配置' : '未配置'}
                              </StatusDot>
                              <div className="mt-0.5 text-[11px] text-ink-faint">
                                {provider.key_source === 'managed'
                                  ? '托管密钥'
                                  : provider.key_source === 'env'
                                    ? `环境变量 ${provider.key_env || ''}`
                                    : '无密钥'}
                              </div>
                            </>
                          )}
                        </td>
                        <td className={tdClass}>
                          <Badge tone={provider.source === 'managed' ? 'accent' : 'neutral'}>
                            {provider.source === 'managed' ? '托管' : '环境变量'}
                          </Badge>
                          <div className="mt-1 text-[11px] text-ink-faint">
                            {provider.editable ? '可编辑' : '只读'}
                          </div>
                        </td>
                        <td className={tdClass}>
                          {isDefault ? (
                            <>
                              <Badge tone="ok">默认</Badge>
                              <div className="mono mt-1 text-[10.5px] text-ink-faint">{data.default_model}</div>
                            </>
                          ) : <span className="text-ink-faint">—</span>}
                        </td>
                        <td className={tdClass}>
                          {state?.busy ? <span className="text-[11.5px] text-ink-faint">测试中…</span>
                            : state?.error ? <Badge tone="bad">{state.error.message}</Badge>
                              : state?.result ? (
                                <div>
                                  <Badge tone={state.result.ok ? 'ok' : 'bad'} dot>
                                    {state.result.ok ? '正常' : state.result.category || '失败'}
                                  </Badge>
                                  <div className="mt-1 text-[10.5px] text-ink-faint">
                                    {state.result.ok
                                      ? `${formatDurationMs(state.result.latency_ms)} · ${state.result.model || ''}`
                                      : state.result.message || ''}
                                  </div>
                                </div>
                              ) : <span className="text-[11.5px] text-ink-faint">未测试</span>}
                        </td>
                        <td className={tdClass}>
                          <div className="flex flex-wrap gap-1.5">
                            <Button size="sm" onClick={() => test(provider.name)} busy={state?.busy}>
                              测试
                            </Button>
                            {provider.editable ? (
                              <>
                                <Button size="sm" icon="edit" onClick={() => openEdit(provider)}>编辑</Button>
                                <Button size="sm" variant="danger" icon="trash"
                                  onClick={() => setConfirmDelete(provider)}>删除</Button>
                              </>
                            ) : (
                              <Button size="sm" icon="plus" onClick={() => openCreate(provider)}>
                                覆盖
                              </Button>
                            )}
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
              title="还没有 Provider"
              description="创建一个上游 Provider，填写 base_url、模型与 API Key；保存后即可在链路测试里使用。"
              action={<Button variant="primary" icon="plus" onClick={() => openCreate()}>新增 Provider</Button>}
            />
          )}
        </Card>

        <div className="flex flex-wrap items-center gap-3 text-[11px] text-ink-faint">
          <span className="inline-flex items-center gap-1.5"><Icon name="lock" size={12} /> 托管配置加密存储</span>
          <span className="mono">{data.managed?.file || ''}</span>
          <span>{data.managed?.encrypted || ''}</span>
          <span>密钥与 header 值不会回显</span>
        </div>
      </div>

      <ProviderForm
        open={Boolean(editing)}
        mode={editing?.mode || 'create'}
        initial={editing?.initial || null}
        onClose={() => setEditing(null)}
        onSubmit={save}
        busy={saving}
        error={formError}
      />

      <ConfirmDialog
        open={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        onConfirm={remove}
        title={`删除 Provider「${confirmDelete?.name || ''}」`}
        description={confirmDelete?.overrides_env
          ? '这是覆盖环境变量配置的托管项。删除后，同名环境变量 Provider 会重新生效。'
          : '删除后该 Provider 的模型将立即不可用；已发出的请求不受影响。'}
        confirmLabel="删除"
        danger
        busy={deleting}
      />
    </div>
  )
}
