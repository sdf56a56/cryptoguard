import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import { Badge, Card, GhostButton, PageHeader, PrimaryButton } from '../components/ui.jsx'

// /settings:大模型 API 配置(Provider / Base URL / Model / API Key)
//
// 安全约束(第六阶段):
//   - API Key 只提交到本项目后端(PUT /api/llm/config),前端从不直连厂商接口;
//   - 任何时刻都不把密钥写入 localStorage/sessionStorage/URL;
//   - 后端只回显掩码(key_masked),输入框留空即表示「保持原密钥不变」。
const EMPTY_FORM = { provider: 'deepseek', base_url: '', model: '', display_name: '' }

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <div className="flex items-baseline gap-2 mb-1.5">
        <span className="text-[12px] font-semibold text-ink">{label}</span>
        {hint && <span className="text-[11px] text-ink-faint">{hint}</span>}
      </div>
      {children}
    </label>
  )
}

const inputCls =
  'w-full px-3 py-2 rounded-lg border border-line bg-surface text-[13px] text-ink mono ' +
  'focus:outline-none focus:border-vault-400 focus:ring-2 focus:ring-vault-100 transition'

export default function SettingsPage() {
  const [providers, setProviders] = useState([])
  const [saved, setSaved] = useState(null)
  const [form, setForm] = useState(EMPTY_FORM)
  const [apiKey, setApiKey] = useState('')       // 非空 = 用户输入了新密钥
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [busy, setBusy] = useState(null)         // 'save' | 'test' | 'clear'
  const [testResult, setTestResult] = useState(null)
  const [notice, setNotice] = useState(null)     // { ok, text }

  const provider = useMemo(
    () => providers.find((p) => p.id === form.provider) || null,
    [providers, form.provider],
  )

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await api.llmConfig()
      setProviders(r.providers || [])
      setSaved(r.config || null)
      const c = r.config || {}
      setForm({
        provider: c.provider || 'deepseek',
        base_url: c.base_url || '',
        model: c.model || '',
        display_name: c.display_name || '',
      })
      setApiKey('')
    } catch (e) {
      setLoadError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const patch = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  const onProviderChange = (id) => {
    const p = providers.find((x) => x.id === id)
    const isPresetDefault = !form.base_url || providers.some((x) => x.base_url === form.base_url)
    setForm((f) => ({
      ...f,
      provider: id,
      base_url: isPresetDefault ? (p?.base_url || '') : f.base_url,
      model: p?.models?.some((m) => m.id === f.model) ? f.model : (p?.models?.[0]?.id || f.model),
    }))
  }

  // 提交体:api_key 为 null 表示保持原密钥不变(后端语义)
  const payload = () => ({
    provider: form.provider,
    base_url: form.base_url,
    model: form.model,
    display_name: form.display_name,
    api_key: apiKey === '' ? null : apiKey,
  })

  const runTest = async () => {
    setBusy('test')
    setTestResult(null)
    setNotice(null)
    try {
      const r = await api.testLLM({
        base_url: form.base_url,
        model: form.model,
        api_key: apiKey === '' ? null : apiKey,
      })
      setTestResult(r)
    } catch (e) {
      setTestResult({ ok: false, category: 'internal', message: e.message || String(e) })
    } finally {
      setBusy(null)
    }
  }

  const save = async () => {
    setBusy('save')
    setNotice(null)
    try {
      const r = await api.saveLLMConfig(payload())
      setSaved(r.config)
      setApiKey('')
      setNotice({ ok: true, text: '配置已保存，对话功能立即生效（无需重启后端）' })
    } catch (e) {
      setNotice({ ok: false, text: '保存失败：' + (e.message || String(e)) })
    } finally {
      setBusy(null)
    }
  }

  const clearKey = async () => {
    setBusy('clear')
    setNotice(null)
    try {
      const r = await api.clearLLMKey()
      setSaved(r.config)
      setApiKey('')
      setTestResult(null)
      setNotice({ ok: true, text: '已清空 API Key，对话将提示需重新配置' })
    } catch (e) {
      setNotice({ ok: false, text: '清空失败：' + (e.message || String(e)) })
    } finally {
      setBusy(null)
    }
  }

  const dirty =
    apiKey !== '' ||
    !saved ||
    saved.provider !== form.provider ||
    saved.base_url !== form.base_url ||
    saved.model !== form.model ||
    (saved.display_name || '') !== form.display_name

  return (
    <div>
      <PageHeader
        title="大模型设置"
        subtitle="配置对话功能实际调用的模型接口 · 密钥仅保存在本机后端"
        icon="⚙️"
        badge={<Badge color={saved?.configured ? 'ok' : 'warn'}>
          {saved?.configured ? '已配置' : '未配置'}
        </Badge>}
      />

      <div className="mx-auto max-w-[820px] px-8 py-7 space-y-5">
        {loading && <div className="text-[13px] text-ink-faint py-10 text-center">加载配置中…</div>}
        {loadError && (
          <div className="rounded-lg border border-bad/25 bg-bad-soft px-4 py-3 text-[13px] text-bad">
            读取配置失败：{loadError}
          </div>
        )}

        {!loading && !loadError && (
          <>
            {!saved?.has_key && (
              <div className="rounded-lg border border-warn/25 bg-warn-soft px-4 py-3 text-[13px] text-warn">
                尚未配置 API Key。对话功能已 <b>fail-closed</b>：发送消息会明确提示「未配置」，
                不会用本地模拟文本冒充模型回答。
              </div>
            )}
            {saved?.has_key && saved?.env_fallback && (
              <div className="rounded-lg border border-line bg-paper px-4 py-3 text-[13px] text-ink-soft">
                当前密钥来自环境变量（.env），尚未在设置页固化。保存一次即可写入加密配置存储。
              </div>
            )}

            <Card title="接口配置" icon="🔌">
              <div className="space-y-4">
                <Field label="API Provider">
                  <select
                    className={inputCls}
                    value={form.provider}
                    onChange={(e) => onProviderChange(e.target.value)}
                  >
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>{p.label}</option>
                    ))}
                  </select>
                </Field>

                <Field label="Base URL" hint={provider?.base_url ? `预设：${provider.base_url}` : '自定义接口地址'}>
                  <input
                    className={inputCls}
                    value={form.base_url}
                    placeholder="https://api.deepseek.com"
                    onChange={(e) => patch('base_url', e.target.value)}
                  />
                </Field>

                <Field label="Model（API model ID）" hint="必须是接口真实存在的模型标识">
                  <input
                    className={inputCls}
                    list="llm-model-options"
                    value={form.model}
                    placeholder="例如 deepseek-flash"
                    onChange={(e) => patch('model', e.target.value)}
                  />
                  <datalist id="llm-model-options">
                    {(provider?.models || []).map((m) => (
                      <option key={m.id} value={m.id}>{m.label}</option>
                    ))}
                  </datalist>
                </Field>

                <Field label="显示名称（可选）" hint="仅用于界面展示，与 API model ID 分开保存">
                  <input
                    className={inputCls}
                    value={form.display_name}
                    placeholder="例如 DeepSeek V4.1 Flash"
                    onChange={(e) => patch('display_name', e.target.value)}
                  />
                </Field>

                <Field
                  label="API Key"
                  hint={saved?.has_key ? `已保存：${saved.key_masked}（留空则不修改）` : '尚未配置'}
                >
                  <input
                    className={inputCls}
                    type="password"
                    autoComplete="off"
                    value={apiKey}
                    placeholder={saved?.has_key ? '留空表示保持原密钥不变' : '粘贴你的 API Key'}
                    onChange={(e) => setApiKey(e.target.value)}
                  />
                </Field>
              </div>
            </Card>

            <Card title="连接测试" icon="🧪" accent={testResult ? (testResult.ok ? 'ok' : 'bad') : 'plain'}>
              <p className="text-[12px] text-ink-soft mb-3">
                测试会真实调用一次模型接口（minimal 请求），验证 Key、Base URL 与模型标识是否可用。
              </p>
              <div className="flex items-center gap-2.5">
                <GhostButton onClick={runTest} disabled={busy !== null} icon="🧪">
                  {busy === 'test' ? '测试中…' : '测试连接'}
                </GhostButton>
              </div>

              {testResult && (
                <div
                  className={`mt-3 rounded-lg border px-4 py-3 text-[13px] ${
                    testResult.ok
                      ? 'border-ok/25 bg-ok-soft text-ok'
                      : 'border-bad/25 bg-bad-soft text-bad'
                  }`}
                >
                  <div className="font-semibold mb-0.5">
                    {testResult.ok ? '✓ 连接成功' : '✗ 连接失败'}
                    <span className="ml-2 text-[11px] font-normal opacity-70 mono">
                      {testResult.category}
                      {testResult.status ? ` · HTTP ${testResult.status}` : ''}
                    </span>
                  </div>
                  <div className="leading-relaxed">{testResult.message}</div>
                  {testResult.model && (
                    <div className="mt-1 text-[11px] opacity-80 mono">应答模型：{testResult.model}</div>
                  )}
                </div>
              )}
            </Card>

            <div className="flex items-center gap-2.5">
              <PrimaryButton onClick={save} disabled={busy !== null || !dirty} icon="💾">
                {busy === 'save' ? '保存中…' : '保存配置'}
              </PrimaryButton>
              <GhostButton onClick={clearKey} disabled={busy !== null || !saved?.has_key} icon="🧹">
                {busy === 'clear' ? '清空中…' : '清空 API Key'}
              </GhostButton>
              <GhostButton onClick={load} disabled={busy !== null} icon="↻">重新载入</GhostButton>
            </div>

            {notice && (
              <div
                className={`rounded-lg border px-4 py-3 text-[13px] ${
                  notice.ok
                    ? 'border-ok/25 bg-ok-soft text-ok'
                    : 'border-bad/25 bg-bad-soft text-bad'
                }`}
              >
                {notice.text}
              </div>
            )}

            <Card title="安全边界" icon="🛡️" accent="plain">
              <ul className="text-[12px] text-ink-soft space-y-1.5 list-disc pl-4 leading-relaxed">
                <li>API Key 由后端加密落盘（AES-GCM，密钥由 VAULT_KEY 经 HKDF 独立派生），前端与构建产物中不含任何密钥。</li>
                <li>浏览器只与本项目后端通信，绝不携带密钥直接调用厂商接口。</li>
                <li>密钥不写入 URL、查询参数或浏览器持久化存储。</li>
                <li>接口无鉴权，仅适用于本机单用户运行；暴露到非可信网络前请自行加访问控制。</li>
              </ul>
            </Card>
          </>
        )}
      </div>
    </div>
  )
}
