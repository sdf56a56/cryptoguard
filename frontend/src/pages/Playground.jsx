import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { ApiError, parseErrorPayload } from '../api/errors.js'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  CopyButton,
  Field,
  Input,
  KeyValue,
  Mono,
  PageHeader,
  Textarea,
} from '../components/ui.jsx'
import { formatDurationMs, formatNumber, shorten } from '../utils/format.js'

function emptyResult() {
  return {
    state: 'idle',      // idle | running | ok | error | aborted
    text: '',
    reasoning: '',
    meta: null,
    usage: null,
    status: null,
    latencyMs: null,
    requestId: '',
    error: null,
  }
}

export default function Playground() {
  const policies = useResource(() => api.policies(), [])
  const models = policies.data?.models || []
  const [clientKey, setClientKey] = useState('')
  const [showKey, setShowKey] = useState(false)
  const [model, setModel] = useState('')
  const [message, setMessage] = useState('')
  const [stream, setStream] = useState(false)
  const [maxTokens, setMaxTokens] = useState('')
  const [temperature, setTemperature] = useState('')
  const [result, setResult] = useState(emptyResult)
  const abortRef = useRef(null)

  useEffect(() => {
    if (!model && models.length) setModel(models[0])
  }, [models, model])

  useEffect(() => () => abortRef.current?.abort(), [])

  const running = result.state === 'running'

  const stop = () => {
    abortRef.current?.abort()
    setResult((prev) => (prev.state === 'running' ? { ...prev, state: 'aborted' } : prev))
  }

  const send = async () => {
    if (!clientKey.trim()) {
      setResult({ ...emptyResult(), state: 'error', error: new ApiError('请先填写客户端密钥') })
      return
    }
    if (!model.trim()) {
      setResult({ ...emptyResult(), state: 'error', error: new ApiError('请选择或输入模型') })
      return
    }
    if (!message.trim()) {
      setResult({ ...emptyResult(), state: 'error', error: new ApiError('请输入测试消息') })
      return
    }
    const body = {
      model: model.trim(),
      messages: [{ role: 'user', content: message }],
      stream,
    }
    if (maxTokens !== '') {
      const tokens = Number(maxTokens)
      if (!Number.isFinite(tokens) || tokens <= 0) {
        setResult({ ...emptyResult(), state: 'error', error: new ApiError('max_tokens 必须是正整数') })
        return
      }
      body.max_tokens = tokens
    }
    if (temperature !== '') {
      const value = Number(temperature)
      if (!Number.isFinite(value) || value < 0 || value > 2) {
        setResult({ ...emptyResult(), state: 'error', error: new ApiError('temperature 必须在 0..2 之间') })
        return
      }
      body.temperature = value
    }

    const controller = new AbortController()
    abortRef.current = controller
    const started = performance.now()
    setResult({ ...emptyResult(), state: 'running' })

    try {
      if (!stream) {
        const response = await fetch('/v1/chat/completions', {
          method: 'POST',
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${clientKey.trim()}`,
          },
          body: JSON.stringify(body),
        })
        const text = await response.text()
        let data = null
        try { data = JSON.parse(text) } catch { data = null }
        if (!response.ok) {
          const parsed = parseErrorPayload(data, text || `HTTP ${response.status}`)
          throw new ApiError(parsed.message, {
            status: response.status,
            kind: parsed.kind,
            requestId: parsed.requestId || response.headers.get('X-CryptoGuard-Request-ID') || '',
            body: data,
          })
        }
        setResult({
          state: 'ok',
          text: data?.choices?.[0]?.message?.content || '',
          reasoning: data?.choices?.[0]?.message?.reasoning_content || '',
          meta: data?.cryptoguard || null,
          usage: data?.usage || null,
          status: response.status,
          latencyMs: performance.now() - started,
          requestId: data?.cryptoguard?.request_id || response.headers.get('X-CryptoGuard-Request-ID') || '',
          error: null,
        })
      } else {
        let collected = ''
        let reasoning = ''
        let meta = null
        let usage = null
        let streamError = null
        await api.playground.stream(body, clientKey.trim(), controller.signal, {
          delta(chunk) {
            collected += chunk
            setResult((prev) => ({ ...prev, text: collected }))
          },
          reasoning(chunk) {
            reasoning += chunk
            setResult((prev) => ({ ...prev, reasoning }))
          },
          usage(value) { usage = value },
          meta(value) { meta = value },
          error(error) { streamError = error },
        })
        if (streamError) throw streamError
        setResult({
          state: 'ok',
          text: collected,
          reasoning,
          meta,
          usage,
          status: 200,
          latencyMs: performance.now() - started,
          requestId: meta?.request_id || '',
          error: null,
        })
      }
    } catch (error) {
      if (error?.name === 'AbortError') {
        setResult((prev) => ({ ...prev, state: 'aborted', latencyMs: performance.now() - started }))
        return
      }
      setResult((prev) => ({
        ...prev,
        state: 'error',
        error,
        status: error?.status ?? null,
        latencyMs: performance.now() - started,
        requestId: error?.requestId || prev.requestId,
      }))
    } finally {
      abortRef.current = null
    }
  }

  return (
    <div>
      <PageHeader
        title="链路测试"
        description="用客户端密钥直接调用 /v1/chat/completions，验证保护、转发、还原与审计。客户端密钥只保存在本页内存，刷新即丢失。"
      />

      <div className="grid gap-4 p-6 lg:grid-cols-2">
        <div className="space-y-4">
          <Card title="请求">
            <div className="space-y-3">
              <Field label="客户端密钥" required hint="不会写入 localStorage / sessionStorage">
                <div className="flex gap-2">
                  <Input
                    type={showKey ? 'text' : 'password'}
                    autoComplete="off"
                    mono
                    value={clientKey}
                    onChange={(event) => setClientKey(event.target.value)}
                    placeholder="cgk_..."
                  />
                  <Button size="md" variant="secondary" icon={showKey ? 'eyeOff' : 'eye'}
                    onClick={() => setShowKey((value) => !value)}>
                    {showKey ? '隐藏' : '显示'}
                  </Button>
                </div>
              </Field>

              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="模型" required>
                  <Input list="playground-models" mono value={model}
                    onChange={(event) => setModel(event.target.value)}
                    placeholder="deepseek-chat" />
                  <datalist id="playground-models">
                    {models.map((item) => <option key={item} value={item} />)}
                  </datalist>
                </Field>
                <Field label="max_tokens" hint="可选">
                  <Input type="number" min="1" value={maxTokens}
                    onChange={(event) => setMaxTokens(event.target.value)} placeholder="默认" />
                </Field>
              </div>

              <Field label="消息" required>
                <Textarea rows={6} value={message}
                  onChange={(event) => setMessage(event.target.value)}
                  placeholder="输入一段测试文本…" />
              </Field>

              <div className="flex flex-wrap items-end gap-3">
                <Field label="temperature" hint="0..2，可选" className="w-[150px]">
                  <Input type="number" min="0" max="2" step="0.1" value={temperature}
                    onChange={(event) => setTemperature(event.target.value)} placeholder="默认" />
                </Field>
                <div className="pb-2">
                  <Checkbox label="流式（SSE）" checked={stream}
                    onChange={(event) => setStream(event.target.checked)} />
                </div>
                <div className="ml-auto flex gap-2 pb-0.5">
                  {running ? (
                    <Button variant="danger" icon="stop" onClick={stop}>停止</Button>
                  ) : (
                    <Button variant="primary" icon="play" onClick={send}>发送请求</Button>
                  )}
                </div>
              </div>
            </div>
          </Card>

          <Card title="调用方式">
            <ul className="space-y-1.5 text-[12px] leading-5 text-ink-soft">
              <li>请求经过网关：出站检测/保护 → 上游 → 回程受控还原 → 写审计。</li>
              <li>客户端密钥只用于本次调用；模型必须在「上游配置」中声明。</li>
              <li>流式模式会展示增量文本与末帧元数据；中断后仍会留下审计记录。</li>
            </ul>
          </Card>
        </div>

        <div className="space-y-4">
          <Card
            title="响应"
            actions={result.state === 'ok' ? <Badge tone="ok" dot>成功</Badge>
              : result.state === 'error' ? <Badge tone="bad" dot>失败</Badge>
                : result.state === 'running' ? <Badge tone="accent" dot>进行中</Badge>
                  : result.state === 'aborted' ? <Badge tone="warn" dot>已停止</Badge> : null}
          >
            {result.state === 'idle' ? (
              <p className="py-8 text-center text-[12.5px] text-ink-faint">
                填写左侧表单并发送请求，结果会显示在这里。
              </p>
            ) : null}

            {result.error ? (
              <div className="rounded-md border border-bad/25 bg-bad-soft px-3 py-2">
                <p className="text-[12px] font-medium text-bad">{result.error.message}</p>
                <p className="mt-1 text-[11px] text-bad/80">
                  {result.status ? `HTTP ${result.status}` : ''}
                  {result.error.kind ? ` · ${result.error.kind}` : ''}
                </p>
              </div>
            ) : null}

            {result.state !== 'idle' && (result.state !== 'error' || result.text || result.meta) ? (
              <>
                <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-ink-faint">
                  {result.latencyMs != null ? <Badge tone="neutral">{formatDurationMs(result.latencyMs)}</Badge> : null}
                  {result.status ? <Badge tone="neutral">HTTP {result.status}</Badge> : null}
                  {result.requestId ? (
                    <span className="inline-flex items-center gap-1">
                      <span className="mono">{shorten(result.requestId, 10, 6)}</span>
                      <CopyButton value={result.requestId} label="复制" />
                    </span>
                  ) : null}
                  {result.requestId ? (
                    <Link className="text-accent-700 hover:underline"
                      to={`/requests/${encodeURIComponent(result.requestId)}`}>
                      查看审计
                    </Link>
                  ) : null}
                </div>

                {result.reasoning ? (
                  <details className="mb-3 rounded-md border border-line bg-canvas p-2">
                    <summary className="cursor-pointer text-[11.5px] text-ink-soft">推理内容</summary>
                    <pre className="mono mt-2 whitespace-pre-wrap text-[11.5px] leading-5 text-ink-soft">{result.reasoning}</pre>
                  </details>
                ) : null}

                <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap rounded-md border border-line bg-canvas p-3 text-[12px] leading-5 text-ink">
{result.text || (result.state === 'running' ? '等待首字节…' : '（空响应）')}
                </pre>

                {result.meta ? (
                  <div className="mt-3 border-t border-line/70 pt-2">
                    <div className="grid gap-x-6 sm:grid-cols-2">
                      <KeyValue label="request_id" mono>{result.meta.request_id || '—'}</KeyValue>
                      <KeyValue label="Provider"><Mono>{result.meta.provider || '—'}</Mono></KeyValue>
                      <KeyValue label="上游模型"><Mono>{result.meta.upstream_model || '—'}</Mono></KeyValue>
                      <KeyValue label="保护模式"><Mono>{result.meta.protection_mode || '—'}</Mono></KeyValue>
                      <KeyValue label="审计 seq"><Mono>{result.meta.audit?.seq ?? '—'}</Mono></KeyValue>
                      <KeyValue label="待确认">{formatNumber(result.meta.pending_confirmations || 0)}</KeyValue>
                    </div>
                    <div className="mt-2 grid gap-3 sm:grid-cols-2">
                      <div>
                        <p className="mb-1 text-[11px] font-medium text-ink-faint">检出</p>
                        <pre className="mono max-h-32 overflow-auto rounded border border-line bg-canvas p-2 text-[10.5px] leading-4 text-ink-soft">
{JSON.stringify(result.meta.detected || {}, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <p className="mb-1 text-[11px] font-medium text-ink-faint">还原</p>
                        <pre className="mono max-h-32 overflow-auto rounded border border-line bg-canvas p-2 text-[10.5px] leading-4 text-ink-soft">
{JSON.stringify(result.meta.restore || {}, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>
                ) : null}

                {result.usage && Object.keys(result.usage).length ? (
                  <div className="mt-2 text-[11px] text-ink-faint">
                    用量：{Object.entries(result.usage).map(([key, value]) => `${key}=${value}`).join(' · ')}
                  </div>
                ) : null}
              </>
            ) : null}
          </Card>
        </div>
      </div>
    </div>
  )
}
