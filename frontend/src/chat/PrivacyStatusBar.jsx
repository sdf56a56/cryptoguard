import { Link } from 'react-router-dom'

// 隐私状态栏(spec §4.1,常驻):
// 检测引擎 ON·N类 | 通道 <真实模型> / 未配置 / Mock 降级中(黄) | 哈希链 N条·校验 | vault 状态
function Sep() {
  return <span className="text-line-strong select-none">|</span>
}

function Dot({ color }) {
  const cls = {
    ok: 'bg-ok',
    warn: 'bg-warn',
    bad: 'bg-bad',
    gray: 'bg-ink-faint',
  }[color] || 'bg-ink-faint'
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${cls}`} />
}

export default function PrivacyStatusBar({
  entityCount = null,
  chainInfo = null,
  degraded = null,
  vaultOk = false,
  llmConfig = null,
  answerModel = null,
}) {
  const chainValid = chainInfo ? chainInfo.chain_valid : null

  // 通道:优先展示真实应答模型;降级与未配置都明确标黄,不伪装成正常模型
  let channelDot = 'gray'
  let channelText = '未知'
  if (degraded) {
    channelDot = 'warn'
    channelText = 'Mock 降级中（非大模型生成）'
  } else if (llmConfig && !llmConfig.configured) {
    channelDot = 'warn'
    channelText = '未配置模型'
  } else if (llmConfig) {
    channelDot = 'ok'
    // 优先展示实际应答模型;未对话时展示配置里的显示名(而非裸 model ID)
    channelText = answerModel || llmConfig.display_name || llmConfig.model || '已配置'
  } else if (answerModel) {
    channelDot = 'ok'
    channelText = answerModel
  }

  return (
    <div className="sticky top-14 z-30 border-b border-line bg-surface/80 backdrop-blur">
      <div className="mx-auto flex max-w-[1280px] flex-wrap items-center gap-x-3 gap-y-1 px-6 py-2 text-[11px] text-ink-soft">
        <span className="inline-flex items-center gap-1.5">
          <Dot color="ok" />
          检测引擎 <b className="text-ink mono">ON·{entityCount ?? '–'}类</b>
        </span>
        <Sep />
        <span className="inline-flex items-center gap-1.5">
          <Dot color={channelDot} />
          通道{' '}
          {channelDot === 'warn' ? (
            <Link to="/settings" className="underline decoration-current underline-offset-2">
              <b className="text-warn">{channelText}</b>
            </Link>
          ) : (
            <b className="text-ink mono">{channelText}</b>
          )}
        </span>
        <Sep />
        <span className="inline-flex items-center gap-1.5">
          <Dot color={chainValid == null ? 'gray' : chainValid ? 'ok' : 'bad'} />
          哈希链{' '}
          <b className="text-ink mono">
            {chainInfo ? `${chainInfo.count}条` : '–条'}·{chainValid == null ? '无数据' : chainValid ? '校验通过' : '校验失败'}
          </b>
        </span>
        <Sep />
        <span className="inline-flex items-center gap-1.5">
          <Dot color={vaultOk ? 'ok' : 'gray'} />
          vault <b className="text-ink">{vaultOk ? '已解封' : '未连接'}</b>
        </span>
      </div>
    </div>
  )
}
