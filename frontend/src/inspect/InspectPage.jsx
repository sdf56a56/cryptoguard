import { Link, useParams } from 'react-router-dom'

// /inspect/:messageId?(占位壳,Task 15 落地双视角查看器:隐私视角/审计视角 + 六失败态)
export default function InspectPage() {
  const { messageId } = useParams()
  return (
    <div className="mx-auto max-w-[1280px] px-6 py-10">
      <h1 className="display text-[24px] font-bold text-ink">查看器 · 双视角</h1>
      {messageId ? (
        <p className="mt-3 text-sm text-ink-soft">
          消息定位:<span className="mono text-ink bg-vault-50 px-2 py-0.5 rounded border border-vault-100">{messageId}</span>
        </p>
      ) : (
        <p className="mt-3 text-sm text-ink-soft">从对话气泡的「查看过程」进入单条消息,或在上方地址栏直接指定消息 id。</p>
      )}
      <p className="mt-4 text-sm text-ink-faint">
        隐私视角(加密后到底发给了大模型什么)与审计视角(流水线时间线 / 哈希链 / Merkle 证明 / 独立复算)将在后续任务落地。
      </p>
      <Link
        to="/chat"
        className="mt-6 inline-flex items-center px-4 py-2 rounded-lg border border-line bg-surface text-sm text-ink hover:border-vault-300 hover:text-vault-700 transition-colors"
      >
        返回对话
      </Link>
    </div>
  )
}
