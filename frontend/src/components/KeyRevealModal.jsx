import { useEffect, useState } from 'react'
import { Button, Checkbox, CopyButton, Modal } from './ui.jsx'

/**
 * 客户端密钥只显示一次。关闭前必须勾选「我已保存」，避免误关后无法找回。
 */
export default function KeyRevealModal({ open, apiKey, title = '客户端密钥', onClose }) {
  const [confirmed, setConfirmed] = useState(false)
  const [hint, setHint] = useState(false)

  useEffect(() => {
    if (open) {
      setConfirmed(false)
      setHint(false)
    }
  }, [open])

  const close = () => {
    if (!confirmed) {
      setHint(true)
      return
    }
    onClose?.()
  }

  return (
    <Modal
      open={open}
      onClose={close}
      title={title}
      description="完整密钥只显示这一次。服务端只保存 HMAC 摘要，关闭后无法找回。"
      size="md"
      footer={(
        <Button variant="primary" disabled={!confirmed} onClick={close}>
          我已保存，关闭
        </Button>
      )}
    >
      <div className="rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12px] leading-5 text-warn">
        不要写入日志、截图、聊天记录或代码仓库。客户端密钥等同于该客户端的调用身份。
      </div>
      <div className="mt-3 flex items-start gap-2 rounded-md border border-line bg-canvas p-3">
        <code className="mono min-w-0 flex-1 break-all text-[12.5px] leading-5 text-ink">
          {apiKey || '—'}
        </code>
        <CopyButton value={apiKey} label="复制密钥" />
      </div>
      <Checkbox
        className="mt-3"
        label="我已保存该密钥"
        checked={confirmed}
        onChange={(event) => setConfirmed(event.target.checked)}
      />
      {hint && !confirmed ? (
        <p className="mt-2 text-[11.5px] text-bad">请先勾选「我已保存」，再关闭弹窗。</p>
      ) : null}
    </Modal>
  )
}
