import { PageHeader, Card, Badge } from '../components/ui'

const MAP = [
  { clause: 'HIPAA §164.312(e)(1)', req: '传输安全：保护传输中的电子 PHI', module: 'AES-256-GCM 加密 + 脱敏', icon: '🔐', algo: 'AES-GCM' },
  { clause: 'HIPAA §164.312(a)(1)', req: '访问控制：唯一用户标识 + 授权', module: 'CP-ABE 细粒度授权', icon: '🔑', algo: 'Shamir SS' },
  { clause: 'HIPAA §164.312(b)', req: '审计控制：记录并检查信息系统活动', module: '哈希链 + Merkle 审计', icon: '🔗', algo: 'SHA-256' },
  { clause: 'HIPAA §164.312(c)(1)', req: '完整性：防止信息被不当篡改', module: 'response_hash + Ed25519 签名', icon: '✓', algo: 'EUF-CMA' },
  { clause: 'PCI-DSS 3.4', req: '存储的持卡人数据不可读', module: '脱敏 + 占位符替换', icon: '✂️', algo: 'Placeholder' },
  { clause: 'PCI-DSS 4.1', req: '通过开放网络传输数据需加密', module: 'AES-GCM / SM4 国密', icon: '🔒', algo: 'SM4' },
  { clause: 'PCI-DSS 10', req: '跟踪和监控对系统组件的访问', module: '日志哈希链 + nonce', icon: '📋', algo: 'HashChain' },
  { clause: 'GB/T 35273', req: '个人信息去标识化与传输安全', module: '脱敏 + 国密 SM2/SM4', icon: '🇨🇳', algo: 'SM2/SM4' },
]

export default function Compliance() {
  return (
    <div>
      <PageHeader icon="📜" title="合规映射" subtitle="密码学机制 → HIPAA / PCI-DSS / GB/T 35273 条款的对应关系" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <div className="grid grid-cols-1 gap-2">
          {MAP.map((m, i) => (
            <div key={m.clause} className="flex items-center gap-4 p-4 rounded-xl border border-line bg-surface shadow-card hover:border-vault-200 hover:shadow-lift transition-all">
              <span className="h-10 w-10 rounded-xl bg-paper border border-line flex items-center justify-center text-lg">{m.icon}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-bold text-vault-700 mono">{m.clause}</span>
                  <span className="mono text-[9px] px-1.5 py-0.5 rounded bg-vault-50 text-vault-600 border border-vault-100">{m.algo}</span>
                </div>
                <div className="text-[13px] text-ink mt-0.5">{m.req}</div>
              </div>
              <Badge color="violet">{m.module}</Badge>
              <Badge color="ok" icon="✓">满足</Badge>
            </div>
          ))}
        </div>

        <Card title="合规说明" icon="ℹ️" accent="vault">
          <p className="text-[13px] text-ink-soft leading-relaxed">
            CryptoGuard 通过「自动识别脱敏 + 加密传输 + 可验证回程 + 可审计日志」四条技术路线，
            映射到医疗（HIPAA）、金融（PCI-DSS）与个人信息保护（GB/T 35273）的核心条款。
            每条映射均标注对应的密码学原语与安全性质（如 AES-GCM 的 IND-CPA、Ed25519 的 EUF-CMA）。
            本映射用于竞赛演示，正式合规需配合完整制度与第三方评估，不构成法律合规承诺。
          </p>
        </Card>
      </div>
    </div>
  )
}
