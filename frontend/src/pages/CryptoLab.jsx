import { useState, useEffect } from 'react'
import { PageHeader, Card, Badge, HashLine, PrimaryButton } from '../components/ui'
import { api } from '../api'

function SSEDemo() {
  const [kw, setKw] = useState('天枢计划')
  const [res, setRes] = useState(null)
  async function search() {
    setRes(await api.sseSearch(kw))
  }
  return (
    <Card title="SSE 密文可搜索加密" icon="🔍" accent="vault">
      <p className="text-[11px] text-ink-faint mb-3">授权方可在密文索引上检索关键词，不泄露明文。令牌 = HMAC-SHA256(key, keyword)。</p>
      <div className="flex gap-2">
        <input value={kw} onChange={(e) => setKw(e.target.value)} className="flex-1 rounded-lg bg-paper border border-line px-3 py-2 text-[13px] mono outline-none focus:border-vault-400 focus:ring-2 focus:ring-vault-100 transition-all" />
        <PrimaryButton onClick={search} icon="🔍">检索</PrimaryButton>
      </div>
      {res && (
        <div className="mt-3 space-y-2">
          <div className="receipt p-2.5">
            <HashLine label="关键词令牌" value={res.token} shorten />
          </div>
          <div className="flex items-center gap-2 text-[12px]">
            <span className="text-ink-faint">命中文档</span>
            <Badge color={res.doc_ids.length ? 'ok' : 'gray'}>{res.doc_ids.length ? res.doc_ids.join(', ') : '无'}</Badge>
          </div>
        </div>
      )}
    </Card>
  )
}

function HEDemo() {
  const [res, setRes] = useState(null)
  const [vals, setVals] = useState('120, 200, 350, 88, 500')
  async function run() {
    setRes(await api.heStats(vals.split(',').map((x) => parseInt(x.trim())).filter((n) => !isNaN(n))))
  }
  return (
    <Card title="Paillier 同态加密 · 密文统计" icon="➕" accent="violet">
      <p className="text-[11px] text-ink-faint mb-3">在密文上直接求和，无需解密。E(m₁)·E(m₂) = E(m₁+m₂)，归约到 DCR 问题。</p>
      <div className="flex gap-2">
        <input value={vals} onChange={(e) => setVals(e.target.value)} className="flex-1 rounded-lg bg-paper border border-line px-3 py-2 text-[13px] mono outline-none focus:border-vault-400 focus:ring-2 focus:ring-vault-100 transition-all" />
        <PrimaryButton onClick={run} icon="Σ">密文求和</PrimaryButton>
      </div>
      {res && (
        <div className="mt-3 space-y-2">
          <div className="text-[11px] text-ink-faint">密文（每个数值的 Paillier 密文）</div>
          <div className="flex flex-wrap gap-1">
            {res.ciphertexts.slice(0, 5).map((c, i) => (
              <span key={i} className="text-[9px] mono px-1.5 py-0.5 rounded bg-vault-50 text-vault-700 border border-vault-100">{c.slice(0, 16)}…</span>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="receipt p-2.5">
              <div className="text-[10px] text-ink-faint">密文求和结果</div>
              <div className="mono text-[11px] text-vault-700 break-all">{res.encrypted_sum.slice(0, 22)}…</div>
            </div>
            <div className="receipt p-2.5 border-l-ok">
              <div className="text-[10px] text-ink-faint">解密后</div>
              <div className="display text-2xl font-bold text-ok">{res.decrypted_sum}</div>
              <div className="text-[10px] text-ink-faint">均值 {res.decrypted_mean}</div>
            </div>
          </div>
        </div>
      )}
    </Card>
  )
}

function ZKPDemo() {
  const [res, setRes] = useState(null)
  async function run() { setRes(await api.zkpInfo()) }
  useEffect(() => { run() }, [])
  return (
    <Card title="ZKP 合规证明（Schnorr + Fiat-Shamir）" icon="🧮" accent="warn">
      <p className="text-[11px] text-ink-faint mb-3">证明「持有映射表密钥」而不泄露秘密本身。零知识性归约到离散对数问题。</p>
      {res && (
        <div className="space-y-1">
          <div className="receipt p-2.5">
            <HashLine label="公钥 y = gˣ" value={res.public_y.slice(0, 34) + '…'} />
            <HashLine label="素数位宽" value={res.prime_bits + ' bit'} />
            <HashLine label="承诺 t = gᵏ" value={res.proof.commitment.slice(0, 34) + '…'} />
            <HashLine label="挑战 c = H(t)" value={res.proof.challenge.slice(0, 34) + '…'} />
            <HashLine label="响应 s = k + cx" value={res.proof.response.slice(0, 34) + '…'} />
          </div>
          <div className="flex items-center gap-2 mt-2">
            <Badge color={res.valid ? 'ok' : 'bad'} icon={res.valid ? '✓' : '✗'}>{res.valid ? '验证通过：gˢ = t·yᶜ' : '验证失败'}</Badge>
          </div>
        </div>
      )}
    </Card>
  )
}

function ABEDemo() {
  return (
    <Card title="CP-ABE 细粒度授权（Shamir 门限语义）" icon="🔑" accent="ok">
      <p className="text-[11px] text-ink-faint mb-3">策略树示例（医疗）：<span className="mono text-ok">(审计员) OR (医生 AND 心内科)</span></p>
      <div className="space-y-2">
        <div className="p-2.5 rounded-lg border border-line bg-paper">
          <div className="text-[10px] text-ink-faint mb-1.5">属性设计</div>
          <div className="flex flex-wrap gap-1.5">
            {['role:doctor', 'role:auditor', 'dept:cardiology', 'level:senior', 'role:analyst'].map((a) => (
              <Badge key={a} color="ok">{a}</Badge>
            ))}
          </div>
        </div>
        <div className="p-2.5 rounded-lg border border-line bg-paper">
          <div className="text-[10px] text-ink-faint mb-1.5">策略树结构（AND = (t=n, n) 门限；OR = (t=1, n) 门限）</div>
          <pre className="mono text-[11px] text-ok leading-relaxed">{`OR          (1-of-2 threshold)
├─ role:auditor
└─ AND       (2-of-2 threshold)
   ├─ role:doctor
   └─ dept:cardiology`}</pre>
        </div>
        <p className="text-[10px] text-ink-faint">在「密码流水线」勾选 CP-ABE 后，映射表将按该策略做门限秘密共享加密，只有属性满足策略的角色可重构密钥解密。</p>
      </div>
    </Card>
  )
}

export default function CryptoLab() {
  return (
    <div>
      <PageHeader icon="🧪" title="密码实验室" subtitle="SSE / HE / ZKP / CP-ABE 增强模块交互演示 —— 每个模块标注安全目标、归约与不承诺" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <div className="rounded-xl border border-warn/30 bg-warn-soft p-4 text-[11px] text-ink-soft leading-relaxed">
          <strong className="text-warn">⚠️ 诚实标注：</strong>
          CP-ABE 采用 Shamir 门限秘密共享实现等价授权语义（非配对群完整 CP-ABE，Python 3.13 无稳定配对库）；
          ZKP 采用 Schnorr 协议（非 zk-SNARK，无可信设置与通用电路）；HE 采用 Paillier（512-bit 演示强度，生产需 2048+）。
          每个模块的「安全目标 / 归约 / 不承诺」均在源码注释中明确。
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SSEDemo />
          <HEDemo />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ZKPDemo />
          <ABEDemo />
        </div>
      </div>
    </div>
  )
}
