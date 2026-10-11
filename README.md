# CryptoGuard · 面向大模型应用的敏感数据加密与防泄漏平台

> **CG-ABE-SSE 混合可验证隐私代理**
> 用户与大模型交互之间的保密性机制：出站自动识别敏感信息并脱敏（占位符/掩码/哈希），明文永不离开本地；
> 回程 Ed25519/SM2 签名 + nonce/input_hash + 日志哈希链 + Merkle 证明，保证「可验证、不可抵赖、可审计」。

## 一句话定位

用户与大模型对话时，本地代理自动识别敏感信息并脱敏，大模型只处理占位符；响应回程用四层可验证机制校验，验证通过后在本地还原明文。

## 核心特性（对标上线产品）

- **安全对话（旗舰）**：聊天式交互，输入时实时检测高亮 13 类敏感实体，一键发送即完成「识别 → 脱敏 → 加密 → 出站 → 四层验证 → 本地还原」全链路
- **13 类敏感实体自动识别**：姓名/身份证/银行卡/手机号/邮箱/地址/IP/URL/API Key/项目代号/组织/医疗 PHI/金融 PII，正则 + 词典 + 规则 + Luhn 校验，带置信度评分
- **3 种脱敏模式**（对标 Presidio Anonymizer）：占位符替换 / 掩码打码 / 哈希替换，策略可配置实时生效
- **四层可验证协议**：输入绑定 → 模型身份 → 响应完整 → 可审计日志，每层标注密码学归约
- **5 种攻击一键注入演示**：篡改/重放/伪造证书/改日志/诬告，逐层拦截告警
- **密码实验室**：SSE 密文搜索 / Paillier 密文统计 / Schnorr ZKP / CP-ABE 门限授权 交互演示
- **浅色「加密账本」UI**：哈希与签名以等宽收据块呈现，验证通过盖印章动效

## 目录结构

```
cryptoguard/
├── backend/                # FastAPI 真实密码学后端
│   ├── app/
│   │   ├── main.py         # 入口：API + WebSocket + 托管前端静态资源
│   │   ├── proxy.py        # 本地代理编排（四层验证协议核心）
│   │   ├── detection.py    # 敏感实体识别（正则 + 规则 + 词典）
│   │   ├── mock_llm.py     # Mock 大模型 + 攻击注入
│   │   ├── mock_auditor.py # Mock 审计机构（签发 model_cert）
│   │   ├── schemas.py      # Pydantic 数据模型
│   │   └── crypto/         # 密码学模块
│   │       ├── aead.py         # AES-GCM（真）
│   │       ├── signatures.py   # Ed25519（真）
│   │       ├── sm_crypto.py    # SM2/SM3/SM4 国密（真·纯 Python 参考实现）
│   │       ├── hashchain.py    # SHA-256 哈希链（真）
│   │       ├── merkle.py       # Merkle 树 + 证明（真）
│   │       ├── abe.py          # CP-ABE（教学级：Shamir 门限共享）
│   │       ├── sse.py          # SSE 密文索引（真 PRF 方案）
│   │       ├── he.py           # Paillier 同态加密（真·纯数学）
│   │       └── zkp.py          # Schnorr ZKP（真·离散对数）
│   └── requirements.txt
├── frontend/               # React + Vite + Tailwind + ECharts + Framer Motion
│   └── src/pages/          # 10 个页面
└── README.md
```

## 快速启动

### 方式一：单端口演示（推荐，用于答辩）

```bash
# 1. 安装后端依赖
cd backend
pip install -r requirements.txt

# 2. 构建前端
cd ../frontend
npm install
npm run build

# 3. 启动（后端托管前端静态资源）
cd ../backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

浏览器打开 http://localhost:8000

### 方式二：开发模式（前后端分离，热更新）

```bash
# 终端 1：后端
cd backend && python -m uvicorn app.main:app --reload --port 8000

# 终端 2：前端
cd frontend && npm run dev   # http://localhost:5173（已配置代理到 8000）
```

## 核心安全机制

### 四层可验证协议

| 层 | 名称 | 公式 |
|---|---|---|
| 1 | 输入绑定 | `input_hash = H(脱敏输入)` + `nonce` + `timestamp` |
| 2 | 模型身份 | `model_cert = Sign(sk_auditor, model_id‖version‖release_date‖model_hash)` |
| 3 | 响应完整 | `response_hash = H(output‖input_hash‖cert‖nonce‖ts)`；`sig = Sign(sk_provider, response_hash)` |
| 4 | 可审计日志 | `log_entry_i = H(req_digest‖resp_digest‖ts‖log_entry_{i-1})` + Merkle 根 |

### 密码学模块：实现级别与归约

| 模块 | 级别 | 归约 / 依据 |
|---|---|---|
| AES-GCM | 真 | IND-CPA + INT-CTXT，NIST 认可 |
| Ed25519 / SM2-SM3-SM4 | 真 | EUF-CMA，归约到 ECDLP |
| SHA-256 / HMAC / nonce | 真 | 抗碰撞 / PRF |
| 哈希链 / Merkle | 真 | 抗第二原像性 |
| Paillier 同态 | 真（512-bit 演示） | 归约到 DCR |
| SSE 密文索引 | 真 PRF 方案 | 归约到 HMAC PRF 安全 |
| CP-ABE | 教学级（Shamir 门限共享） | 信息论安全（非配对群 CP-ABE） |
| ZKP | 真（Schnorr + Fiat-Shamir） | 归约到 DLOG + ROM |

> **诚实边界（答辩加分项）**：完整 CP-ABE 依赖双线性配对（Python 3.13 无稳定库），
> 本作品用 Shamir 门限共享实现等价授权语义；ZKP 用 Schnorr 而非 zk-SNARK。
> 每个模块的「安全目标 / 归约 / 不承诺」均在代码注释与 `CryptoLab` 页面明确标注。

### 明确不承诺

- 不证明大模型内部实际计算了什么（非 zkML）
- 不承诺防服务商主动调包（除非加 TEE）
- 不承诺防服务商偷懒计算

## 5 种攻击演示

| 攻击 | 注入方式 | 拦截机制 |
|---|---|---|
| 篡改响应 | 中间人改输出 | response_hash 校验失败 |
| 重放旧响应 | 复用旧 nonce | nonce 校验失败 |
| 伪造模型声明 | 伪造 model_cert | 审计签名失败 |
| 篡改日志 | 改日志条目 | Merkle 证明失败 |
| 用户诬告 | 声称错误输入 | input_hash 双向绑定失败 |

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| POST | `/api/detect` | 敏感实体识别（支持 mode：placeholder/mask/hash） |
| POST | `/api/proxy/query` | 完整流水线（可带 attack/attributes） |
| GET | `/api/entities` | 实体类型目录（13 类，含敏感度/识别方法） |
| GET/POST | `/api/policy` | 策略配置（脱敏模式 + 启用实体类型） |
| GET | `/api/stats` | 运行统计（查询数/保护实体数/拦截攻击/延迟） |
| GET | `/api/logs` | 审计日志（哈希链 + Merkle） |
| POST | `/api/logs/tamper` | 篡改日志演示 |
| POST | `/api/sse/search` | SSE 密文检索 |
| POST | `/api/he/stats` | Paillier 密文统计 |
| GET | `/api/zkp/info` | ZKP 证明与验证 |
| GET | `/api/perf` | 性能预算与密钥信息 |
| WS | `/ws/pipeline` | WebSocket 实时流水线推送 |

## 答辩主线

> 我们不证明大模型内部算了什么，而是解决一个可落地的问题：当用户把计算委托给诚实但可审计的 AI 服务商时，如何用 CG-ABE-SSE 保护出站敏感数据，用四层可验证机制保证回程响应完整性、输入绑定、不可抵赖和可审计。每一层都有明确归约，每一个承诺都做得到。
