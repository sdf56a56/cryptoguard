# LLM 安全中间件 —— 测试文档

> 配套 [MIDDLEWARE.md](MIDDLEWARE.md)。本文说明**怎么跑、每个文件测什么、哪些没跑、为什么**,
> 以及测试**不能**证明什么。

## 1. 运行

```bash
cd backend
python -m pytest tests -q                 # 全量(离线、无外网、无费用)
python -m pytest tests/mw -q              # 只跑中间件这一层
python -m pytest tests/mw/test_stream_boundaries.py -q
python -m pytest tests -q -p no:randomly  # 关掉随机顺序(复现失败时用)
```

最近一次全量结果(Windows 11 / Python 3.12 / pytest 8.3.3,2026-10-14):

```
583 collected → 581 passed, 2 skipped, 0 failed   (~106s)
```

**两个跳过都是有意为之**,且都是「真实厂商联调」这一类,不是失败:

| 位置 | 原因 |
|---|---|
| `tests/mw/test_real_http_e2e.py::test_real_vendor_upstream_opt_in` | 需要显式设置 `CG_REAL_UPSTREAM_KEY` / `CG_REAL_UPSTREAM_URL` / `CG_REAL_MODEL` 才执行;自动化测试不依赖外网、不产生任何费用 |
| `tests/mw/test_upstream_provider.py::test_real_upstream_placeholder` | 占位说明:真实上游密钥不在仓库内,联调需另行配置 |

## 2. 测试文件与覆盖点

| 文件 | 用例 | 覆盖 |
|---|---|---|
| `tests/mw/conftest.py` | — | 离线装配夹具:临时数据目录、客户端密钥、管理员令牌、真上游中间件工厂 |
| `tests/mw/test_mode_a_placeholder.py` | 17 | 模式 A:出站无原文、占位符仅在本请求上下文还原、伪造占位符不触发还原、重复/多实体/跨字段不打乱映射、上游返回的未知占位符不还原、错误/超时/重试/流式不误还原、跨请求与跨客户端隔离 |
| `tests/mw/test_mode_b_token.py` | 18 | 模式 B:令牌不可预测/不可伪造、映射绑定客户端与请求、伪造/篡改/过期/未知令牌被拒收、A 不能还原 B 的令牌、跨请求不复用、错误与审计不泄漏明文、`/v1/verify` 与管理接口不是推断预言机、映射生命周期与清理 |
| `tests/mw/test_mode_c_encrypt.py` | 18 | 模式 C:AES-256-GCM 参数(256 位密钥 / 96 位随机 nonce)、同钥不复用 nonce、篡改密文/nonce/标签/AAD 被拒、错误密钥/缺失字段/畸形密文/非法编码不泄漏明文、密钥派生与轮换、**绝不**记录密钥或可解材料 |
| `tests/mw/test_gateway_chain.py` | 32 | 网关主链路:请求/响应摘要(JCS)、策略合成只收紧不放松、限流与并发、审计字段、鉴权先于限流先于上游、Anthropic 协议适配 |
| `tests/mw/test_upstream_provider.py` | 63 | 上游适配:超时/重试/错误分类、响应头白名单、连接池、`MockTransport` 与真实 HTTP 共用同一套断言 |
| `tests/mw/test_confirmations.py` | 21 | 人工确认:状态机全流程、所有者绑定、客户端不能自批、无管理员令牌则 503、`acknowledged` ≠ 批准、伪造/跨请求/过期/复用凭据失败、多令牌全有或全无、审计只记令牌 |
| `tests/mw/test_real_http_e2e.py` | 21(+1 跳过) | **真实 socket 与真实 HTTP** 的上游(本机 ThreadingHTTPServer):出站原始字节无原文(三模式)、回声上游证明「上游手里没有原文」、流式与非流式一致、错误/超时/重试下不泄漏、上游密钥与客户端密钥独立、审计/验证/磁盘全链路无原文、客户端用**自己收到的响应体**可复算响应摘要(上游自述 model 名与请求名不同时也成立) |
| `tests/mw/test_stream_boundaries.py` | 24 | 流式边界:令牌跨块重组(9 组切分方式)、UTF-8 多字节跨块不损坏、SSE 事件边界/usage/`[DONE]`、有界缓冲与响应侧扫描、断流如实标注、取消即关闭上游生成器、并发流与并发确认互不串味 |
| `tests/mw/test_verification_audit.py` | 38 | 验证与审计:有效记录可验证、三个结论互相独立、篡改/删除/重排/重放被检出、工具调用的 `name`/`arguments` 在响应摘要覆盖范围内(改参数必检出)、MAC 密钥域分离、并发写入、进程重启接链、异常退出 fail-closed、验证接口不是明文/映射预言机 |
| `tests/mw/test_agent_clients.py` | 15 | **Agent 客户端接入**(第 5 阶段):OpenAI 兼容形状(`Bearer` 与 `x-api-key`、非流式/流式/工具调用)与 Anthropic 形状(`/v1/messages`、系统提示、分块 content、tool_use→tool_result 回合、流式事件名与顺序)在**真实 socket 的真实 HTTP 上游**上跑通;上游原始字节无原文、审计与 `/v1/verify` 完整且客户端可自证、篡改必检出、鉴权失败 401 且不触达上游、未知模型 404、上游 429 分类映射;并把两处**明确缺口**钉成可执行事实(`/v1/responses` 与 `/v1/messages/count_tokens` 均返回显式 404) |
| `tests/mw/test_concurrent_store_access.py` | 3 | **并发读写客户端密钥存储**(第 5 阶段实测发现的既有缺陷的回归):确定性地把一次 `last_used` 写拆成两段,验证并发读不会把「写到一半」误判成存储损坏;反证真正损坏的存储仍然 fail-closed;不同密钥的并发首请求全部 200 |

## 3. 「真实 HTTP」是怎么做的(任务 5)

关键手法是**回声上游(EchoUpstream)**:一个真实的本机 HTTP 服务,把「它实际收到的
最后一条用户消息」原样回显成回答。于是「响应里能否还原出原文」只取决于「上游手里
有没有原文」:

- 上游收到令牌 → 回显令牌 → 本地还原出白名单类别的明文;
- 上游收到原文 → 回显原文 → 断言立刻失败(证明脱敏没做)。

这是**反证**:不让上游「配合保护数据」,而是证明它根本拿不到数据。上游服务端记录的
原始请求字节(路径 + 头 + body)是独立观察面,断言在其中搜索不到任何原始值。

**诚实声明**:本套件**从未**访问任何真实模型服务商。自动化测试用的是本机回环的
自建 HTTP 服务,因此不得把本套件的结果表述为「已在真实厂商上验证」。真实厂商连通性
是一个显式可选、默认跳过的用例。

## 4. 复现某个失败

```bash
# 单文件
python -m pytest tests/mw/test_verification_audit.py -q -p no:randomly
# 单用例
python -m pytest "tests/mw/test_verification_audit.py::test_deleted_record_is_detected" -q
```

测试全部使用 `tmp_path` 下的临时数据目录与临时 bootstrap 密钥文件:客户端密钥、审计
日志、确认记录、映射金库、密钥指纹都落在临时目录里,**不写仓库的 `data/`,也不写
`backend/.env`**;`VAULT_KEY` 只是从 `backend/.env` 读取(该文件在首次启动时就已生成,
测试只读不写)。

## 5. 本套件不能证明什么

- **不能**证明「系统绝对安全」:通过只说明这些用例在这些实现路径上成立;
- **不能**证明上游服务商身份(哈希/HMAC 只能证明本地网关写下的内容未被改动);
- **不能**防持 `VAULT_KEY` 者的整链重写与尾段截断(用例外明确固定了这两条边界);
- **不能**替代真实厂商联调与人工双盲评测(本阶段均未执行);
- **不能**覆盖多进程/多实例部署下的状态一致性(确认凭据、限流、金库均为进程内)。
