# 验收矩阵执行记录(spec §6.5)

> 测试环境(spec §5.3,所有性能数字的前提):
>
> | 项 | 规格 |
> |---|---|
> | CPU | AMD Ryzen 7 7735H (8C/16T) |
> | RAM | 16 GB |
> | OS | Windows 11 Home China 26200 |
> | Python | 3.13.14 (MSC v.1944, AMD64) |
> | cryptography | 43.0.1 |
> | FastAPI / uvicorn / pydantic | 0.115.0 / 0.30.6 / 2.9.2 |
> | rfc8785(JCS 主选) | 0.1.4 |
> | ff3(FF1) | 1.0.3 |
>
> 执行日期:2026-10-11。指标为该测试集与该环境上的实测值,不承诺对抗性变形输入。

## §6.5 验收矩阵(逐行实测)

| 承诺 | 验证 | 达标线 | 实测值 | 结论 |
|---|---|---|---|---|
| 准确率 >95% / 召回率 >90% / 误报率 <5% | Golden Set 400(§6.1) | 实测值 + Wilson CI(FPR ±3%) | P=0.9658 Wilson95% [0.9496, 0.9769];R=1.0000 [0.9944, 1.0000];FPR=0.0400 [0.0254, 0.0623],半宽 ±1.84%;分句单元 450(≥400) | 达标 |
| 密码开销 <20ms | PERF-BUDGET-1 | P95 | 1.55ms(本地段 = total_ms − Mock LLM 段,N=150;含检测/令牌化/JCS 哈希/四层验证/入链) | 达标 |
| 端到端 <500ms | PERF-BUDGET-2 | P95 | 101.45ms(单进程 N=150)/ 120ms(压测聚合,100 VU;含 Mock 50–100ms sleep) | 达标 |
| 吞吐 >100 QPS | PERF-BUDGET-3 | 实测 | 244.9 QPS(14519 请求 / 60s,0 失败,100 VU;8 worker 多进程 + run_in_executor 线程池) | 达标 |
| 防重放 5 分钟窗 | SEC-ATK-2 + 假时钟边界 | 窗内拒/窗外拒 | SEC-ATK-2 PASS(旧 nonce 重放被层1拒);nonce/timestamp 同源绑定进 input_hash/response_hash。5 分钟窗已强制执行(层 1 `within_freshness_window`:\|now−ts\| ≤ 300s,超窗即拒);边界单测覆盖(300s 界上放行/301s 拒);在路径检查经纯函数单测覆盖(backend/tests/test_replay_window.py) | 达标 |
| 无伪造响应 | ProVerif 查询 1 + SEC-ATK-1/3/6 | RESULT 符合预期 | formal/cryptoguard.pv 六查询 + EXPECTED_RESULTS.md 预期 RESULT 已落盘(**待装 ProVerif 2.x 验证**,本机无二进制);SEC-ATK-1/3/6 全 PASS(篡改/伪 cert/令牌张冠李戴被挡) | 部分达标(等 ProVerif 实跑) |
| 出站无明文 | BIND 族 + ProVerif 查询 5 | 双重验证 | BIND-1..6 全 PASS(JCS 一致性/文件一字节偷换/override 诬告证伪等);`query attacker(plain_secret)` 预期 `not attacker(plain_secret) is true.`(待装 ProVerif 实跑) | 部分达标(等 ProVerif 实跑) |
| 回答质量下降 <5% | 双盲人工评 50 题 Likert 5 级 | 均分差 <5% | **未执行**——需双盲人工评卷(小样本探索性评测,评测表随提交包);机器不可替代,不造数 | 未执行 |

## Golden Set 400 指标明细(`py tests/detection_golden.py`,span 级精确匹配)

| 子集 | 规模 | TP | FP | FN |
|---|---|---|---|---|
| 模板(13 类×变体,校验位/Luhn 正反对) | 120 | 114 | 6(3 坏校验位 ID + 3 Luhn 挂卡号,有意负例) | 0 |
| 复合(病历/流水句式,实体共现嵌套) | 100 | 534 | 0 | 0 |
| 对抗负例(非敏感) | 150 | – | 18(订单号 Luhn 挂 ×10、版本号 1.2.3.4 ×8,有意触发) | – |
| 跨模态(plain/csv-row/docx-para/pdf-line) | 30 | 30 | 0 | 0 |
| **Overall** | **400** | **678** | **24** | **0** |

- FPR 分母 = 对抗负例非敏感分句单元 450(150 单元 × 3 分句),FP 分句 18、TN 432。
- Wilson 95% CI(P/R/FPR)见上表;FPR CI 半宽 ±1.84% ≤ ±3%。
- 24 个 FP 全部为**有意对抗负例**(坏校验位/坏 Luhn/似 IP 版本号),无意外误报;
  检测器低置信度(<0.6)走人工复核通道,本指标口径为严格 span 全等(不剔除低置信度)。
- 诚实边界:指标是该测试集上的实测值,不承诺同音字/零宽字符等对抗变形。
- 文件链路抽取损耗归因抽取器,不计检测器(本集为纯文本单元,单列 N/A)。

## 性能明细

| 项 | 方法 | 实测 |
|---|---|---|
| FF1 单价(PERF-FF1-1) | `ff1_unit_ms_p95(T2Cipher, 1000)` | 0.122 ms/个 ≤ 2ms,**未触发降级**;降级路径(FF1_DEGRADED + 横幅)由 backend/tests/test_perf_ff1.py 覆盖 |
| 计时条真值(PERF-TRUTH-1) | backend/tests/test_perf_truth.py 双断言 | PASS(duration_ms 2 位小数同源;raw−sent <0.01ms 量化界(双断言:raw 携带 + 差值界);mock_sleep_ms 与 LLM 段一致) |
| 泄漏标注完备(PERF-LEAK-1) | T2/T3 令牌 leak_class 同源 UI 徽章 | PASS(tokenize_entities 泄漏类别 100% 伴随令牌,UI 漏徽章即 fail——前端 vitest) |
| 吞吐/时延 | `locust -f tests/locustfile.py --headless -u 100 -t 60s` | 244.9 QPS;P50 84ms / P95 120ms / P99 150ms;0 失败 |

> 注:多 worker 仅承载吞吐;审计链/沙箱状态为单 worker 进程内状态,演示审计链用单 worker。

## 安全测试用例执行(`cd backend && py -m pytest tests/ -q`:109 passed)

| 用例组 | 文件 | 结果 |
|---|---|---|
| BIND-1..6 | backend/tests/test_bind_suite.py | 6/6 PASS(含 RFC 8785 向量 + rfc8785/canonicaljson 双库交叉) |
| SEC-ATK-1..9(5a/5b 拆分) | backend/tests/test_sec_attacks.py | 9/9 PASS(5a→输入绑定/防重放,5b→响应完整性)+ SEC-ISO-3 |
| SEC-ISO-1/2 + 九攻击注入 | backend/tests/test_sandbox.py | PASS(主链 verify 恒真、reset 逐字段还原) |
| 防重放 5 分钟窗 | backend/tests/test_replay_window.py | 5/5 PASS(时间窗纯函数边界 300/301s + fail-closed + 在路径接线) |
| PERF-TRUTH-1 | backend/tests/test_perf_truth.py | 3/3 PASS |
| 密码原语/网关/文件/流水线/API | 其余 15 个文件 | PASS(AES-GCM 篡改拒、Ed25519 负例、哈希链、FF1 逆变换+校验位、OPE 全对、Paillier、SSE、文件双通道默认拒绝、网关规则 1/2 fail-closed) |

## ProVerif(formal/)

- `formal/cryptoguard.pv`:四层协议模型,6 条合法语法查询(预期 RESULT 见 formal/EXPECTED_RESULTS.md)。
- 状态:**待装 ProVerif 2.x 验证**——Windows 开发机无 ProVerif 二进制;安装后
  `proverif formal/cryptoguard.pv | tee formal/output.txt` 原样归档。
- 字段对照:formal/FIELD_MAP.md(5 行,fun 元数 == 代码前映像字段数,双向勾稽)。

## 偏差与诚实边界

1. **压测部署形态**:gunicorn 依赖 Unix fork,Windows 开发机不可运行;本页吞吐用
   `uvicorn --workers 8` 多进程 + `run_in_executor` 线程池等价实测。Linux 部署命令
   (`gunicorn app.main:app -c gunicorn_conf.py`,workers=cpu_count())已写入 README。
2. **5 分钟防重放窗**:层 1 已强制时间窗(`within_freshness_window`,|now−ts| ≤ 300s,
   过期即拒),300/301s 边界由纯函数单测覆盖;在路径检查调用同一函数,经该纯函数单测覆盖。
3. **网关规则 2 仅对 T1 做 HMAC 复算;T2 FF1 复算未实现(spec §3.2 规则2 字面含 FF1)— 记录为已知偏差**。
4. **回答质量双盲评**:机器不可执行,留人工评卷,不造数。
5. **ProVerif**:模型与预期已归档,实跑输出待装二进制后补 formal/output.txt。
6. Golden Set FP 全部是有意对抗负例(校验位非法/似 IP 版本号),检测器不为指标调参;
   校准只动生成器句式(复合句式双帧加密实体密度)。
