# ProVerif 查询与预期结果(formal/cryptoguard.pv)

> 状态:**待装 ProVerif 2.x 验证** —— 本机为 Windows 开发环境,未安装 ProVerif 二进制;
> 模型已按 spec §6.4-C 合法语法落盘,查询与预期 RESULT 一一列出。
> 安装后执行 `proverif formal/cryptoguard.pv | tee formal/output.txt`,
> 以实装版本输出为准原样归档(部分版本对不可达事件输出 `is false.` 形态,同为通过)。

模型覆盖:层1 输入绑定 / 层2 model_cert / 层3 响应签名 + 域分隔 / 层4 哈希链 /
防重放(nonce 单次使用状态)。不建模:NLP 检测质量、T3 声明泄漏、T4 与计算网关、
侧信道、密钥托管、OCR、服务商主动调包(spec §6.4-A 诚实边界)。

## 六条查询与预期

| # | 查询(合法语法) | 预期 RESULT | 人话解释 |
|---|---|---|---|
| 1 | `query attacker(sk_provider).` | `RESULT not attacker(sk_provider) is true.` | 攻击者拿不到服务商私钥,伪造不出合法响应签名 |
| 1b | `query x: bitstring; event(resp_accept(x)) ==> event(provider_sign(x)).` | `RESULT event(resp_accept(x)) ==> event(provider_sign(x)) is true.` | 每个被接受的响应,服务商都真的签过(EUF-CMA 归约) |
| 2 | `query x: bitstring; event(cert_accept(x)) ==> event(cert_issued(x)).` | `RESULT event(cert_accept(x)) ==> event(cert_issued(x)) is true.` | 伪造模型声明不可达:接受的 cert 必出自审计机构签发 |
| 3 | `query n: bitstring; event(nonce_reused(n)).` | `RESULT not event(nonce_reused(n)) is true.` | nonce 单次使用:同一 nonce 被接受两次不可达,重放被挡 |
| 4 | `query attacker(vault_key).` | `RESULT not attacker(vault_key) is true.` | 映射表保险库密钥不出本地 |
| 5 | `query attacker(plain_secret).` | `RESULT not attacker(plain_secret) is true.` | 出站包只有令牌/哈希,明文敏感数据不上线 |

注:
- 查询 3 部分 ProVerif 版本输出 `RESULT event(nonce_reused(n)) is false.` —— 同为通过。
- 模型内 nonce 状态表 `acceptedNonce` 在接受侧 `insert`/`get` 查复用,
  `get` 命中即 `event nonce_reused`(实现语义:get 命中分支仅在单次使用纪律被打破时可达,
  `new nonce` 新鲜性使其不可达)。
- 时间窗(5 分钟)在模型中以 nonce 新鲜性 + response_hash 绑定 `ts` 表达,
  时钟不建模(不承诺时钟偏移下的行为)。
