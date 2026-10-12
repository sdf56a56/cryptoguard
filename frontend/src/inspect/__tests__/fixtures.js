// Task 15 测试夹具:形状对齐后端契约(pipeline / chain / proof / preimage),值仅供渲染断言
export const hex = (c, n = 64) => c.repeat(n)

export const outboundDump = {
  schema_version: 'CG/2.0',
  session_id: hex('a', 32),
  redacted_text: '患者[NAME#a1b2c3d4],手机[PHONE#e5f6a7b8],参加天枢计划。',
  file_payloads: [
    {
      file_ref: 'f_01',
      filename_token: '[FILE#9c0d1e2f]',
      content_tier: 'readable',
      redacted_content: '化验单摘要…',
      file_content_hash: hex('b'),
      file_hash: hex('c'),
    },
    {
      file_ref: 'f_02',
      filename_token: '[FILE#8b7a6c5d]',
      content_tier: 'evidence',
      redacted_content: null,
      file_content_hash: null,
      file_hash: hex('1'),
    },
  ],
  token_index: [
    { token: '[NAME#a1b2c3d4]', type: 'NAME', tier: 'T1', leak_class: 'equality' },
    { token: '[PHONE#e5f6a7b8]', type: 'PHONE', tier: 'T2', leak_class: 'format+equality' },
    { token: '[ID#77665544]', type: 'ID', tier: 'T3', leak_class: 'order+equality' },
    { token: '[LAB#33445566]', type: 'LAB', tier: 'T4', leak_class: 'ciphertext-shape' },
  ],
  override_events: [],
  token_root: hex('d'),
  input_hash: hex('e'),
  nonce: hex('f', 32),
  timestamp: '2026-10-12T10:00:00.000000+00:00',
  canonical_preimage: '{"d":"CG/INPUT/v2","f":[],"ih":"","n":"","o":"","r":"","t":"","ts":""}',
}

export const canonicalPreimageStr =
  '{"d":"CG/INPUT/v2","t":"' + hex('9') + '","f":[],"r":"' + hex('d') + '","o":"","n":"' + hex('f', 32) + '","ts":"2026-10-12T10:00:00.000000+00:00"}'

export const userMessage = {
  type: 'message',
  id: 'msg_user1',
  session_id: hex('a', 32),
  role: 'user',
  ts: '2026-10-12T10:00:00.000000+00:00',
  llm_view: '患者[NAME#a1b2c3d4],手机[PHONE#e5f6a7b8],参加天枢计划。',
  user_view: '患者张伟,手机13800138000,参加天枢计划。',
  mapping_delta_ct: { iv: hex('2', 12), ciphertext: hex('3', 32) },
  reasoning_ct: null,
  files: [{ name: 'report.txt', file_hash: hex('c'), channel: 'readable' }],
  chain_refs: [4, 5],
  reply_meta: { model: 'mimo', incomplete: false, degraded: null },
  verification: [
    { layer: '输入绑定/防重放', ok: true, detail: 'nonce/timestamp 与出站包一致,且落在 5 分钟时间窗内' },
    { layer: '模型身份', ok: true, detail: 'model_cert 审计签名有效' },
    { layer: '响应完整性', ok: true, detail: 'response_hash 一致且签名有效' },
    { layer: '可审计日志', ok: true, detail: '已追加哈希链条目(entry_type=QUERY)并更新 Merkle 根' },
  ],
  artifacts: {
    outbound: outboundDump,
    canonical_preimage: canonicalPreimageStr,
    tokens: outboundDump.token_index.map((t) => ({ ...t, replacement: t.token, pending: false })),
    entities: [
      { type: 'NAME', start: 3, end: 5, value_len: 2 },
      { type: 'PHONE', start: 8, end: 19, value_len: 11 },
    ],
  },
}

export const assistantMessage = {
  type: 'message',
  id: 'msg_asst1',
  session_id: hex('a', 32),
  role: 'assistant',
  ts: '2026-10-12T10:00:03.000000+00:00',
  llm_view: '已为患者[NAME#a1b2c3d4]建立随访记录。',
  user_view: '已为患者张伟建立随访记录。',
  mapping_delta_ct: { iv: hex('2', 12), ciphertext: '' },
  reasoning_ct: { iv: hex('4', 12), ciphertext: hex('5', 48) },
  files: [],
  chain_refs: [],
  reply_meta: { model: 'mimo', incomplete: false, degraded: null },
  verification: userMessage.verification,
  artifacts: { response_hash: hex('6'), signature: hex('7', 86) },
}

export const chainEntries = [
  {
    index: 3,
    entry_type: 'FILE_COMMIT',
    payload_digest: hex('1'),
    timestamp: '2026-10-12T09:59:58.000000+00:00',
    prev_hash: hex('0'),
    hash: hex('2'),
    message_id: 'msg_prev',
  },
  {
    index: 4,
    entry_type: 'QUERY',
    payload_digest: hex('e'),
    timestamp: '2026-10-12T10:00:00.000000+00:00',
    prev_hash: hex('2'),
    hash: hex('3'),
    message_id: 'msg_user1',
  },
  {
    index: 5,
    entry_type: 'RESPONSE',
    payload_digest: hex('4'),
    timestamp: '2026-10-12T10:00:03.000000+00:00',
    prev_hash: hex('3'),
    hash: hex('5'),
    message_id: 'msg_user1',
  },
]

export const proofData = {
  index: 4,
  leaf: hex('3'),
  proof: [
    { sibling: hex('9'), node_left: true },
    { sibling: hex('8'), node_left: false },
  ],
  root: hex('7'),
  verified: true,
}

export const preimageResultMatch = {
  preimage: JSON.parse(canonicalPreimageStr),
  expected_hash: hex('e'),
  recomputed_hash: hex('e'),
  match: true,
}

export const preimageResultMismatch = {
  preimage: JSON.parse(canonicalPreimageStr),
  expected_hash: hex('e'),
  recomputed_hash: hex('a'),
  match: false,
}
