# CryptoGuard 控制台

面向单进程安全中转网关的运维控制台（Vite + React）。与后端分开运行：浏览器只访问
Vite，由 Vite 代理 `/health`、`/ready`、`/metrics`、`/v1`、`/admin` 到网关。

## 启动

```bash
cd frontend
npm install
npm run dev          # http://127.0.0.1:5173
```

后端默认监听 `http://127.0.0.1:8100`；如不同：

```bash
CG_API_TARGET=http://127.0.0.1:9000 npm run dev
```

登录令牌就是后端的 `CG_ADMIN_TOKEN`。令牌只存当前标签页的 `sessionStorage`，
不写入 `localStorage`，也不会出现在 URL 中。

## 生产构建

```bash
npm run build        # 输出 dist/
npm run preview      # 本地预览 http://127.0.0.1:4173（同样带代理）
```

生产环境用反向代理把上面五个路径转发到网关，并把 `dist/` 作为静态站点；网关本身
不托管前端静态资源（后端测试明确禁止 SPA 挂载）。

## 页面

- `/` 概览：业务请求计数、速率、错误率、P95、敏感检出、阻断、待确认、上游健康、
  审计链尾、最近请求（只统计 `/v1/*`，控制台轮询不计入）。
- `/requests`、`/requests/:rid`：审计日志与单条详情。
- `/confirmations`：高风险数据释放申请的批准/拒绝。
- `/clients`：客户端密钥签发、编辑、轮换、撤销；完整密钥只显示一次。
- `/upstreams`：Provider 增删改、默认路由、连通性测试；API Key 加密落盘、不回显。
- `/policies`：只读策略、审计链校验、按保留期清理。
- `/playground`：用客户端密钥发一次真实请求（非流式/流式），验证保护与还原。

## 测试

```bash
npm test
npm run build
```

测试覆盖 API 错误解析、SSE 帧解析（跨块/UTF-8/畸形帧）、格式化与基础状态组件。
