import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 控制台与网关分开运行：浏览器只访问 Vite（同源），由 Vite 把网关路径代理到
// 后端。这样不需要给后端挂 CORS，也不需要恢复 SPA 静态托管。
const target = process.env.CG_API_TARGET || 'http://127.0.0.1:8100'
const proxy = {
  '/health': target,
  '/ready': target,
  '/metrics': target,
  '/v1': target,
  '/admin': target,
}

export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true, proxy },
})
