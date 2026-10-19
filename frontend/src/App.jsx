import { Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './components/AppShell.jsx'
import { ErrorState, Spinner, Button } from './components/ui.jsx'
import { useAuth } from './auth/AuthContext.jsx'
import LoginPage from './auth/LoginPage.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Requests from './pages/Requests.jsx'
import RequestDetail from './pages/RequestDetail.jsx'
import Confirmations from './pages/Confirmations.jsx'
import Clients from './pages/Clients.jsx'
import Upstreams from './pages/Upstreams.jsx'
import Policies from './pages/Policies.jsx'
import Playground from './pages/Playground.jsx'

function Protected() {
  const { status, error, retry, logout } = useAuth()

  if (status === 'checking') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas">
        <div className="flex items-center gap-3 text-[13px] text-ink-soft">
          <Spinner size={18} />
          正在校验管理员令牌…
        </div>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
        <div className="w-full max-w-lg rounded-lg border border-line bg-surface p-6 shadow-card">
          <ErrorState error={error} onRetry={retry} />
          <div className="mt-2 flex justify-center">
            <Button variant="ghost" size="sm" onClick={logout}>返回登录</Button>
          </div>
        </div>
      </div>
    )
  }

  if (status !== 'authenticated') return <Navigate to="/login" replace />
  return <AppShell />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Protected />}>
        <Route index element={<Dashboard />} />
        <Route path="requests" element={<Requests />} />
        <Route path="requests/:rid" element={<RequestDetail />} />
        <Route path="confirmations" element={<Confirmations />} />
        <Route path="clients" element={<Clients />} />
        <Route path="upstreams" element={<Upstreams />} />
        <Route path="policies" element={<Policies />} />
        <Route path="playground" element={<Playground />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
