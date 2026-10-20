import { request, streamChatCompletion } from './client.js'

function query(params = {}) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    search.set(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

export const api = {
  health: () => request('/health'),
  ready: () => request('/ready'),
  dashboard: () => request('/admin/dashboard'),
  policies: () => request('/admin/security/policies'),

  providers: {
    list: (opts = {}) => request('/admin/providers', opts),
    create: (payload) => request('/admin/providers', { method: 'POST', body: payload }),
    update: (name, payload) =>
      request(`/admin/providers/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        body: payload,
      }),
    remove: (name) =>
      request(`/admin/providers/${encodeURIComponent(name)}`, { method: 'DELETE' }),
    test: (name) =>
      request(`/admin/providers/${encodeURIComponent(name)}/test`, { method: 'POST' }),
    setDefaults: (defaultProvider, defaultModel) =>
      request('/admin/provider-defaults', {
        method: 'PUT',
        body: { default_provider: defaultProvider, default_model: defaultModel },
      }),
  },

  clients: {
    list: () => request('/admin/clients'),
    create: (payload) => request('/admin/clients', { method: 'POST', body: payload }),
    update: (id, payload) =>
      request(`/admin/clients/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: payload,
      }),
    revoke: (id) =>
      request(`/admin/clients/${encodeURIComponent(id)}/revoke`, { method: 'POST' }),
    rotate: (id) =>
      request(`/admin/clients/${encodeURIComponent(id)}/rotate`, { method: 'POST' }),
  },

  audit: {
    list: (params = {}) => request(`/admin/audit${query(params)}`),
    get: (requestId) =>
      request(`/admin/audit/${encodeURIComponent(requestId)}`),
    verify: (full = true) =>
      request(`/admin/audit/verify?full=${full ? 'true' : 'false'}`, {
        method: 'POST',
      }),
    purge: (dryRun = true) =>
      request(`/admin/audit/purge?dry_run=${dryRun ? 'true' : 'false'}`, {
        method: 'POST',
      }),
  },

  confirmations: {
    list: (params = {}) => request(`/admin/confirmations${query(params)}`),
    approve: (id) =>
      request(`/admin/confirmations/${encodeURIComponent(id)}/approve`, {
        method: 'POST',
      }),
    deny: (id, reason = '') =>
      request(`/admin/confirmations/${encodeURIComponent(id)}/deny`, {
        method: 'POST',
        body: { reason },
      }),
  },

  playground: {
    stream: (body, clientKey, signal, handlers) =>
      streamChatCompletion({ body, clientKey, signal, handlers }),
  },
}
