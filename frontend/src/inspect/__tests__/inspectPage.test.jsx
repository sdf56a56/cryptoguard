import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import InspectPage from '../InspectPage.jsx'
import RecentMessages from '../RecentMessages.jsx'

// 直接 URL(无 id):显示「最近消息」选择列表(验收①直达路径)
test('InspectPage 无 id:渲染「最近消息」选择列表', () => {
  const html = renderToStaticMarkup(
    <MemoryRouter initialEntries={['/inspect']}>
      <Routes>
        <Route path="/inspect" element={<InspectPage />} />
      </Routes>
    </MemoryRouter>,
  )
  expect(html).toContain('最近消息')
})

// 有 id:先出骨架屏(载入中),视角 Tab 与定位条随数据渲染
test('InspectPage 有 id:载入骨架屏 + 视角 Tab 入口', () => {
  const html = renderToStaticMarkup(
    <MemoryRouter initialEntries={['/inspect/msg_user1']}>
      <Routes>
        <Route path="/inspect/:messageId" element={<InspectPage />} />
      </Routes>
    </MemoryRouter>,
  )
  expect(html).toContain('载入中')
  expect(html).toContain('隐私视角')
  expect(html).toContain('审计视角')
})

// 最近消息列表:每条可点击进入 /inspect/:id
test('RecentMessages:列表行链接到 /inspect/:id(会话/角色/时间)', () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <RecentMessages
        items={[
          {
            id: 'msg_a',
            session_id: 'sess_1',
            title: '会话甲',
            role: 'user',
            ts: '2026-10-12T10:00:00+00:00',
            snippet: '患者[NAME#a1b2c3d4]…',
          },
          {
            id: 'msg_b',
            session_id: 'sess_1',
            title: '会话甲',
            role: 'assistant',
            ts: '2026-10-12T10:00:03+00:00',
            snippet: '已为患者建立随访…',
          },
        ]}
      />
    </MemoryRouter>,
  )
  expect(html).toContain('/inspect/msg_a')
  expect(html).toContain('/inspect/msg_b')
  expect(html).toContain('会话甲')
  expect(html).toContain('user')
  expect(html).toContain('2026-10-12')
})

test('RecentMessages:空态与载入态', () => {
  const empty = renderToStaticMarkup(
    <MemoryRouter>
      <RecentMessages items={[]} />
    </MemoryRouter>,
  )
  expect(empty).toContain('暂无消息')
  const loading = renderToStaticMarkup(
    <MemoryRouter>
      <RecentMessages loading />
    </MemoryRouter>,
  )
  expect(loading).toContain('载入中')
})
