import { useState } from 'react'
import Console from '../console/Console.jsx'
import AcceptanceDrawer from './AcceptanceDrawer.jsx'
import { Badge } from '../components/ui.jsx'

// /demo(spec §4.3):现有六步控制台原样迁入,零重写;仅加「演示沙箱」徽章 +
// 顶栏提示 + 「验收清单」抽屉(spec §6.3)。
export default function DemoPage() {
  const [drawerOpen, setDrawerOpen] = useState(false)
  return (
    <div>
      <div className="border-b border-warn/30 bg-warn-soft">
        <div className="mx-auto max-w-[1280px] px-6 py-2 flex items-center gap-3">
          <Badge color="warn">演示沙箱</Badge>
          <span className="text-xs text-warn">此模式写入沙箱链,不影响真实审计数据</span>
          <button
            onClick={() => setDrawerOpen(true)}
            className="ml-auto px-3 py-1.5 rounded-lg border border-warn/40 bg-surface text-[12px] font-medium text-warn hover:border-warn hover:text-warn"
          >
            验收清单 ▾
          </button>
        </div>
      </div>
      <div id="demo-console">
        <Console />
      </div>
      <AcceptanceDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  )
}
