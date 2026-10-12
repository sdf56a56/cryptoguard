import Console from '../console/Console.jsx'
import { Badge } from '../components/ui.jsx'

// /demo(spec §4.3):现有六步控制台原样迁入,零重写;仅加「演示沙箱」徽章 + 顶栏提示。
// 「验收清单」抽屉由 Task 16 落地。
export default function DemoPage() {
  return (
    <div>
      <div className="border-b border-warn/30 bg-warn-soft">
        <div className="mx-auto max-w-[1280px] px-6 py-2 flex items-center gap-3">
          <Badge color="warn">演示沙箱</Badge>
          <span className="text-xs text-warn">此模式写入沙箱链,不影响真实审计数据</span>
        </div>
      </div>
      <Console />
    </div>
  )
}
