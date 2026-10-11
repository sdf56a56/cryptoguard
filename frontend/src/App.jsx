import { Routes, Route } from "react-router-dom";
import Console from "./console/Console.jsx";

// 单路由 /console(spec §4.0 一路由 · 六步 · 一抽屉):旧 12 页已收敛
export default function App() {
  return (
    <Routes>
      <Route path="/console" element={<Console />} />
      <Route path="*" element={<Console />} />
    </Routes>
  );
}
