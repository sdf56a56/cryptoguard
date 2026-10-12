import { Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./AppShell.jsx";
import ChatPage from "./chat/ChatPage.jsx";
import InspectPage from "./inspect/InspectPage.jsx";
import DemoPage from "./demo/DemoPage.jsx";

// 三路由(spec §4.0):/chat(默认)、/inspect/:messageId?、/demo(现有 Console 沙箱壳)
export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Navigate to="/chat" replace />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/inspect/:messageId" element={<InspectPage />} />
        <Route path="/inspect" element={<InspectPage />} />
        <Route path="/demo" element={<DemoPage />} />
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Route>
    </Routes>
  );
}
