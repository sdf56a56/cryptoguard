import { Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./AppShell.jsx";
import ChatPage from "./chat/ChatPage.jsx";
import InspectPage from "./inspect/InspectPage.jsx";
import DemoPage from "./demo/DemoPage.jsx";
import SettingsPage from "./settings/SettingsPage.jsx";

// 四路由:/chat(默认)、/inspect/:messageId?、/demo、/settings(大模型配置)
export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Navigate to="/chat" replace />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/inspect/:messageId" element={<InspectPage />} />
        <Route path="/inspect" element={<InspectPage />} />
        <Route path="/demo" element={<DemoPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Route>
    </Routes>
  );
}
