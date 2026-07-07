import { NavLink, Routes, Route, Navigate } from "react-router-dom";
import Dashboard from "./pages/Dashboard.jsx";
import DetectionResults from "./pages/DetectionResults.jsx";
import RealtimeAlerts from "./pages/RealtimeAlerts.jsx";
import Evaluation from "./pages/Evaluation.jsx";

// App.jsx - Kerangka aplikasi: navbar + routing antar 3 halaman.
// Memakai react-router-dom; NavLink otomatis menambah class "active" pada
// menu halaman yang sedang dibuka.
export default function App() {
  return (
    <div>
      <nav className="navbar">
        <span className="brand">WebLog-IDS</span>
        <NavLink to="/" end>
          Dashboard
        </NavLink>
        <NavLink to="/detections">Hasil Deteksi</NavLink>
        <NavLink to="/evaluation">Evaluasi</NavLink>
        <NavLink to="/alerts">Alert Realtime</NavLink>
      </nav>

      <div className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/detections" element={<DetectionResults />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/alerts" element={<RealtimeAlerts />} />
          {/* Fallback: arahkan rute tak dikenal ke dashboard. */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}
