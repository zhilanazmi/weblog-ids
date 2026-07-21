import { useState, useEffect, useCallback } from "react";
import {
  fetchSummary,
  fetchAttackTypes,
  fetchTopIp,
  fetchRuleTriggered,
  fetchLatestDetections,
} from "../api/api.js";
import SummaryCards from "../components/SummaryCards.jsx";
import AttackTypeChart from "../components/AttackTypeChart.jsx";
import TopIpChart from "../components/TopIpChart.jsx";
import RuleTriggeredChart from "../components/RuleTriggeredChart.jsx";
import AlertTable from "../components/AlertTable.jsx";

// Opsi rentang waktu dashboard (nilai null = semua waktu, tanpa filter days).
const RANGE_OPTIONS = [
  { value: "30", label: "30 hari terakhir" },
  { value: "14", label: "14 hari terakhir" },
  { value: "7", label: "7 hari terakhir" },
  { value: "all", label: "Semua waktu" },
];

// Dashboard.jsx - Halaman utama: ringkasan + grafik + alert terbaru.
// Data diambil dari beberapa endpoint dan di-refresh otomatis tiap 5 detik.
// Filter days (7/14/30) diterapkan ke statistik agregat (kartu + chart).
export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [attackTypes, setAttackTypes] = useState([]);
  const [topIp, setTopIp] = useState([]);
  const [rules, setRules] = useState([]);
  const [latest, setLatest] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // Default 30 hari agar total log langsung menampilkan jendela terbaru.
  const [range, setRange] = useState("30");

  // Konversi nilai select ke argumen API (null = tanpa filter days).
  const daysParam = range === "all" ? null : Number(range);

  // loadAll mengambil semua data dashboard sekaligus (Promise.all) agar
  // satu siklus refresh efisien. Dibungkus useCallback supaya referensinya
  // stabil saat dipakai di useEffect; bergantung pada daysParam.
  const loadAll = useCallback(async () => {
    try {
      const [s, at, ip, rt, lt] = await Promise.all([
        fetchSummary(daysParam),
        fetchAttackTypes(daysParam),
        fetchTopIp(10, daysParam),
        fetchRuleTriggered(10, daysParam),
        fetchLatestDetections(10),
      ]);
      setSummary(s);
      setAttackTypes(at.data || []);
      setTopIp(ip.data || []);
      setRules(rt.data || []);
      setLatest(lt.data || []);
      setError(""); // sukses -> bersihkan pesan error sebelumnya
    } catch (e) {
      // Backend mati / CORS / jaringan: tampilkan pesan, jangan layar kosong.
      setError(
        "Gagal mengambil data dari backend. Pastikan backend berjalan di " +
          "http://localhost:8000. (" + e.message + ")"
      );
    } finally {
      setLoading(false);
    }
  }, [daysParam]);

  // Saat mount / ganti rentang: ambil data, lalu set interval refresh 5 detik.
  // Cleanup interval saat unmount atau days berubah agar tidak ada timer bocor.
  useEffect(() => {
    setLoading(true);
    loadAll();
    const id = setInterval(loadAll, 5000);
    return () => clearInterval(id);
  }, [loadAll]);

  if (loading && !summary) {
    return <div className="msg loading">Memuat data dashboard...</div>;
  }

  return (
    <div>
      <h2 className="page-title">Dashboard</h2>

      <div className="controls">
        <label>
          Rentang waktu:{" "}
          <select value={range} onChange={(e) => setRange(e.target.value)}>
            {RANGE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* Pesan error tetap tampil walau data lama masih ada. */}
      {error && <div className="msg error">{error}</div>}

      {summary && <SummaryCards summary={summary} />}

      <div className="charts-grid">
        <div className="panel">
          <h3>Jenis Serangan</h3>
          <AttackTypeChart data={attackTypes} />
        </div>
        <div className="panel">
          <h3>Top IP Penyerang</h3>
          <TopIpChart data={topIp} />
        </div>
        <div className="panel">
          <h3>Rule Paling Sering Terpicu</h3>
          <RuleTriggeredChart data={rules} />
        </div>
      </div>

      <div className="panel">
        <h3>Alert Terbaru</h3>
        <AlertTable rows={latest} />
      </div>
    </div>
  );
}
