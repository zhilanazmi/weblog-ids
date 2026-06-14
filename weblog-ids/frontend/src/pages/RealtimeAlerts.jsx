import { useState, useEffect, useRef } from "react";
import { WS_URL } from "../api/api.js";

// RealtimeAlerts.jsx - Menerima alert serangan secara realtime via WebSocket.
//
// Logika WebSocket (penting untuk dijelaskan saat sidang):
// - Koneksi dibuka saat komponen mount, ditutup saat unmount (cleanup useEffect).
// - Tiap pesan alert ditambahkan ke ATAS daftar (alert terbaru di paling atas).
// - Bila koneksi putus, lakukan reconnect otomatis dengan jeda 3 detik.
// - useRef dipakai untuk menyimpan objek WebSocket & timer agar nilainya tetap
//   bertahan antar render tanpa memicu render ulang.

function formatRules(matched) {
  if (Array.isArray(matched)) return matched.join(", ");
  return matched || "-";
}

export default function RealtimeAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);

  const wsRef = useRef(null);
  const reconnectRef = useRef(null);
  // Flag agar proses reconnect berhenti total saat komponen unmount.
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    // connect() membuka WebSocket dan memasang handler-nya.
    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      // onopen: tandai status terhubung.
      ws.onopen = () => setConnected(true);

      // onmessage: parse JSON alert, sisipkan di awal array (terbaru di atas).
      ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          // beri id unik lokal untuk key React (timestamp + waktu terima).
          alert._id = `${Date.now()}-${Math.random()}`;
          setAlerts((prev) => [alert, ...prev].slice(0, 100)); // batasi 100
        } catch {
          // abaikan pesan non-JSON
        }
      };

      // onclose: tandai terputus, lalu jadwalkan reconnect (kecuali unmount).
      ws.onclose = () => {
        setConnected(false);
        if (mountedRef.current) {
          reconnectRef.current = setTimeout(connect, 3000);
        }
      };

      // onerror: tutup koneksi agar onclose menangani reconnect.
      ws.onerror = () => ws.close();
    }

    connect();

    // Cleanup saat unmount: hentikan reconnect & tutup koneksi.
    return () => {
      mountedRef.current = false;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  return (
    <div>
      <h2 className="page-title">Alert Realtime</h2>

      {/* Indikator status koneksi WebSocket. */}
      <div className="controls">
        <span className="status">
          <span className={`dot ${connected ? "on" : "off"}`}></span>
          {connected ? "Terhubung" : "Terputus (mencoba reconnect...)"}
        </span>
        <span className="label">Total alert diterima: {alerts.length}</span>
      </div>

      {alerts.length === 0 && (
        <div className="msg loading">
          Menunggu alert serangan masuk... Picu request XSS/SQLi ke DVWA untuk
          mengetesnya.
        </div>
      )}

      {/* Tiap alert sebagai card; warna mengikuti severity (class sev-*). */}
      {alerts.map((a) => (
        <div className={`alert-card sev-${a.severity}`} key={a._id}>
          <div className="row">
            <span className={`badge label-${a.label}`}>{a.label}</span>{" "}
            <span className={`badge ${a.severity}`}>{a.severity}</span>
          </div>
          <div className="row">
            <span className="key">Waktu:</span>
            {a.timestamp}
          </div>
          <div className="row">
            <span className="key">IP:</span>
            {a.ip} <span className="key">Method:</span>
            {a.method}
          </div>
          <div className="row">
            <span className="key">Request URI:</span>
            {a.request_uri}
          </div>
          <div className="row">
            <span className="key">Decoded:</span>
            {a.decoded_payload}
          </div>
          <div className="row">
            <span className="key">Rules:</span>
            {formatRules(a.matched_rules)}
          </div>
          <div className="row">
            <span className="key">Rekomendasi:</span>
            {a.recommendation}
          </div>
        </div>
      ))}
    </div>
  );
}
