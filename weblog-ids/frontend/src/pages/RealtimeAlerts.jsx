import { useState, useEffect, useRef } from "react";
import { WS_URL } from "../api/api.js";
import { formatDateTimeMs, formatDelta } from "../utils/time";

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

// Format latency ms menjadi string ringkas (ms, atau detik bila >= 1000ms).
function formatLatency(ms) {
  if (ms == null || isNaN(ms)) return "-";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`;
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
          // Waktu alert diterima browser: dipakai menghitung latency
          // pengiriman (browser - detected_at dari backend).
          alert._received_at = Date.now();
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
            <span className="key">Waktu Log:</span>
            {/* log_timestamp: waktu request dari log Nginx, presisi ms
                (dari msec=$msec); format sama dengan waktu alert. */}
            {formatDateTimeMs(a.log_timestamp ?? a.timestamp)}
          </div>
          <div className="row">
            <span className="key">Waktu Alert:</span>
            {/* alert_time: waktu alert dibuat di DB (created_at, ms). */}
            {formatDateTimeMs(a.alert_time)}
          </div>
          <div className="row">
            <span className="key">Delta (Log→Alert):</span>
            {/* delta_ms: selisih waktu request -> alert (bukti realtime). */}
            {formatDelta(a.delta_ms)}
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
            <span className="key">Latency Deteksi:</span>
            {formatLatency(a.latency_ms)}
            <span className="key" style={{ marginLeft: 12 }}>
              Latency Pengiriman:
            </span>
            {a.detected_at
              ? formatLatency(a._received_at - a.detected_at)
              : "-"}
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
