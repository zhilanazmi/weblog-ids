// Util format waktu & delta presisi milidetik.
// Dipakai bersama AlertTable, DetectionResults, dan RealtimeAlerts agar
// format waktu log Nginx dan waktu alert konsisten (PRD: tampilan ms).

/**
 * Format nilai waktu menjadi "YYYY-MM-DD HH:MM:SS.mmm".
 *
 * Menerima:
 * - String ISO dari backend (log_time / created_at), mis.
 *   "2026-09-08T01:09:40.729" atau "2026-09-08T01:09:40.729000".
 * - String "YYYY-MM-DD HH:MM:SS.mmm" dari payload alert WebSocket.
 * - Epoch milidetik (number), mis. detected_at.
 * - String timestamp Nginx lama (fallback: ditampilkan apa adanya).
 *
 * String TIDAK dikonversi zona waktu (ditampilkan persis seperti disimpan
 * server) supaya waktu log dan waktu alert selalu sebanding.
 */
export function formatDateTimeMs(value) {
  if (value === null || value === undefined || value === "") return "-";

  if (typeof value === "number") {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "-";
    const p = (n, l = 2) => String(n).padStart(l, "0");
    return (
      `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
      `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.` +
      `${p(d.getMilliseconds(), 3)}`
    );
  }

  const s = String(value);
  const m = s.match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?/
  );
  if (!m) return s; // fallback: string mentah (mis. format Nginx lama)
  const ms = (m[7] || "").padEnd(3, "0").slice(0, 3);
  return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}.${ms}`;
}

/**
 * Format delta milidetik: "123 ms" / "1.45 s" / "2.30 mnt".
 * Null/NaN (data lama tanpa delta) ditampilkan "-".
 */
export function formatDelta(ms) {
  if (ms === null || ms === undefined || Number.isNaN(Number(ms))) return "-";
  const v = Number(ms);
  if (v < 1000) return `${Math.round(v)} ms`;
  if (v < 60000) return `${(v / 1000).toFixed(2)} s`;
  return `${(v / 60000).toFixed(2)} mnt`;
}
