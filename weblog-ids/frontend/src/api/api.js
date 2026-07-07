// api.js - Konfigurasi terpusat untuk akses backend WebLog-IDS.
//
// Semua URL backend didefinisikan di sini lewat BASE_URL agar tidak perlu
// di-hardcode berulang di banyak komponen. Bila backend pindah host/port,
// cukup ubah di satu tempat ini.

// BASE_URL bisa dioverride lewat environment variable Vite (VITE_API_BASE_URL),
// default ke localhost:8000 sesuai backend. Jika env production terlanjur
// diisi dengan akhiran /api, normalisasi di sini mencegah URL dobel /api/api.
export const BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

// URL WebSocket alert. Turunkan dari BASE_URL: ganti skema http->ws / https->wss.
export const WS_URL =
  (import.meta.env.VITE_WS_URL ||
    BASE_URL.replace(/^http/, "ws")) + "/ws/alerts";

// Helper fetch JSON dengan penanganan error terpusat. Melempar Error berisi
// pesan agar komponen pemanggil bisa menampilkan kondisi error ke layar.
async function getJSON(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} saat mengambil ${path}`);
  }
  return res.json();
}

async function postJSON(path, body = undefined) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} saat mengirim ${path}`);
  }
  return res.json();
}

// ---------- Endpoint dashboard ----------
export const fetchSummary = () => getJSON("/api/dashboard/summary");
export const fetchAttackTypes = () => getJSON("/api/dashboard/attack-types");
export const fetchTopIp = (limit = 10) =>
  getJSON(`/api/dashboard/top-attacker-ip?limit=${limit}`);
export const fetchRuleTriggered = (limit = 10) =>
  getJSON(`/api/dashboard/rule-triggered?limit=${limit}`);

// ---------- Endpoint deteksi ----------
export const fetchLatestDetections = (n = 10) =>
  getJSON(`/api/detections/latest?n=${n}`);

// Daftar deteksi dengan paginasi + filter label opsional.
export const fetchDetections = ({ limit = 20, offset = 0, label = "" } = {}) => {
  const params = new URLSearchParams({ limit, offset });
  if (label) params.append("label", label);
  return getJSON(`/api/detections?${params.toString()}`);
};

export const setActualLabel = (id, actualLabel) =>
  postJSON(`/api/detections/${id}/actual-label`, { actual_label: actualLabel });

export const markUnlabeledAsNormal = () =>
  postJSON("/api/detections/mark-unlabeled-as-normal");

// ---------- Endpoint evaluasi ----------
export const runEvaluation = () => postJSON("/api/evaluation/run");
export const clearEvaluation = () => postJSON("/api/evaluation/clear");
export const fetchEvaluationResults = () => getJSON("/api/evaluation/results");

export const exportEvaluationCsvUrl = () =>
  `${BASE_URL}/api/evaluation/export-csv`;

export const fetchHealth = () => getJSON("/api/health");

// URL export CSV (dengan filter label opsional). Dipakai untuk memicu unduhan
// langsung di browser, jadi kita kembalikan URL-nya saja, bukan fetch JSON.
export const exportCsvUrl = (label = "") => {
  const params = new URLSearchParams();
  if (label) params.append("label", label);
  const qs = params.toString();
  return `${BASE_URL}/api/reports/export-csv${qs ? `?${qs}` : ""}`;
};
