import { useState, useEffect, useCallback, useRef } from "react";
import {
  fetchDetections,
  setActualLabel,
  markUnlabeledAsNormal,
  matchGroundTruth,
  runEvaluation,
  clearEvaluation,
  fetchEvaluationResults,
  exportEvaluationCsvUrl,
  runGenerator,
  fetchGeneratorStatus,
} from "../api/api.js";
import { formatDateTimeMs } from "../utils/time";

// Evaluation.jsx - Halaman Evaluasi WebLog-IDS.
// Bagian A: Generator serangan (kirim payload + catat ground truth).
// Bagian B: Label aktual (matching ground truth + labeling manual fallback).
// Bagian C: Hasil evaluasi OvR strict 4-kelas (confusion matrix + metrik).

const LABELS = ["Semua", "Normal", "XSS", "SQLi", "Multiple"];
const EVAL_CLASSES = ["XSS", "SQLi", "Normal", "Multiple"];
const PAGE_SIZE = 20;
const DEFAULT_TARGET = "https://dvwa.zhilanazmi.id";
const EVALUATION_DAYS = [7, 14, 30];

function formatRules(matched) {
  if (!matched) return "-";
  if (Array.isArray(matched)) return matched.join(", ");
  try {
    const arr = JSON.parse(matched);
    return Array.isArray(arr) ? arr.join(", ") : String(matched);
  } catch {
    return String(matched);
  }
}

function fmt(value) {
  if (value === null || value === undefined) return "0";
  return Number(value).toFixed(4).replace(/\.0+$/, "").replace(/(\.\d*?)0+$/, "$1");
}

function ActualLabelBadge({ label }) {
  if (!label) return <span className="label-muted">Belum Dilabeli</span>;
  return <span className={`badge label-${label}`}>{label}</span>;
}

function SourceBadge({ source }) {
  if (!source) return null;
  const cls =
    source === "generator" ? "src-generator" :
    source === "manual" ? "src-manual" : "src-auto";
  return <span className={`badge ${cls}`}>{source}</span>;
}

export default function Evaluation() {
  const [rows, setRows] = useState([]);
  const [label, setLabel] = useState("Semua");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState(null);
  const [error, setError] = useState("");
  const [evalResult, setEvalResult] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);
  const [evaluationDays, setEvaluationDays] = useState(7);

  // State generator (Bagian A)
  const [gTarget, setGTarget] = useState(DEFAULT_TARGET);
  const [gXss, setGXss] = useState(20);
  const [gSqli, setGSqli] = useState(20);
  const [gNormal, setGNormal] = useState(30);
  const [gMultiple, setGMultiple] = useState(5);
  const [gRunning, setGRunning] = useState(false);
  const [gSummary, setGSummary] = useState(null);
  const pollRef = useRef(null);

  // State matching (Bagian B)
  const [matchMsg, setMatchMsg] = useState("");
  const [matching, setMatching] = useState(false);

  const loadDetections = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchDetections({
        limit: PAGE_SIZE,
        offset,
        label: label === "Semua" ? "" : label,
      });
      setRows(res.data || []);
      setError("");
    } catch (e) {
      setError("Gagal mengambil data deteksi. Pastikan backend berjalan. (" + e.message + ")");
    } finally {
      setLoading(false);
    }
  }, [label, offset]);

  const loadEvaluation = useCallback(async () => {
    try {
      const res = await fetchEvaluationResults(evaluationDays);
      setEvalResult(res);
    } catch {
      // Evaluasi bisa belum ada; tombol Run Evaluation akan membuat snapshot.
    }
  }, [evaluationDays]);

  useEffect(() => { loadDetections(); }, [loadDetections]);
  useEffect(() => { loadEvaluation(); }, [loadEvaluation]);

  // Hentikan polling saat unmount.
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const onChangeLabel = (e) => { setLabel(e.target.value); setOffset(0); };

  // ---------- Bagian A: Generator ----------
  const onRunGenerator = async () => {
    if (!gTarget.trim()) { setError("Isi target URL DVWA."); return; }
    const ok = window.confirm(
      `Kirim payload ke ${gTarget}? (XSS=${gXss}, SQLi=${gSqli}, Normal=${gNormal}, Multiple=${gMultiple})`
    );
    if (!ok) return;
    setError("");
    setGSummary(null);
    try {
      const res = await runGenerator({
        target: gTarget.trim(),
        xss: Number(gXss) || 0,
        sqli: Number(gSqli) || 0,
        normal: Number(gNormal) || 0,
        multiple: Number(gMultiple) || 0,
      });
      if (!res.started) { setError(res.message || "Generator sedang berjalan."); return; }
      setGRunning(true);
      // Polling status sampai selesai.
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const st = await fetchGeneratorStatus();
          if (!st.running) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setGRunning(false);
            if (st.error) setError("Generator error: " + st.error);
            else { setGSummary(st.summary); await loadDetections(); }
          }
        } catch { /* abaikan error polling sesaat */ }
      }, 1500);
    } catch (e) {
      setError("Gagal menjalankan generator. (" + e.message + ")");
    }
  };

  // ---------- Bagian B: Label aktual ----------
  const onSetActualLabel = async (id, actualLabel) => {
    if (!actualLabel) return;
    setSavingId(id);
    try {
      await setActualLabel(id, actualLabel);
      await loadDetections();
      setError("");
    } catch (e) {
      setError("Gagal menyimpan label aktual. (" + e.message + ")");
    } finally {
      setSavingId(null);
    }
  };

  const onMatchGroundTruth = async () => {
    setMatching(true);
    setMatchMsg("");
    try {
      const res = await matchGroundTruth();
      setMatchMsg(res.message || `Cocok: ${res.matched}, belum cocok: ${res.unmatched}`);
      await loadDetections();
      setError("");
    } catch (e) {
      setError("Gagal mencocokkan ground truth. (" + e.message + ")");
    } finally {
      setMatching(false);
    }
  };

  const onMarkAllNormal = async () => {
    const ok = window.confirm("Tandai semua baris belum dilabeli sebagai Normal (background request)?");
    if (!ok) return;
    setLoading(true);
    try {
      await markUnlabeledAsNormal();
      await loadDetections();
      setError("");
    } catch (e) {
      setError("Gagal menandai label Normal massal. (" + e.message + ")");
    } finally {
      setLoading(false);
    }
  };

  // ---------- Bagian C: Evaluasi ----------
  const onRunEvaluation = async () => {
    setEvalLoading(true);
    try {
      const res = await runEvaluation(evaluationDays);
      setEvalResult(res);
      setError("");
    } catch (e) {
      setError("Gagal menjalankan evaluasi. (" + e.message + ")");
    } finally {
      setEvalLoading(false);
    }
  };

  const onExportEvaluation = () => { window.open(exportEvaluationCsvUrl(evaluationDays), "_blank"); };

  const onClearEvaluation = async () => {
    const ok = window.confirm(
      "Clear Evaluasi akan menghapus semua Label Aktual dan histori evaluasi, tetapi data deteksi/log tetap aman. Lanjutkan?"
    );
    if (!ok) return;
    setEvalLoading(true);
    setLoading(true);
    try {
      await clearEvaluation();
      setEvalResult(null);
      setMatchMsg("");
      setOffset(0);
      await loadDetections();
      setError("");
    } catch (e) {
      setError("Gagal clear evaluasi. (" + e.message + ")");
    } finally {
      setEvalLoading(false);
      setLoading(false);
    }
  };

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const matrix = evalResult?.confusion_matrix || {};
  const ovr = evalResult?.ovr_metrics || {};
  const overall = evalResult?.overall_metrics || {};

  return (
    <div>
      <h2 className="page-title">Evaluasi</h2>

      {/* ===== Bagian A: Generator Serangan ===== */}
      <div className="panel eval-section">
        <h3>Generator Serangan</h3>
        <p className="label">
          Kirim payload terkontrol ke DVWA dan catat ground truth otomatis ke database.
          Pastikan request melewati Nginx yang dipantau log watcher.
        </p>
        <div className="controls">
          <label>Target URL:{" "}
            <input type="text" value={gTarget} onChange={(e) => setGTarget(e.target.value)}
              placeholder={DEFAULT_TARGET} style={{ minWidth: "280px" }} />
          </label>
        </div>
        <div className="controls">
          <label>XSS:{" "}
            <input type="number" min="0" value={gXss} onChange={(e) => setGXss(e.target.value)} style={{ width: "80px" }} />
          </label>
          <label>SQLi:{" "}
            <input type="number" min="0" value={gSqli} onChange={(e) => setGSqli(e.target.value)} style={{ width: "80px" }} />
          </label>
          <label>Normal:{" "}
            <input type="number" min="0" value={gNormal} onChange={(e) => setGNormal(e.target.value)} style={{ width: "80px" }} />
          </label>
          <label>Multiple:{" "}
            <input type="number" min="0" value={gMultiple} onChange={(e) => setGMultiple(e.target.value)} style={{ width: "80px" }} />
          </label>
          <button onClick={onRunGenerator} disabled={gRunning}>
            {gRunning ? "Mengirim payload..." : "Generate & Send"}
          </button>
        </div>
        {gRunning && <div className="msg loading">Generator berjalan di background... mohon tunggu.</div>}
        {gSummary && (
          <p className="label">
            Selesai: Normal={gSummary.normal}, XSS={gSummary.xss}, SQLi={gSummary.sqli},
            Multiple={gSummary.multiple} (total {gSummary.total_sent}). Lanjutkan ke "Match Ground Truth".
          </p>
        )}
      </div>

      {/* ===== Bagian B: Label Aktual ===== */}
      <div className="panel eval-section">
        <h3>Label Aktual</h3>
        <p className="label">
          Cocokkan deteksi dengan ground truth dari generator, atau beri label manual per baris.
        </p>

        <div className="controls">
          <button onClick={onMatchGroundTruth} disabled={matching}>
            {matching ? "Mencocokkan..." : "Match Ground Truth"}
          </button>
          <button onClick={onMarkAllNormal} disabled={loading}>
            Mark all unlabeled as Normal
          </button>
          <label>Filter label prediksi:{" "}
            <select value={label} onChange={onChangeLabel}>
              {LABELS.map((l) => (<option key={l} value={l}>{l}</option>))}
            </select>
          </label>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
            &larr; Sebelumnya
          </button>
          <span>Halaman {page}</span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={rows.length < PAGE_SIZE}>
            Berikutnya &rarr;
          </button>
        </div>

        {matchMsg && <div className="msg">{matchMsg}</div>}
        {error && <div className="msg error">{error}</div>}
        {loading && <div className="msg loading">Memuat...</div>}
        {!loading && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Waktu</th><th>IP</th><th>Method</th><th>Request URI</th>
                  <th>Prediksi</th><th>Label Aktual</th><th>Sumber</th><th>Severity</th>
                  <th>Rule Terpicu</th><th>Rekomendasi</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (<tr><td colSpan="10">Tidak ada data.</td></tr>)}
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td className="nowrap">{formatDateTimeMs(r.log_time ?? r.timestamp)}</td>
                    <td>{r.ip}</td>
                    <td>{r.method}</td>
                    <td className="wrap">{r.request_uri}</td>
                    <td><span className={`badge label-${r.label}`}>{r.label}</span></td>
                    <td>
                      <div className="actual-label-cell">
                        <ActualLabelBadge label={r.actual_label} />
                        <select
                          value={r.actual_label || ""}
                          disabled={savingId === r.id}
                          onChange={(e) => onSetActualLabel(r.id, e.target.value)}
                        >
                          <option value="" disabled>Belum Dilabeli</option>
                          {EVAL_CLASSES.map((cls) => (<option key={cls} value={cls}>{cls}</option>))}
                        </select>
                      </div>
                    </td>
                    <td><SourceBadge source={r.labeled_by} /></td>
                    <td><span className={`badge ${r.severity}`}>{r.severity}</span></td>
                    <td className="wrap">{formatRules(r.matched_rules)}</td>
                    <td className="wrap">{r.recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ===== Bagian C: Hasil Evaluasi ===== */}
      <div className="panel eval-section">
        <h3>Hasil Evaluasi</h3>
        <div className="controls">
          <button onClick={onRunEvaluation} disabled={evalLoading}>
            {evalLoading ? "Menghitung..." : "Run Evaluation"}
          </button>
          <label>Rentang waktu:
            <select
              value={evaluationDays}
              disabled={evalLoading}
              onChange={(e) => setEvaluationDays(Number(e.target.value))}
            >
              {EVALUATION_DAYS.map((days) => <option key={days} value={days}>{days} hari terakhir</option>)}
            </select>
          </label>
          <button onClick={onClearEvaluation} disabled={evalLoading || loading}>
            Clear Evaluasi
          </button>
          <button onClick={onExportEvaluation}>Export Hasil Evaluasi (CSV)</button>
          {evalResult?.run_id && <span className="label">Run ID: {evalResult.run_id} | Periode: {evaluationDays} hari terakhir</span>}
        </div>

        {!evalResult && <p className="label">Belum ada hasil evaluasi.</p>}

        {evalResult && (
          <>
            <div className="cards eval-cards">
              <div className="card"><span className="label">Accuracy</span><div className="value">{fmt(overall.accuracy)}</div></div>
              <div className="card"><span className="label">Precision</span><div className="value">{fmt(overall.macro_precision)}</div></div>
              <div className="card"><span className="label">Recall</span><div className="value">{fmt(overall.macro_recall)}</div></div>
              <div className="card"><span className="label">F1-Score</span><div className="value">{fmt(overall.macro_f1)}</div></div>
              <div className="card"><span className="label">Total Labeled</span><div className="value">{overall.total_labeled || 0}</div></div>
            </div>

            <h3>Confusion Matrix 4×4</h3>
            <div className="table-scroll">
              <table className="confusion-table">
                <thead>
                  <tr>
                    <th>Aktual \ Prediksi</th>
                    {EVAL_CLASSES.map((cls) => <th key={cls}>{cls}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {EVAL_CLASSES.map((actual) => (
                    <tr key={actual}>
                      <th>{actual}</th>
                      {EVAL_CLASSES.map((pred) => (
                        <td key={pred} className={actual === pred ? "cm-diagonal" : "cm-off"}>
                          {matrix?.[actual]?.[pred] || 0}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3>Metrik Per-Kelas</h3>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Kelas</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th>
                    <th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>FNR</th>
                  </tr>
                </thead>
                <tbody>
                  {EVAL_CLASSES.map((cls) => {
                    const m = ovr[cls] || {};
                    return (
                      <tr key={cls}>
                        <td><span className={`badge label-${cls}`}>{cls}</span></td>
                        <td>{m.tp || 0}</td>
                        <td>{m.fp || 0}</td>
                        <td>{m.tn || 0}</td>
                        <td>{m.fn || 0}</td>
                        <td>{fmt(m.precision)}</td>
                        <td>{fmt(m.recall)}</td>
                        <td>{fmt(m.f1)}</td>
                        <td>{fmt(m.fpr)}</td>
                        <td>{fmt(m.fnr)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
