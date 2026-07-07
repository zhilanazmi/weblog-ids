import { useState, useEffect, useCallback } from "react";
import {
  fetchDetections,
  setActualLabel,
  markUnlabeledAsNormal,
  runEvaluation,
  clearEvaluation,
  fetchEvaluationResults,
  exportEvaluationCsvUrl,
} from "../api/api.js";

// Evaluation.jsx - Halaman labeling ground truth + evaluasi OvR strict 4 kelas.

const LABELS = ["Semua", "Normal", "XSS", "SQLi", "Multiple"];
const EVAL_CLASSES = ["XSS", "SQLi", "Normal", "Multiple"];
const PAGE_SIZE = 20;

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

export default function Evaluation() {
  const [rows, setRows] = useState([]);
  const [label, setLabel] = useState("Semua");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState(null);
  const [error, setError] = useState("");
  const [evalResult, setEvalResult] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);

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
      const res = await fetchEvaluationResults();
      setEvalResult(res);
    } catch {
      // Evaluasi bisa belum ada; tombol Run Evaluation akan membuat snapshot.
    }
  }, []);

  useEffect(() => {
    loadDetections();
  }, [loadDetections]);

  useEffect(() => {
    loadEvaluation();
  }, [loadEvaluation]);

  const onChangeLabel = (e) => {
    setLabel(e.target.value);
    setOffset(0);
  };

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

  const onMarkAllNormal = async () => {
    const ok = window.confirm("Tandai semua baris belum dilabeli sebagai Normal?");
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

  const onRunEvaluation = async () => {
    setEvalLoading(true);
    try {
      const res = await runEvaluation();
      setEvalResult(res);
      setError("");
    } catch (e) {
      setError("Gagal menjalankan evaluasi. (" + e.message + ")");
    } finally {
      setEvalLoading(false);
    }
  };

  const onExportEvaluation = () => {
    window.open(exportEvaluationCsvUrl(), "_blank");
  };

  const onClearEvaluation = async () => {
    const ok = window.confirm(
      "Clear Evaluasi akan menghapus semua Label Aktual dan histori hasil evaluasi, tetapi data deteksi/log tetap aman. Lanjutkan?"
    );
    if (!ok) return;
    setEvalLoading(true);
    setLoading(true);
    try {
      await clearEvaluation();
      setEvalResult(null);
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

      <div className="panel eval-section">
        <h3>Label Aktual</h3>
        <p className="label">
          Beri ground truth manual untuk tiap baris. Label prediksi tetap berasal dari sistem;
          Label Aktual adalah jawaban benar dari peneliti.
        </p>

        <div className="controls">
          <label>
            Filter label prediksi:{" "}
            <select value={label} onChange={onChangeLabel}>
              {LABELS.map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </label>
          <button onClick={onMarkAllNormal} disabled={loading}>
            Mark all unlabeled as Normal
          </button>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
            ← Sebelumnya
          </button>
          <span>Halaman {page}</span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={rows.length < PAGE_SIZE}>
            Berikutnya →
          </button>
        </div>

        {error && <div className="msg error">{error}</div>}
        {loading && <div className="msg loading">Memuat...</div>}
        {!loading && rows.length === 0 && <p className="label">Tidak ada data untuk filter ini.</p>}

        {rows.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Waktu</th>
                  <th>IP</th>
                  <th>Method</th>
                  <th>Request URI</th>
                  <th>Decoded Payload</th>
                  <th>Label Prediksi</th>
                  <th>Label Aktual</th>
                  <th>Severity</th>
                  <th>Rules</th>
                  <th>Rekomendasi</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className={`sev-${r.severity}`}>
                    <td>{r.timestamp}</td>
                    <td>{r.ip}</td>
                    <td>{r.method}</td>
                    <td className="wrap">{r.request_uri}</td>
                    <td className="wrap">{r.decoded_payload}</td>
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
                          {EVAL_CLASSES.map((cls) => (
                            <option key={cls} value={cls}>{cls}</option>
                          ))}
                        </select>
                      </div>
                    </td>
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

      <div className="panel eval-section">
        <h3>Hasil Evaluasi</h3>
        <div className="controls">
          <button onClick={onRunEvaluation} disabled={evalLoading}>
            {evalLoading ? "Menghitung..." : "Run Evaluation"}
          </button>
          <button onClick={onClearEvaluation} disabled={evalLoading || loading}>
            Clear Evaluasi
          </button>
          <button onClick={onExportEvaluation}>Export Hasil Evaluasi (CSV)</button>
          {evalResult?.run_id && <span className="label">Run ID: {evalResult.run_id}</span>}
        </div>

        {!evalResult && <p className="label">Belum ada hasil evaluasi.</p>}

        {evalResult && (
          <>
            <div className="cards eval-cards">
              <div className="card"><span className="label">Accuracy</span><div className="value">{fmt(overall.accuracy)}</div></div>
              <div className="card"><span className="label">Macro-F1</span><div className="value">{fmt(overall.macro_f1)}</div></div>
              <div className="card"><span className="label">Macro-Precision</span><div className="value">{fmt(overall.macro_precision)}</div></div>
              <div className="card"><span className="label">Macro-Recall</span><div className="value">{fmt(overall.macro_recall)}</div></div>
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
