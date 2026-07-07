"""
evaluator.py - Logika evaluasi OvR strict 4-kelas untuk WebLog-IDS.

Modul ini sengaja memisahkan perhitungan evaluasi dari route API dan UI agar
rumus confusion matrix dapat diuji/diterangkan langsung saat sidang skripsi.
Skema yang dipakai adalah One-vs-Rest strict untuk kelas:
XSS, SQLi, Normal, Multiple.
"""

import json
from typing import Dict, Any, List, Optional

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database

CLASSES = ["XSS", "SQLi", "Normal", "Multiple"]
_VALID_LABELS = set(CLASSES)


def _safe_div(num: float, den: float) -> float:
    """Pembagian aman: 0.0 bila denominator nol, dibulatkan 4 desimal."""
    return round(num / den, 4) if den else 0.0


def _empty_confusion_matrix() -> Dict[str, Dict[str, int]]:
    """Buat matrix 4x4 dengan baris aktual dan kolom prediksi."""
    return {actual: {pred: 0 for pred in CLASSES} for actual in CLASSES}


def compute_confusion_matrix(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Hitung confusion matrix 4x4 strict.

    Input record wajib punya predicted_label dan actual_label. Record dengan
    actual_label NULL/kosong atau label di luar 4 kelas akan di-skip agar ground
    truth tidak ambigu. Tidak ada double-counting: satu record hanya menambah
    satu sel matrix [actual][predicted].
    """
    matrix = _empty_confusion_matrix()
    for r in records:
        actual = r.get("actual_label")
        predicted = r.get("predicted_label") or r.get("label")
        if actual not in _VALID_LABELS or predicted not in _VALID_LABELS:
            continue
        matrix[actual][predicted] += 1
    return matrix


def compute_ovr_metrics(confusion_matrix: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, Any]]:
    """
    Hitung TP/FP/TN/FN dan metrik OvR untuk tiap kelas.

    Untuk kelas C: TP = aktual C & prediksi C; FP = aktual bukan C & prediksi C;
    FN = aktual C & prediksi bukan C; TN = aktual bukan C & prediksi bukan C.
    """
    total = sum(
        confusion_matrix[actual][pred]
        for actual in CLASSES
        for pred in CLASSES
    )
    metrics: Dict[str, Dict[str, Any]] = {}

    for cls in CLASSES:
        tp = confusion_matrix[cls][cls]
        fp = sum(confusion_matrix[actual][cls] for actual in CLASSES if actual != cls)
        fn = sum(confusion_matrix[cls][pred] for pred in CLASSES if pred != cls)
        tn = total - tp - fp - fn

        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        fpr = _safe_div(fp, fp + tn)
        fnr = _safe_div(fn, fn + tp)

        metrics[cls] = {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "fnr": fnr,
        }
    return metrics


def compute_overall_metrics(
    confusion_matrix: Dict[str, Dict[str, int]],
    ovr_metrics: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Hitung accuracy dan macro-average dari hasil OvR 4 kelas."""
    total = sum(
        confusion_matrix[actual][pred]
        for actual in CLASSES
        for pred in CLASSES
    )
    correct = sum(confusion_matrix[cls][cls] for cls in CLASSES)
    n_class = len(CLASSES)
    return {
        "accuracy": _safe_div(correct, total),
        "macro_f1": round(sum(ovr_metrics[c]["f1"] for c in CLASSES) / n_class, 4),
        "macro_precision": round(
            sum(ovr_metrics[c]["precision"] for c in CLASSES) / n_class, 4
        ),
        "macro_recall": round(sum(ovr_metrics[c]["recall"] for c in CLASSES) / n_class, 4),
        "total_labeled": total,
    }


def _fetch_labeled_records() -> List[Dict[str, Any]]:
    """Ambil record yang sudah memiliki ground truth dari database."""
    sql = """
        SELECT d.id, d.label AS predicted_label, d.actual_label
        FROM detection_results d
        WHERE d.actual_label IS NOT NULL
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _save_evaluation_run(result: Dict[str, Any]) -> int:
    """Simpan snapshot hasil evaluasi ke evaluation_runs sebagai JSON."""
    sql = """
        INSERT INTO evaluation_runs (accuracy, macro_f1, json_result)
        VALUES (%s, %s, %s)
    """
    overall = result["overall_metrics"]
    params = (
        overall["accuracy"],
        overall["macro_f1"],
        json.dumps(result, ensure_ascii=False),
    )
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid
    finally:
        conn.close()


def run_evaluation(db_session: Optional[Any] = None) -> Dict[str, Any]:
    """
    Jalankan evaluasi dari record DB yang sudah dilabeli manual.

    Parameter db_session disediakan agar signature sesuai spesifikasi, tetapi
    proyek ini memakai PyMySQL manual via database.get_connection(), bukan ORM.
    """
    records = _fetch_labeled_records()
    confusion_matrix = compute_confusion_matrix(records)
    ovr_metrics = compute_ovr_metrics(confusion_matrix)
    overall_metrics = compute_overall_metrics(confusion_matrix, ovr_metrics)
    result = {
        "classes": CLASSES,
        "confusion_matrix": confusion_matrix,
        "ovr_metrics": ovr_metrics,
        "overall_metrics": overall_metrics,
    }
    run_id = _save_evaluation_run(result)
    result["run_id"] = run_id
    return result


def get_latest_evaluation_run() -> Optional[Dict[str, Any]]:
    """Ambil snapshot evaluasi terbaru dari evaluation_runs."""
    sql = """
        SELECT id, run_at, accuracy, macro_f1, json_result
        FROM evaluation_runs
        ORDER BY id DESC
        LIMIT 1
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None
    payload = json.loads(row.get("json_result") or "{}")
    payload["run_id"] = row.get("id")
    payload["run_at"] = row.get("run_at")
    return payload


if __name__ == "__main__":
    sample = [
        {"actual_label": "XSS", "predicted_label": "XSS"},
        {"actual_label": "XSS", "predicted_label": "Multiple"},
        {"actual_label": "Normal", "predicted_label": "SQLi"},
        {"actual_label": "SQLi", "predicted_label": "SQLi"},
    ]
    cm = compute_confusion_matrix(sample)
    ovr = compute_ovr_metrics(cm)
    overall = compute_overall_metrics(cm, ovr)
    print(json.dumps({"confusion_matrix": cm, "ovr_metrics": ovr, "overall": overall}, indent=2))
