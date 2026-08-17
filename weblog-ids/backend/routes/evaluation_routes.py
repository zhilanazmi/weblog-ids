"""
evaluation_routes.py - Endpoint REST evaluasi OvR strict 4-kelas.

Route ini hanya mengorkestrasi request/response. Rumus evaluasi ada di
`evaluation/evaluator.py` agar bisa diuji terpisah dari HTTP layer.
"""

import csv
import io
from typing import Dict, Any

import os
import sys

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database
from evaluation.evaluator import CLASSES, run_evaluation, get_latest_evaluation_run
from evaluation.matcher import match_ground_truth, mark_unlabeled_as_normal

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])

_ALLOWED_DAYS = frozenset({7, 14, 30})


def _parse_days(days: int) -> int:
    """Validasi rentang evaluasi agar hanya periode yang tersedia di UI dipakai."""
    if days not in _ALLOWED_DAYS:
        raise HTTPException(status_code=400, detail="Parameter days harus 7, 14, atau 30.")
    return days


def _latest_or_run(days: int) -> Dict[str, Any]:
    """Ambil evaluasi terbaru; bila belum ada, jalankan evaluasi baru."""
    latest = get_latest_evaluation_run(days)
    if latest is not None:
        return latest
    return run_evaluation(days)


def _build_evaluation_csv(result: Dict[str, Any]) -> str:
    """Bangun CSV berisi confusion matrix, metrik per kelas, dan overall."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(["Confusion Matrix (baris=aktual, kolom=prediksi)"])
    writer.writerow(["Aktual\\Prediksi", *CLASSES])
    matrix = result.get("confusion_matrix") or {}
    for actual in CLASSES:
        row = matrix.get(actual, {})
        writer.writerow([actual, *[row.get(pred, 0) for pred in CLASSES]])

    writer.writerow([])
    writer.writerow(["Metrik Per Kelas"])
    writer.writerow(["Kelas", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1", "FPR", "FNR"])
    ovr = result.get("ovr_metrics") or {}
    for cls in CLASSES:
        m = ovr.get(cls, {})
        writer.writerow([
            cls,
            m.get("tp", 0),
            m.get("fp", 0),
            m.get("tn", 0),
            m.get("fn", 0),
            m.get("precision", 0),
            m.get("recall", 0),
            m.get("f1", 0),
            m.get("fpr", 0),
            m.get("fnr", 0),
        ])

    writer.writerow([])
    writer.writerow(["Overall"])
    overall = result.get("overall_metrics") or {}
    writer.writerow(["Accuracy", overall.get("accuracy", 0)])
    writer.writerow(["Macro-F1", overall.get("macro_f1", 0)])
    writer.writerow(["Macro-Precision", overall.get("macro_precision", 0)])
    writer.writerow(["Macro-Recall", overall.get("macro_recall", 0)])
    writer.writerow(["Total Labeled", overall.get("total_labeled", 0)])
    return buffer.getvalue()


@router.post("/run")
def run_evaluation_endpoint(days: int = Query(7)) -> Dict[str, Any]:
    """Jalankan evaluasi dari record berlabel pada rentang waktu terpilih."""
    return run_evaluation(_parse_days(days))


@router.post("/match-ground-truth")
def match_ground_truth_endpoint() -> Dict[str, Any]:
    """Cocokkan hasil deteksi yang belum dilabeli dengan ground truth generator."""
    return match_ground_truth()


@router.post("/mark-unlabeled-as-normal")
def mark_unlabeled_as_normal_endpoint() -> Dict[str, Any]:
    """Label semua record tanpa ground truth sebagai Normal (auto-normal)."""
    return mark_unlabeled_as_normal()

@router.post("/clear")
def clear_evaluation() -> Dict[str, Any]:
    """
    Reset state evaluasi tanpa menghapus data deteksi/log.

    Yang dihapus hanya ground truth manual (`actual_label`, `labeled_at`,
    `labeled_by`) dan histori snapshot `evaluation_runs`, supaya peneliti bisa
    memulai ulang sesi evaluasi dari awal secara eksplisit.
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE detection_results
                SET actual_label = NULL, labeled_at = NULL, labeled_by = NULL
                WHERE actual_label IS NOT NULL
                   OR labeled_at IS NOT NULL
                   OR labeled_by IS NOT NULL
                """
            )
            reset_labels = cur.rowcount
            cur.execute("DELETE FROM evaluation_runs")
            deleted_runs = cur.rowcount
    finally:
        conn.close()
    return {"reset_labels": reset_labels, "deleted_runs": deleted_runs}


@router.get("/results")
def get_results(days: int = Query(7)) -> Dict[str, Any]:
    """Ambil hasil evaluasi terakhir untuk rentang waktu yang dipilih."""
    return _latest_or_run(_parse_days(days))


@router.get("/confusion-matrix")
def get_confusion_matrix(days: int = Query(7)) -> Dict[str, Any]:
    """Return hanya confusion matrix 4x4 untuk render tabel UI."""
    result = _latest_or_run(_parse_days(days))
    return {
        "classes": result.get("classes", CLASSES),
        "confusion_matrix": result.get("confusion_matrix", {}),
    }


@router.get("/export-csv")
def export_evaluation_csv(days: int = Query(7)):
    """Export confusion matrix + metrik evaluasi terbaru sebagai CSV."""
    result = _latest_or_run(_parse_days(days))
    csv_content = _build_evaluation_csv(result)
    data_bytes = csv_content.encode("utf-8-sig")
    return StreamingResponse(
        io.BytesIO(data_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="weblog_ids_evaluation.csv"'},
    )

