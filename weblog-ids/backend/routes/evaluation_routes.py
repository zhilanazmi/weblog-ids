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

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from evaluation.evaluator import CLASSES, run_evaluation, get_latest_evaluation_run

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


def _latest_or_run() -> Dict[str, Any]:
    """Ambil evaluasi terbaru; bila belum ada, jalankan evaluasi baru."""
    latest = get_latest_evaluation_run()
    if latest is not None:
        return latest
    return run_evaluation()


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
def run_evaluation_endpoint() -> Dict[str, Any]:
    """Jalankan evaluasi dari semua record yang sudah memiliki actual_label."""
    return run_evaluation()


@router.get("/results")
def get_results() -> Dict[str, Any]:
    """Ambil hasil evaluasi terakhir; jika belum ada, jalankan evaluasi baru."""
    return _latest_or_run()


@router.get("/confusion-matrix")
def get_confusion_matrix() -> Dict[str, Any]:
    """Return hanya confusion matrix 4x4 untuk render tabel UI."""
    result = _latest_or_run()
    return {
        "classes": result.get("classes", CLASSES),
        "confusion_matrix": result.get("confusion_matrix", {}),
    }


@router.get("/export-csv")
def export_evaluation_csv():
    """Export confusion matrix + metrik evaluasi terbaru sebagai CSV."""
    result = _latest_or_run()
    csv_content = _build_evaluation_csv(result)
    data_bytes = csv_content.encode("utf-8-sig")
    return StreamingResponse(
        io.BytesIO(data_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="weblog_ids_evaluation.csv"'},
    )
