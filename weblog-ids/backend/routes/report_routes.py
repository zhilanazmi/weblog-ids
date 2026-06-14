"""
report_routes.py - Endpoint export hasil deteksi ke CSV.

Mengembalikan file CSV sebagai unduhan (attachment) sehingga browser langsung
menyimpannya sebagai file.
"""

import io
from datetime import datetime
from typing import Optional

import os
import sys

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services.report_service import build_detections_csv

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/export-csv")
def export_csv(label: Optional[str] = Query(None)):
    """
    Export hasil deteksi ke CSV. Filter opsional: label.

    - Isi CSV dibuat oleh report_service.build_detections_csv().
    - Encoding utf-8-sig: menambahkan BOM di awal file agar Excel mengenali
      file sebagai UTF-8, sehingga payload berisi karakter khusus (mis. <script>,
      tanda kutip) tetap tampil rapi, tidak jadi karakter aneh.
    - StreamingResponse + header Content-Disposition: attachment memicu browser
      mengunduh file alih-alih menampilkannya.
    - Nama file diberi timestamp agar tiap unduhan unik dan mudah diarsipkan.
    """
    csv_content = build_detections_csv({"label": label} if label else {})

    # Encode dengan utf-8-sig (BOM) untuk kompatibilitas Excel.
    data_bytes = csv_content.encode("utf-8-sig")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"weblog_ids_detections_{timestamp}.csv"

    return StreamingResponse(
        io.BytesIO(data_bytes),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
