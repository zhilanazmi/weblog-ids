"""
report_service.py - Membuat isi CSV dari hasil deteksi.

Mengambil data gabungan access_logs + detection_results dari MySQL lalu
menulisnya menjadi CSV memakai modul csv bawaan Python (ringan, tanpa
dependency tambahan).
"""

import csv
import io
import json
from typing import Optional, Dict, Any

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database

# Kolom CSV sesuai permintaan. Didefinisikan sekali agar header dan urutan
# penulisan baris konsisten.
CSV_COLUMNS = [
    "timestamp",
    "ip",
    "method",
    "request_uri",
    "decoded_payload",
    "label",
    "severity",
    "matched_rules",
    "recommendation",
]


def _format_matched_rules(raw: Optional[str]) -> str:
    """
    matched_rules tersimpan sebagai TEXT JSON (mis. '["XSS-001","XSS-004"]').
    Untuk CSV, kita gabung menjadi string dipisah ';' (mis. "XSS-001;XSS-004").

    Alasan pilihan: dipisah ';' lebih mudah dibaca di spreadsheet daripada
    tanda kurung/kutip JSON, dan ';' tidak bentrok dengan koma pemisah kolom CSV.
    """
    if not raw:
        return ""
    try:
        codes = json.loads(raw)
        if isinstance(codes, list):
            return ";".join(str(c) for c in codes)
    except (json.JSONDecodeError, TypeError):
        pass
    return str(raw)


def build_detections_csv(filters: Optional[Dict[str, Any]] = None) -> str:
    """
    Ambil data deteksi (opsional difilter label) lalu kembalikan isi CSV
    sebagai string.

    filters: dict opsional, mendukung key 'label' (Normal/XSS/SQLi/Multiple).
    Query parameterized (%s) untuk mencegah SQL injection.

    SQL:
        SELECT a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        [WHERE d.label = %s]
        ORDER BY d.id DESC
    """
    filters = filters or {}
    label = filters.get("label")

    base = """
        SELECT a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
    """
    params = []
    if label:
        base += " WHERE d.label = %s"
        params.append(label)
    base += " ORDER BY d.id DESC"

    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(base, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()

    # Tulis ke buffer string memakai csv.writer agar quoting/escaping otomatis
    # ditangani (mis. nilai yang mengandung koma atau kutip).
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)  # baris header

    for r in rows:
        writer.writerow(
            [
                r.get("timestamp", ""),
                r.get("ip", ""),
                r.get("method", ""),
                r.get("request_uri", ""),
                r.get("decoded_payload", ""),
                r.get("label", ""),
                r.get("severity", ""),
                _format_matched_rules(r.get("matched_rules")),
                r.get("recommendation", ""),
            ]
        )

    return buffer.getvalue()
