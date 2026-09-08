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
from services.time_utils import format_local_datetime_ms

# Kolom CSV sesuai permintaan. Didefinisikan sekali agar header dan urutan
# penulisan baris konsisten.
CSV_COLUMNS = [
    "timestamp",
    "log_time",
    "ip",
    "method",
    "request_uri",
    "decoded_payload",
    "label",
    "severity",
    "matched_rules",
    "latency_ms",
    "delta_ms",
    "recommendation",
]


# Kolom CSV export dataset access_logs (log mentah DVWA). Label hasil deteksi
# disertakan via LEFT JOIN agar dataset yang diunduh langsung punya anotasi
# kelas untuk keperluan analisis/pelatihan data.
ACCESS_LOG_CSV_COLUMNS = [
    "id",
    "timestamp",
    "log_time",
    "ip",
    "method",
    "request_uri",
    "protocol",
    "status_code",
    "body_bytes_sent",
    "referrer",
    "user_agent",
    "label",
    "raw_log",
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
        SELECT a.timestamp, a.log_time, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.latency_ms, d.delta_ms, d.recommendation
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
                format_local_datetime_ms(r.get("log_time")),
                r.get("ip", ""),
                r.get("method", ""),
                r.get("request_uri", ""),
                r.get("decoded_payload", ""),
                r.get("label", ""),
                r.get("severity", ""),
                _format_matched_rules(r.get("matched_rules")),
                r.get("latency_ms") if r.get("latency_ms") is not None else "",
                r.get("delta_ms") if r.get("delta_ms") is not None else "",
                r.get("recommendation", ""),
            ]
        )

    return buffer.getvalue()


def build_access_logs_csv(filters: Optional[Dict[str, Any]] = None) -> str:
    """
    Ambil seluruh dataset access_logs (log mentah DVWA) lalu kembalikan isi
    CSV sebagai string. Label hasil deteksi disertakan via LEFT JOIN sehingga
    tiap baris log langsung berpasangan dengan kelasnya (Normal/XSS/SQLi/
    Multiple) -- siap dipakai sebagai dataset untuk analisis.

    filters: dict opsional, mendukung key 'label' (Normal/XSS/SQLi/Multiple).
    Bila label diberikan, hanya baris access_logs dengan label tersebut yang
    diekspor. Query parameterized (%s) untuk mencegah SQL injection.

    ORDER BY a.id ASC: dataset diekspor urut kronologis (sesuai urutan baris
    log asli), bukan terbaru-dulu seperti halaman deteksi.
    """
    filters = filters or {}
    label = filters.get("label")

    base = """
        SELECT a.id, a.timestamp, a.log_time, a.ip, a.method, a.request_uri,
               a.protocol, a.status_code, a.body_bytes_sent, a.referrer,
               a.user_agent, d.label, a.raw_log
        FROM access_logs a
        LEFT JOIN detection_results d ON d.log_id = a.id
    """
    params = []
    if label:
        base += " WHERE d.label = %s"
        params.append(label)
    base += " ORDER BY a.id ASC"

    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(base, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(ACCESS_LOG_CSV_COLUMNS)

    for r in rows:
        writer.writerow(
            [
                r.get("id", ""),
                r.get("timestamp", ""),
                format_local_datetime_ms(r.get("log_time")),
                r.get("ip", ""),
                r.get("method", ""),
                r.get("request_uri", ""),
                r.get("protocol", ""),
                r.get("status_code") if r.get("status_code") is not None else "",
                r.get("body_bytes_sent") if r.get("body_bytes_sent") is not None else "",
                r.get("referrer", ""),
                r.get("user_agent", ""),
                r.get("label") or "",
                r.get("raw_log", ""),
            ]
        )

    return buffer.getvalue()
