"""
detection_routes.py - Endpoint REST untuk akses log & hasil deteksi.

Memakai APIRouter agar rute deteksi terpisah rapi dari rute lain (dashboard,
dst) dan mudah didaftarkan di main.py. Semua query parameterized (%s) untuk
mencegah SQL injection -- relevan karena data yang dikelola berasal dari
request berbahaya.
"""

from typing import Optional, List, Dict, Any

import os
import sys

from fastapi import APIRouter, Query

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database

router = APIRouter(prefix="/api", tags=["detections"])

# Label yang dianggap serangan (bukan Normal). Dipakai beberapa endpoint.
_ATTACK_LABELS = ("XSS", "SQLi", "Multiple")


@router.get("/logs")
def get_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    Daftar access_logs di-LEFT JOIN ke detection_results (sebagian log mungkin
    belum punya hasil deteksi). Urut terbaru dulu (id DESC).

    SQL:
        SELECT a.*, d.label, d.severity, d.matched_rules
        FROM access_logs a
        LEFT JOIN detection_results d ON d.log_id = a.id
        ORDER BY a.id DESC
        LIMIT %s OFFSET %s
    """
    sql = """
        SELECT a.id, a.ip, a.timestamp, a.method, a.request_uri, a.protocol,
               a.status_code, a.body_bytes_sent, a.referrer, a.user_agent,
               a.created_at,
               d.label, d.severity, d.matched_rules
        FROM access_logs a
        LEFT JOIN detection_results d ON d.log_id = a.id
        ORDER BY a.id DESC
        LIMIT %s OFFSET %s
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (limit, offset))
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "limit": limit, "offset": offset, "data": rows}


@router.get("/detections")
def get_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    label: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """
    Hasil deteksi gabungan access_logs + detection_results. Filter opsional
    berdasarkan label (Normal/XSS/SQLi/Multiple).

    Filter label dibangun kondisional namun nilainya tetap diteruskan sebagai
    parameter %s (bukan disisipkan ke string), supaya aman dari injeksi.

    SQL (tanpa filter):
        SELECT d.id, a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation, d.created_at
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        [WHERE d.label = %s]
        ORDER BY d.id DESC
        LIMIT %s OFFSET %s
    """
    base = """
        SELECT d.id, a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation, d.created_at
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
    """
    params: List[Any] = []
    if label:
        base += " WHERE d.label = %s"
        params.append(label)
    base += " ORDER BY d.id DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(base, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()
    return {
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "label": label,
        "data": rows,
    }


@router.get("/detections/latest")
def get_latest_detections(
    n: int = Query(10, ge=1, le=100),
) -> Dict[str, Any]:
    """
    N deteksi serangan TERBARU (label XSS/SQLi/Multiple) untuk panel alert.

    Memakai placeholder %s untuk tiap label di klausa IN agar tetap
    parameterized walau jumlah label dinamis.

    SQL:
        SELECT d.id, a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation, d.created_at
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.label IN (%s, %s, %s)
        ORDER BY d.id DESC
        LIMIT %s
    """
    placeholders = ", ".join(["%s"] * len(_ATTACK_LABELS))
    sql = f"""
        SELECT d.id, a.timestamp, a.ip, a.method, a.request_uri,
               d.decoded_payload, d.label, d.severity, d.matched_rules,
               d.recommendation, d.created_at
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.label IN ({placeholders})
        ORDER BY d.id DESC
        LIMIT %s
    """
    params = list(_ATTACK_LABELS) + [n]
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "data": rows}
