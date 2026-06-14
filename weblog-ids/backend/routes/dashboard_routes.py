"""
dashboard_routes.py - Endpoint REST untuk ringkasan & statistik dashboard.

Statistik agregat dihitung di sisi database (COUNT + GROUP BY) sebisa mungkin,
bukan di-loop di Python, agar efisien walau data besar. Semua query
parameterized (%s).
"""

import json
from collections import Counter
from typing import Dict, Any, List

import os
import sys

from fastapi import APIRouter, Query

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database
from app_state import app_state

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_summary() -> Dict[str, Any]:
    """
    Ringkasan angka untuk kartu dashboard. Jumlah per label dihitung lewat
    satu query GROUP BY (bukan loop Python), lalu dipetakan ke field spesifik.

    SQL:
        SELECT label, COUNT(*) AS jumlah
        FROM detection_results
        GROUP BY label
    """
    sql = "SELECT label, COUNT(*) AS jumlah FROM detection_results GROUP BY label"
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    finally:
        conn.close()

    # Petakan hasil GROUP BY ke dict {label: jumlah} agar mudah diambil.
    by_label = {r["label"]: r["jumlah"] for r in rows}
    total_normal = by_label.get("Normal", 0)
    total_xss = by_label.get("XSS", 0)
    total_sqli = by_label.get("SQLi", 0)
    total_multiple = by_label.get("Multiple", 0)
    total_logs = sum(by_label.values())
    # total_alert = semua deteksi yang bukan Normal.
    total_alert = total_logs - total_normal

    return {
        "total_logs": total_logs,
        "total_normal": total_normal,
        "total_xss": total_xss,
        "total_sqli": total_sqli,
        "total_multiple": total_multiple,
        "total_alert": total_alert,
        "watcher_running": app_state.is_watcher_running(),
    }


@router.get("/top-attacker-ip")
def get_top_attacker_ip(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    """
    Top IP penyerang berdasarkan jumlah deteksi berlabel serangan (bukan Normal).
    Dihitung dengan GROUP BY ip + ORDER BY desc di database.

    SQL:
        SELECT a.ip, COUNT(*) AS jumlah
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.label <> %s
        GROUP BY a.ip
        ORDER BY jumlah DESC
        LIMIT %s
    """
    sql = """
        SELECT a.ip, COUNT(*) AS jumlah
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.label <> %s
        GROUP BY a.ip
        ORDER BY jumlah DESC
        LIMIT %s
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, ("Normal", limit))
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "data": rows}


@router.get("/attack-types")
def get_attack_types() -> Dict[str, Any]:
    """
    Jumlah deteksi per label (untuk grafik pie/bar). Memakai GROUP BY label.

    SQL:
        SELECT label, COUNT(*) AS jumlah
        FROM detection_results
        GROUP BY label
        ORDER BY jumlah DESC
    """
    sql = """
        SELECT label, COUNT(*) AS jumlah
        FROM detection_results
        GROUP BY label
        ORDER BY jumlah DESC
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "data": rows}


@router.get("/rule-triggered")
def get_rule_triggered(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    """
    Rule yang paling sering terpicu. Karena matched_rules disimpan sebagai TEXT
    berisi JSON (mis. ["XSS-001","SQLI-002"]), agregasi murni SQL sulit/tidak
    portabel. Maka kolom dibaca lalu frekuensi tiap rule_code dihitung di Python
    pakai Counter. Hanya kolom matched_rules yang diambil agar tetap ringan.

    SQL:
        SELECT matched_rules
        FROM detection_results
        WHERE matched_rules IS NOT NULL AND matched_rules <> '[]'
    """
    sql = """
        SELECT matched_rules
        FROM detection_results
        WHERE matched_rules IS NOT NULL AND matched_rules <> '[]'
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    finally:
        conn.close()

    counter: Counter = Counter()
    for r in rows:
        raw = r.get("matched_rules")
        if not raw:
            continue
        try:
            codes = json.loads(raw)  # parse JSON list rule_code
        except (json.JSONDecodeError, TypeError):
            continue
        counter.update(codes)

    # Counter.most_common sudah terurut desc; potong sesuai limit.
    data = [
        {"rule_code": code, "jumlah": jumlah}
        for code, jumlah in counter.most_common(limit)
    ]
    return {"count": len(data), "data": data}
