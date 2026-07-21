"""
dashboard_routes.py - Endpoint REST untuk ringkasan & statistik dashboard.

Statistik agregat dihitung di sisi database (COUNT + GROUP BY) sebisa mungkin,
bukan di-loop di Python, agar efisien walau data besar. Semua query
parameterized (%s).

Filter opsional `days` (7/14/30) membatasi data ke N hari terakhir berdasarkan
detection_results.created_at (DATETIME insert), bukan access_logs.timestamp
(VARCHAR mentah Nginx).
"""

import json
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple

import os
import sys

from fastapi import APIRouter, Query, HTTPException

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database
from app_state import app_state

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# Rentang hari yang diizinkan di UI dashboard.
_ALLOWED_DAYS = frozenset({7, 14, 30})


def _parse_days(days: Optional[int]) -> Optional[int]:
    """Validasi query days: None = semua waktu; selain itu harus 7/14/30."""
    if days is None:
        return None
    if days not in _ALLOWED_DAYS:
        raise HTTPException(
            status_code=400,
            detail="Parameter days harus 7, 14, atau 30 (atau dikosongkan).",
        )
    return days


def _days_filter(days: Optional[int], column: str = "created_at") -> Tuple[str, List[Any]]:
    """
    Bangun fragmen SQL + param untuk filter N hari terakhir.
    column: nama kolom DATETIME (biasanya detection_results.created_at).
    """
    if days is None:
        return "", []
    return f" AND {column} >= NOW() - INTERVAL %s DAY", [days]


@router.get("/summary")
def get_summary(
    days: Optional[int] = Query(
        None,
        description="Filter N hari terakhir (7/14/30). Kosong = semua waktu.",
    ),
) -> Dict[str, Any]:
    """
    Ringkasan angka untuk kartu dashboard. Jumlah per label dihitung lewat
    satu query GROUP BY (bukan loop Python), lalu dipetakan ke field spesifik.

    SQL (tanpa filter):
        SELECT label, COUNT(*) AS jumlah
        FROM detection_results
        GROUP BY label

    Dengan days=N:
        ... WHERE created_at >= NOW() - INTERVAL N DAY ...
    """
    days = _parse_days(days)
    where_extra, params = _days_filter(days, "created_at")
    # WHERE 1=1 memudahkan append AND opsional tanpa cabang SQL terpisah.
    sql = (
        "SELECT label, COUNT(*) AS jumlah FROM detection_results"
        f" WHERE 1=1{where_extra}"
        " GROUP BY label"
    )
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
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
        "days": days,
        "watcher_running": app_state.is_watcher_running(),
    }


@router.get("/top-attacker-ip")
def get_top_attacker_ip(
    limit: int = Query(10, ge=1, le=100),
    days: Optional[int] = Query(
        None,
        description="Filter N hari terakhir (7/14/30). Kosong = semua waktu.",
    ),
) -> Dict[str, Any]:
    """
    Top IP penyerang berdasarkan jumlah deteksi berlabel serangan (bukan Normal).
    Dihitung dengan GROUP BY ip + ORDER BY desc di database.
    """
    days = _parse_days(days)
    where_extra, day_params = _days_filter(days, "d.created_at")
    sql = f"""
        SELECT a.ip, COUNT(*) AS jumlah
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.label <> %s{where_extra}
        GROUP BY a.ip
        ORDER BY jumlah DESC
        LIMIT %s
    """
    params: List[Any] = ["Normal", *day_params, limit]
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "data": rows, "days": days}


@router.get("/attack-types")
def get_attack_types(
    days: Optional[int] = Query(
        None,
        description="Filter N hari terakhir (7/14/30). Kosong = semua waktu.",
    ),
) -> Dict[str, Any]:
    """
    Jumlah deteksi per label (untuk grafik pie/bar). Memakai GROUP BY label.
    """
    days = _parse_days(days)
    where_extra, params = _days_filter(days, "created_at")
    sql = f"""
        SELECT label, COUNT(*) AS jumlah
        FROM detection_results
        WHERE 1=1{where_extra}
        GROUP BY label
        ORDER BY jumlah DESC
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    finally:
        conn.close()
    return {"count": len(rows), "data": rows, "days": days}


@router.get("/rule-triggered")
def get_rule_triggered(
    limit: int = Query(10, ge=1, le=100),
    days: Optional[int] = Query(
        None,
        description="Filter N hari terakhir (7/14/30). Kosong = semua waktu.",
    ),
) -> Dict[str, Any]:
    """
    Rule yang paling sering terpicu. Karena matched_rules disimpan sebagai TEXT
    berisi JSON (mis. ["XSS-001","SQLI-002"]), agregasi murni SQL sulit/tidak
    portabel. Maka kolom dibaca lalu frekuensi tiap rule_code dihitung di Python
    pakai Counter. Hanya kolom matched_rules yang diambil agar tetap ringan.
    """
    days = _parse_days(days)
    where_extra, params = _days_filter(days, "created_at")
    sql = f"""
        SELECT matched_rules
        FROM detection_results
        WHERE matched_rules IS NOT NULL AND matched_rules <> '[]'{where_extra}
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
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
    return {"count": len(data), "data": data, "days": days}
