"""
matcher.py - Pencocokan ground truth (dari generator) dengan hasil deteksi IDS.

Ground truth disimpan oleh attack_generator dengan payload mentah dan waktu kirim.
Log Nginx menyimpan request_uri yang mungkin ter-URL-encode, jadi pencocokan
konten dilakukan setelah URL-decode pada kedua sisi, dikombinasikan dengan
toleransi waktu.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database


def _norm(text: Optional[str]) -> str:
    """Normalisasi teks untuk perbandingan: URL-decode berulang + lowercase."""
    if not text:
        return ""
    prev = str(text)
    for _ in range(3):
        new = unquote(prev)
        if new == prev:
            break
        prev = new
    return prev.lower()


def _fetch_unlabeled_detections() -> List[Dict[str, Any]]:
    """Ambil hasil deteksi yang belum punya actual_label, beserta konteks log."""
    sql = """
        SELECT d.id, d.created_at, d.decoded_payload, d.normalized_payload,
               a.request_uri
        FROM detection_results d
        JOIN access_logs a ON a.id = d.log_id
        WHERE d.actual_label IS NULL
        ORDER BY d.id ASC
    """
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _fetch_recent_ground_truth(hours: int = 24) -> List[Dict[str, Any]]:
    """Ambil ground truth yang dikirim dalam rentang waktu terakhir."""
    sql = """
        SELECT id, sent_at, request_uri, payload, actual_label
        FROM ground_truth
        WHERE sent_at >= %s
        ORDER BY id ASC
    """
    since = datetime.now() - timedelta(hours=hours)
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (since,))
            return cur.fetchall()
    finally:
        conn.close()


def _content_matches(det: Dict[str, Any], gt: Dict[str, Any]) -> bool:
    """True bila payload/URI ground truth muncul pada URI/payload deteksi."""
    det_uri = _norm(det.get("request_uri"))
    det_dec = _norm(det.get("decoded_payload"))
    det_npl = _norm(det.get("normalized_payload"))
    gt_uri = _norm(gt.get("request_uri"))
    gt_pay = _norm(gt.get("payload"))

    haystacks = [h for h in (det_uri, det_dec, det_npl) if h]
    needles = [n for n in (gt_pay, gt_uri) if n]
    if not needles or not haystacks:
        return False
    for n in needles:
        for h in haystacks:
            if n in h:
                return True
    return False


def match_ground_truth(tolerance_seconds: int = 8, hours: int = 24) -> Dict[str, Any]:
    """
    Cocokkan hasil deteksi yang belum dilabeli dengan ground truth.

    Kriteria cocok: selisih waktu (detection.created_at vs ground_truth.sent_at)
    <= tolerance_seconds DAN konten payload/URI cocok setelah URL-decode.
    Satu ground truth dipakai maksimal satu kali (dikonsumsi berurutan).
    """
    detections = _fetch_unlabeled_detections()
    ground_truths = _fetch_recent_ground_truth(hours)

    tol = timedelta(seconds=tolerance_seconds)
    used_gt = set()
    updates = []

    for det in detections:
        det_time = det.get("created_at")
        if not isinstance(det_time, datetime):
            continue
        best = None
        for gt in ground_truths:
            if gt["id"] in used_gt:
                continue
            gt_time = gt.get("sent_at")
            if not isinstance(gt_time, datetime):
                continue
            if abs(det_time - gt_time) > tol:
                continue
            if _content_matches(det, gt):
                best = gt
                break
        if best is not None:
            used_gt.add(best["id"])
            updates.append((best["actual_label"], best["id"], det["id"]))

    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.executemany(
                """
                UPDATE detection_results
                SET actual_label = %s, labeled_at = NOW(),
                    labeled_by = 'generator', ground_truth_id = %s
                WHERE id = %s
                """,
                updates,
            )
    finally:
        conn.close()

    matched = len(updates)
    unmatched = len(detections) - matched
    print(f"[Matcher] matched={matched} unmatched={unmatched}")
    return {
        "matched": matched,
        "unmatched": unmatched,
        "message": f"{matched} record cocok dengan ground truth, {unmatched} belum cocok.",
    }


def mark_unlabeled_as_normal() -> Dict[str, Any]:
    """Label semua record yang belum dilabeli sebagai Normal (background request)."""
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE detection_results
                SET actual_label = 'Normal', labeled_at = NOW(), labeled_by = 'auto-normal'
                WHERE actual_label IS NULL
                """
            )
            updated = cur.rowcount
    finally:
        conn.close()
    print(f"[Matcher] auto-normal updated={updated}")
    return {"updated": updated}
