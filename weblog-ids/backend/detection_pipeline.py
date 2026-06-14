"""
detection_pipeline.py - Orkestrasi alur deteksi end-to-end.

Menggabungkan komponen yang sudah dibuat menjadi satu fungsi yang dipanggil
untuk setiap baris log baru dari log_watcher:

    parse -> preprocess -> rule match -> classify -> severity -> recommend
          -> simpan ke access_logs -> simpan ke detection_results

Modul ini sengaja dipisah dari log_watcher agar logika "apa yang dilakukan
terhadap satu baris log" bisa diuji terpisah dari mekanisme membaca file.
"""

from typing import Optional, Dict, Any, List

import os
import sys
import asyncio

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database
from app_state import app_state
from services.alert_service import manager
from services.nginx_parser import parse_log_line
from services.preprocessor import build_payload
from services.rule_engine import load_rules, match_rules
from services.classifier import (
    classify,
    determine_severity,
    generate_recommendation,
)

# Label yang dianggap serangan dan memicu alert WebSocket.
_ATTACK_LABELS = ("XSS", "SQLi", "Multiple")


class DetectionPipeline:
    """Memproses baris log mentah menjadi hasil deteksi dan menyimpannya."""

    def __init__(self):
        # Rule dimuat sekali saat inisialisasi (precompiled) agar tiap baris
        # tidak perlu membaca ulang file JSON -- penting untuk performa realtime.
        self.rules = load_rules()
        print(f"[Pipeline] {len(self.rules)} rule dimuat.")

    def process_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Proses satu baris log. Mengembalikan dict ringkasan hasil deteksi,
        atau None bila baris invalid (di-skip, sesuai PRD cleaning).
        """
        # 1. Parse. Baris gagal parse -> skip tanpa menghentikan sistem.
        parsed = parse_log_line(line)
        if parsed is None:
            return None

        # 2. Preprocess: decode + normalisasi request_uri jadi payload.
        payload = build_payload(parsed)

        # 3. Rule matching terhadap payload ternormalisasi.
        matched = match_rules(payload["normalized_payload"], self.rules)

        # 4-6. Klasifikasi, severity, rekomendasi.
        label = classify(matched)
        severity = determine_severity(matched)
        recommendation = generate_recommendation(
            label, severity, parsed.get("ip", ""), parsed.get("request_uri", "")
        )

        hasil_deteksi = {
            "decoded_payload": payload["decoded_payload"],
            "normalized_payload": payload["normalized_payload"],
            "label": label,
            "severity": severity,
            "matched_rules": matched,
            "recommendation": recommendation,
        }

        # 7-8. Simpan access_log lalu detection_result yang terhubung via log_id.
        log_id = database.save_access_log(parsed)
        detection_id = database.save_detection_result(log_id, hasil_deteksi)

        # 9. Jika ini serangan (bukan Normal), kirim alert realtime ke WebSocket.
        if label in _ATTACK_LABELS:
            alert_payload = {
                "timestamp": parsed.get("timestamp"),
                "ip": parsed.get("ip"),
                "method": parsed.get("method"),
                "request_uri": parsed.get("request_uri"),
                "decoded_payload": payload["decoded_payload"],
                "label": label,
                "severity": severity,
                "matched_rules": [m["id"] for m in matched],
                "recommendation": recommendation,
            }
            self._broadcast_alert(alert_payload)

        return {
            "log_id": log_id,
            "detection_id": detection_id,
            "ip": parsed.get("ip"),
            "request_uri": parsed.get("request_uri"),
            "label": label,
            "severity": severity,
            "matched_rules": [m["id"] for m in matched],
        }

    def _broadcast_alert(self, alert_payload: Dict[str, Any]) -> None:
        """
        Kirim alert ke WebSocket clients dengan aman dari konteks thread.

        TITIK TEKNIS PENTING (threading vs asyncio):
        process_line() dipanggil dari thread log watcher yang sinkron, sedangkan
        manager.broadcast() adalah coroutine yang HARUS berjalan di event loop
        FastAPI. Memanggil coroutine langsung dari thread lain tidak akan jalan.

        Solusinya: pakai asyncio.run_coroutine_threadsafe() untuk menjadwalkan
        coroutine broadcast ke loop utama (referensinya disimpan di
        app_state.loop saat startup). Ini cara aman menyeberangkan pekerjaan
        async dari thread sinkron ke event loop.
        """
        loop = app_state.loop
        if loop is None:
            # Loop belum siap (mis. pipeline dipakai di luar FastAPI) -> lewati.
            return
        try:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(alert_payload), loop
            )
        except Exception as e:
            # Kegagalan broadcast tidak boleh menjatuhkan pemrosesan log.
            print(f"[Pipeline] Gagal broadcast alert: {e}")


# ---------------------------------------------------------------------------
# Uji mandiri:  python detection_pipeline.py
# Memproses beberapa baris log uji dan menyimpannya ke MySQL.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    database.init_db()
    pipeline = DetectionPipeline()

    sample_lines = [
        '45.1.1.1 - - [14/Jun/2026:12:00:00 +0800] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 100 "-" "ua"',
        '45.2.2.2 - - [14/Jun/2026:12:00:01 +0800] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20or%201%3D1--&Submit=Submit HTTP/1.1" 200 120 "-" "ua"',
        '45.5.5.5 - - [14/Jun/2026:12:00:04 +0800] "GET /login.php HTTP/1.1" 200 644 "-" "Mozilla/5.0"',
    ]
    for line in sample_lines:
        result = pipeline.process_line(line)
        print(result)
