"""
generator.py - Logic utama generator serangan terkontrol.

AttackGenerator mengirim request ke DVWA (lewat Nginx) dan mencatat setiap
request ke tabel ground_truth dengan label aktual yang sesuai. Karena generator
mengetahui payload apa yang dikirim, label ini sah sebagai ground truth untuk
evaluasi akademik (pengujian terkontrol).
"""

import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import database
from attack_generator.payloads import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    MULTIPLE_PAYLOADS,
    NORMAL_REQUESTS,
)

# Endpoint DVWA untuk tiap jenis serangan.
XSS_ENDPOINT = "/vulnerabilities/xss_r/?name="
SQLI_ENDPOINT = "/vulnerabilities/sqli/?id="


def _insert_ground_truth(
    method: str, request_uri: str, payload: str, actual_label: str, source_ip: str = ""
) -> None:
    """Catat satu request yang dikirim ke tabel ground_truth."""
    conn = database.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ground_truth
                    (sent_at, source_ip, method, request_uri, payload, actual_label)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (datetime.now(), source_ip, method, request_uri, payload, actual_label),
            )
    finally:
        conn.close()


class AttackGenerator:
    """Mengirim skenario serangan/normal ke DVWA dan mencatat ground truth."""

    def __init__(
        self,
        target_url: str,
        delay: float = 0.5,
        source_ip: str = "",
        session: Optional[requests.Session] = None,
    ):
        """
        target_url: alamat DVWA lewat Nginx, mis. https://dvwa.zhilanazmi.id
        delay     : jeda antar request (detik) agar watcher sempat membaca log.
        source_ip : dicatat ke ground_truth (opsional, untuk dokumentasi).
        session   : requests.Session bila butuh cookie login DVWA.
        """
        self.target = target_url.rstrip("/")
        self.delay = delay
        self.source_ip = source_ip
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "WebLog-IDS-AttackGenerator/1.0")

    def _fire(self, uri: str, payload: str, label: str) -> bool:
        """Kirim satu request GET dan catat ground truth. Return True bila terkirim."""
        try:
            self.session.get(self.target + uri, timeout=15, verify=False)
            _insert_ground_truth("GET", uri, payload, label, self.source_ip)
            time.sleep(self.delay)
            return True
        except Exception as e:  # noqa: BLE001
            print(f"    [warn] gagal kirim {uri}: {e}")
            return False

    def _send_batch(self, uris: List[str], label: str, tag: str, count: Optional[int]) -> int:
        """Kirim batch URI (diulang sampai count), catat ground truth per item."""
        if not uris:
            return 0
        total = count if count is not None else len(uris)
        sent = 0
        i = 0
        while sent < total:
            uri = uris[i % len(uris)]
            payload = uri.split("=", 1)[1] if "=" in uri else ""
            if self._fire(uri, payload, label):
                sent += 1
                if sent % 5 == 0 or sent == total:
                    print(f"[{tag}] Sent {sent}/{total}...")
            i += 1
        return sent

    def send_xss(self, count: int = None) -> int:
        """Kirim payload XSS ke endpoint XSS DVWA. Catat ground truth 'XSS'."""
        uris = [XSS_ENDPOINT + quote(p) for p in XSS_PAYLOADS]
        return self._send_batch(uris, "XSS", "XSS", count)

    def send_sqli(self, count: int = None) -> int:
        """Kirim payload SQLi ke endpoint SQLi DVWA. Catat ground truth 'SQLi'."""
        uris = [SQLI_ENDPOINT + quote(p) + "&Submit=Submit" for p in SQLI_PAYLOADS]
        return self._send_batch(uris, "SQLi", "SQLi", count)

    def send_multiple(self, count: int = None) -> int:
        """Kirim payload campuran XSS+SQLi. Catat ground truth 'Multiple'."""
        uris = [XSS_ENDPOINT + quote(p) for p in MULTIPLE_PAYLOADS]
        return self._send_batch(uris, "Multiple", "MULTI", count)

    def send_normal(self, count: int = None) -> int:
        """Kirim request normal (browse halaman DVWA). Catat ground truth 'Normal'."""
        return self._send_batch(list(NORMAL_REQUESTS), "Normal", "NORMAL", count)

    def run_full_test(
        self, xss_count: int = 20, sqli_count: int = 20,
        normal_count: int = 20, multiple_count: int = 5,
    ) -> Dict[str, Any]:
        """Jalankan semua jenis request. Return ringkasan jumlah terkirim."""
        print(f"[Generator] Target: {self.target}")
        summary = {
            "target": self.target,
            "normal": self.send_normal(normal_count),
            "xss": self.send_xss(xss_count),
            "sqli": self.send_sqli(sqli_count),
            "multiple": self.send_multiple(multiple_count),
        }
        summary["total_sent"] = (
            summary["normal"] + summary["xss"] + summary["sqli"] + summary["multiple"]
        )
        print(f"[Generator] Selesai. Total terkirim: {summary['total_sent']}")
        return summary
