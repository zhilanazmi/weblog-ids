"""
preprocessor.py - Decoding & normalisasi request sebelum rule matching.

Tahapan (PRD 1.5.5):
1. recursive_decode: URL-decode berulang (max 3x) untuk menangani
   double/triple encoding, mis. %253Cscript%253E -> %3Cscript%3E -> <script>.
2. normalize: lowercase + rapikan whitespace agar rule matching konsisten.
3. build_payload: gabungkan bagian request yang relevan menjadi satu string
   payload untuk diinspeksi rule engine.
"""

from urllib.parse import unquote_plus
from typing import Optional, Dict, Any
import re

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config


def recursive_decode(value: str, max_round: int = None) -> str:
    """
    URL-decode sebuah string berulang kali hingga stabil atau mencapai
    batas max_round. Menangani payload yang di-encode lebih dari sekali.

    Contoh:
        %3Cscript%3Ealert(1)%3C%2Fscript%3E -> <script>alert(1)</script>
    """
    if value is None:
        return ""
    if max_round is None:
        max_round = config.MAX_DECODE_ROUND

    current = value
    for _ in range(max_round):
        decoded = unquote_plus(current)
        if decoded == current:
            # Sudah tidak ada perubahan -> berhenti lebih awal.
            break
        current = decoded
    return current


def normalize(value: str) -> str:
    """
    Normalisasi payload agar rule matching lebih konsisten:
    - lowercase
    - ubah whitespace (tab, newline, dll) menjadi spasi tunggal
    - hapus spasi berlebih dan trim ujung
    """
    if not value:
        return ""
    lowered = value.lower()
    # Satukan semua jenis whitespace menjadi spasi tunggal.
    collapsed = re.sub(r"\s+", " ", lowered)
    return collapsed.strip()


def build_payload(parsed: Dict[str, Any]) -> Dict[str, str]:
    """
    Bangun payload inspeksi dari hasil parsing log.

    Fokus inspeksi adalah request_uri (path + query string + nilai parameter),
    karena payload XSS/SQLi umumnya muncul di sana (PRD 1.5.4).

    Mengembalikan dict:
        - decoded_payload    : request_uri setelah recursive decode
        - normalized_payload : decoded_payload setelah normalisasi
    """
    request_uri = (parsed or {}).get("request_uri") or ""
    decoded = recursive_decode(request_uri)
    normalized = normalize(decoded)
    return {
        "decoded_payload": decoded,
        "normalized_payload": normalized,
    }


# ---------------------------------------------------------------------------
# Uji mandiri:  python services/preprocessor.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [
        "/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/vuln/?name=%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "/sqli/?id=1%27%20or%201%3D1--&Submit=Submit",
        "/login.php",
    ]
    for t in tests:
        decoded = recursive_decode(t)
        print("RAW    :", t)
        print("DECODED:", decoded)
        print("NORM   :", normalize(decoded))
        print("-" * 60)
