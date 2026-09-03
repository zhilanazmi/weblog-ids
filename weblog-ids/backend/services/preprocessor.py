"""
preprocessor.py - Decoding & normalisasi request sebelum rule matching.

Tahapan (PRD 1.5.5), bisa dikendalikan per level lewat PREPROCESS_LEVEL
(config.py / env var, default 4 = pipeline penuh):
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


def preprocess_payload(value: str, level: Optional[int] = None) -> str:
    """
    Jalankan pipeline preprocessing sesuai level tahapan (1-4).

    Level dikendalikan parameter `level` atau config.PREPROCESS_LEVEL
    (env PREPROCESS_LEVEL, default 4 = pipeline penuh):
        1: URL-decode SATU kali (unquote_plus sekali).
        2: level 1 + recursive decode hingga total maks. MAX_DECODE_ROUND
           kali (berhenti lebih awal bila string sudah tidak berubah).
        3: level 2 + lowercasing seluruh string.
        4: level 3 + trim whitespace ujung + normalisasi whitespace
           (tab/newline/spasi ganda) menjadi spasi tunggal.

    Dipakai harness pengujian bertahap; build_payload memakai fungsi ini
    dengan level dari konfigurasi sehingga perilaku produksi (level 4)
    tetap identik dengan pipeline lama.
    """
    if value is None:
        return ""

    resolved = config.PREPROCESS_LEVEL if level is None else level
    resolved = max(1, min(4, int(resolved)))

    current = value
    if resolved == 1:
        current = unquote_plus(current)
    else:
        # Level >= 2: recursive decode (sudah mencakup decode pertama,
        # total maks. MAX_DECODE_ROUND kali, berhenti bila stabil).
        current = recursive_decode(current)
    if resolved >= 3:
        current = current.lower()
    if resolved >= 4:
        current = re.sub(r"\s+", " ", current).strip()
    return current


def build_payload(
    parsed: Dict[str, Any], level: Optional[int] = None
) -> Dict[str, str]:
    """
    Bangun payload inspeksi dari hasil parsing log.

    Fokus inspeksi adalah request_uri (path + query string + nilai parameter),
    karena payload XSS/SQLi umumnya muncul di sana (PRD 1.5.4).

    Parameter `level` (opsional, default None -> config.PREPROCESS_LEVEL)
    mengendalikan kedalaman pipeline preprocessing; default mempertahankan
    perilaku produksi (level 4).

    Mengembalikan dict:
        - decoded_payload    : request_uri setelah tahap decode saja
        - normalized_payload : hasil preprocessing penuh pada level aktif
    """
    request_uri = (parsed or {}).get("request_uri") or ""
    resolved = config.PREPROCESS_LEVEL if level is None else level
    resolved = max(1, min(4, int(resolved)))

    decoded = preprocess_payload(request_uri, min(resolved, 2))
    normalized = preprocess_payload(request_uri, resolved)
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
    print(f"[Preprocessor] PREPROCESS_LEVEL aktif: {config.PREPROCESS_LEVEL}")
    for t in tests:
        print("RAW    :", t)
        for lv in (1, 2, 3, 4):
            print(f"L{lv}     :", repr(preprocess_payload(t, lv)))
        print("-" * 60)
