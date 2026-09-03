"""
send_live_payloads.py - Kirim 13 payload uji tahapan ke DVWA live, lalu
verifikasi hasil deteksi WebLog-IDS end-to-end.

Alur:
1. Kirim P01-P13 (payload mentah persis seperti di test_preprocessing_stages)
   ke endpoint DVWA yang sesuai (XSS -> xss_r, SQLi -> sqli), TANPA
   re-encoding -- payload sudah berbentuk percent-encoded.
   (DVWA sudah dikonfigurasi tanpa login.)
2. Polling API backend /api/logs sampai semua request muncul dengan hasil
   deteksinya (watcher butuh waktu; default tunggu maks. 30 detik).
3. Bandingkan matched_rules live vs matriks offline level 4 (dihitung ulang
   via harness yang sama) -> konsisten = pipeline produksi terverifikasi.

Contoh pemakaian di server (folder backend/):
    python send_live_payloads.py \
        --target https://dvwa.zhillanazmi.id \
        --backend http://localhost:8000

Argumen bisa juga lewat env: DVWA_TARGET, BACKEND_URL.
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# Reuse daftar payload + matriks offline dari harness (single source of truth).
from test_preprocessing_stages import PAYLOADS, LEVELS, run_matrix
from services import rule_engine

# Endpoint DVWA (sama dengan attack_generator/generator.py).
XSS_ENDPOINT = "/vulnerabilities/xss_r/?name="
SQLI_ENDPOINT = "/vulnerabilities/sqli/?id="
XSS_PAYLOAD_IDS = {"P01", "P02", "P03", "P04", "P05"}


def send_payloads(
    target: str, session: requests.Session, delay: float
) -> List[Tuple[str, str, str]]:
    """
    Kirim P01-P13 ke DVWA. Return list (pid, raw_payload, sent_query) dengan
    sent_query = query string persis yang diterima server (untuk pencocokan
    log; requests mempreservasi percent-encoding yang sudah ada dan hanya
    meng-encode karakter ilegal seperti spasi -> %20).
    """
    sent: List[Tuple[str, str, str]] = []
    for pid, raw in PAYLOADS:
        if pid in XSS_PAYLOAD_IDS:
            url = target + XSS_ENDPOINT + raw
        else:
            url = target + SQLI_ENDPOINT + raw + "&Submit=Submit"
        try:
            r = session.get(url, timeout=15, verify=False)
            sent_query = r.request.url.split("?", 1)[-1] if "?" in r.request.url else ""
            print(
                f"[Kirim] {pid} -> HTTP {r.status_code} | query: {sent_query[:70]}"
                + ("..." if len(sent_query) > 70 else "")
            )
            sent.append((pid, raw, sent_query))
        except Exception as e:  # noqa: BLE001
            print(f"[Kirim] {pid} GAGAL: {e}")
        time.sleep(delay)
    return sent


def fetch_detections(backend: str, limit: int = 200) -> List[Dict]:
    """Ambil log terbaru + hasil deteksinya dari API backend."""
    r = requests.get(
        backend.rstrip("/") + f"/api/logs?limit={limit}", timeout=15
    )
    r.raise_for_status()
    return r.json().get("data", [])


def wait_for_detections(
    backend: str, sent: List[Tuple[str, str, str]], timeout_s: float, poll_s: float
) -> Dict[str, Dict]:
    """
    Polling /api/logs sampai setiap payload yang dikirim muncul di log DAN
    sudah punya hasil deteksi (label tidak None). Return mapping pid -> row.
    """
    deadline = time.time() + timeout_s
    found: Dict[str, Dict] = {}
    while time.time() < deadline and len(found) < len(sent):
        try:
            rows = fetch_detections(backend, limit=300)
        except Exception as e:  # noqa: BLE001
            print(f"[Verify] gagal polling backend: {e}")
            rows = []
        for pid, raw, sent_query in sent:
            if pid in found:
                continue
            for row in rows:
                uri = row.get("request_uri") or ""
                # Cocokkan via query persis yang dikirim; fallback substring
                # payload mentah (log menyimpan URI persis seperti diterima).
                if sent_query and sent_query in uri:
                    found[pid] = row
                    break
        if len(found) < len(sent):
            time.sleep(poll_s)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Uji live 13 payload tahapan terhadap DVWA + WebLog-IDS."
    )
    parser.add_argument(
        "--target",
        default=os.getenv("DVWA_TARGET", "https://dvwa.zhillanazmi.id"),
        help="Base URL DVWA lewat Nginx",
    )
    parser.add_argument(
        "--backend",
        default=os.getenv("BACKEND_URL", "http://localhost:8001"),
        help="Base URL backend WebLog-IDS (untuk verifikasi deteksi)",
    )
    parser.add_argument(
        "--delay", type=float, default=1.0, help="Jeda antar request (detik)"
    )
    parser.add_argument(
        "--wait", type=float, default=30.0, help="Maks. waktu tunggu deteksi (detik)"
    )
    args = parser.parse_args()

    target = args.target.rstrip("/")
    backend = args.backend.rstrip("/")

    # Matriks offline sebagai ekspektasi (level 4 = pipeline produksi).
    rules = rule_engine.load_rules()
    offline_matrix, _ = run_matrix(rules)
    print(f"[Setup] {len(rules)} rule dimuat; ekspektasi = matriks offline T4.")
    print(f"[Setup] Target DVWA : {target}")
    print(f"[Setup] Backend IDS : {backend}")
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "WebLog-IDS-StageTest/1.0"

    sent = send_payloads(target, session, args.delay)
    if not sent:
        print("[Selesai] Tidak ada payload terkirim; hentikan.")
        return 1
    print()

    print(f"[Verify] Menunggu watcher memproses log (maks {args.wait:.0f}s)...")
    found = wait_for_detections(backend, sent, args.wait, poll_s=2.0)

    # --- Tabel perbandingan offline vs live ---
    header = (
        f"{'Payload':<8}{'Label live':<12}{'Rule live (T4)':<28}"
        f"{'Rule offline T4':<28}{'Status'}"
    )
    print()
    print("PERBANDINGAN DETEKSI: LIVE vs OFFLINE (LEVEL 4)")
    print(header)
    print("-" * len(header))
    match_count = 0
    for pid, raw, _ in sent:
        row = found.get(pid)
        if row is None:
            print(f"{pid:<8}{'(tidak ditemukan)':<12}{'-':<28}", end="")
            print(f"{'-':<28}MISSING di log/backend")
            continue
        live_label = row.get("label") or "(belum diproses)"
        raw_matched = row.get("matched_rules")
        try:
            live_rules = json.loads(raw_matched) if raw_matched else []
        except (TypeError, ValueError):
            live_rules = []
        expected = offline_matrix[(pid, 4)]
        status = "OK" if sorted(live_rules) == sorted(expected) else "BEDA"
        if status == "OK":
            match_count += 1
        print(
            f"{pid:<8}{live_label:<12}"
            f"{(','.join(live_rules) or '-'):<28}"
            f"{(','.join(expected) or '-'):<28}{status}"
        )
    print()
    print(
        f"[Hasil] {match_count}/{len(sent)} payload konsisten offline vs live."
    )
    if len(found) < len(sent):
        missing = [pid for pid, _, _ in sent if pid not in found]
        print(
            f"[Hasil] Payload belum muncul/terdeteksi di backend: {', '.join(missing)}"
            " (perpanjang --wait bila watcher lambat)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
