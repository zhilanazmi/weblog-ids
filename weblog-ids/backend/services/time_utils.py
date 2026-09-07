"""
time_utils.py - Utilitas konversi/normalisasi waktu presisi milidetik.

Sumber waktu request ada dua (sesuai log_format Nginx yang dipakai):
1. Field tambahan ``msec=$msec`` -> epoch detik.milidetik (mis. 1788803495.969).
   Paling presisi dan bebas timezone, jadi diprioritaskan.
2. Bracket ``[$time_local]`` (mis. 08/Sep/2026:01:51:35 +0800) -> presisi
   detik; dipakai sebagai fallback bila msec tidak ada.

Konversi epoch -> datetime lokal memakai zona waktu MESIN backend (sama dengan
zona waktu MySQL yang mengisi created_at), sehingga selisih waktu request ->
alert (delta) dapat dihitung konsisten.

Asumsi jam: server Nginx dan mesin backend+MySQL harus sinkron (NTP) agar
delta mencerminkan delay end-to-end yang sebenarnya.
"""

import re
from datetime import datetime, timedelta
from typing import Optional

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# Field msec=<detik>.<milidetik> pada field tambahan log, mis. "msec=1788803495.969".
_MSEC_PATTERN = re.compile(r"\bmsec=(\d+(?:\.\d+)?)")

# Epoch murni (tanpa label "msec="), mis. bracket yang berisi $msec saja.
_EPOCH_PATTERN = re.compile(r"^(\d{9,11})(?:\.(\d{1,6}))?$")

# Format klasik $time_local Nginx, dengan/tanya milidetik, dengan offset tz.
_LOCAL_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S.%f %z",
)


def msec_to_epoch_ms(msec_value: str) -> Optional[int]:
    """
    Konversi nilai $msec ("1788803495.969") menjadi epoch milidetik (int).

    Pecahan dipotong/padding ke 3 digit milidetik.
    """
    if not msec_value:
        return None
    sec, _, frac = msec_value.partition(".")
    if not sec.isdigit():
        return None
    frac = (frac + "000")[:3]
    return int(sec) * 1000 + int(frac)


def parse_msec_field(extras: str) -> Optional[int]:
    """Cari 'msec=...' pada field tambahan log lalu konversi ke epoch ms."""
    m = _MSEC_PATTERN.search(extras or "")
    if not m:
        return None
    return msec_to_epoch_ms(m.group(1))


def parse_timestamp_ms(raw: Optional[str]) -> Optional[int]:
    """
    Parse bracket timestamp Nginx menjadi epoch milidetik (int), atau None.

    Mendukung: epoch murni ("1788803495.969"), $time_local klasik
    ("08/Sep/2026:01:51:35 +0800" / "...01:51:35.969 +0800"), dan ISO 8601.
    Baris tanpa offset timezone dianggap waktu lokal mesin backend.
    """
    if not raw:
        return None
    raw = raw.strip()

    m = _EPOCH_PATTERN.match(raw)
    if m:
        return msec_to_epoch_ms(raw)

    for fmt in _LOCAL_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue

    # ISO 8601 (mis. dari $time_iso8601): fromisoformat menangani offset.
    try:
        return int(datetime.fromisoformat(raw).timestamp() * 1000)
    except ValueError:
        return None


def epoch_ms_to_local_datetime(epoch_ms: int) -> datetime:
    """
    Konversi epoch ms -> datetime NAIF lokal (zona waktu mesin backend).

    Dipisah detik/milidetik agar tidak kena pembulatan float, karena nilai
    inilah yang disimpan ke kolom DATETIME(3) MySQL.
    """
    sec, ms_rem = divmod(int(epoch_ms), 1000)
    return datetime.fromtimestamp(sec) + timedelta(milliseconds=ms_rem)


def format_local_datetime_ms(dt: Optional[datetime]) -> str:
    """Format datetime -> "YYYY-MM-DD HH:MM:SS.mmm" (3 digit milidetik)."""
    if dt is None:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def format_epoch_ms_local(epoch_ms: Optional[int]) -> str:
    """Format epoch ms -> string lokal "YYYY-MM-DD HH:MM:SS.mmm"."""
    if epoch_ms is None:
        return "-"
    return format_local_datetime_ms(epoch_ms_to_local_datetime(epoch_ms))


# ---------------------------------------------------------------------------
# Uji mandiri:  python services/time_utils.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [
        ("msec field", parse_msec_field, "msec=1788803495.969 rt=0.006"),
        ("msec field kosong", parse_msec_field, "rt=0.006"),
        ("epoch murni", parse_timestamp_ms, "1788803495.969"),
        ("time_local klasik", parse_timestamp_ms, "08/Sep/2026:01:51:35 +0800"),
        ("time_local + ms", parse_timestamp_ms, "08/Sep/2026:01:51:35.969 +0800"),
        ("ISO 8601", parse_timestamp_ms, "2026-09-08T01:51:35.969+08:00"),
        ("tidak valid", parse_timestamp_ms, "ngawur"),
    ]
    for nama, fn, arg in tests:
        print(f"{nama:22}: {arg!r} -> {fn(arg)}")

    ms = parse_msec_field("msec=1788803495.969 rt=0.006")
    print("\nepoch_ms               :", ms)
    print("datetime lokal         :", epoch_ms_to_local_datetime(ms))
    print("format epoch           :", format_epoch_ms_local(ms))
