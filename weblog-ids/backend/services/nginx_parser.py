"""
nginx_parser.py - Parser untuk Nginx access log format combined.

Format yang didukung (PRD 1.9):
<ip> - <remote_user> [<time_local>] "<method> <request_uri> HTTP/<version>"
<status> <body_bytes_sent> "<http_referer>" "<http_user_agent>"
[msec=<epoch.milidetik> rt=<request_time> ...field tambahan lain]

Field tambahan setelah user-agent bersifat opsional (agar log lama tetap
lolos parse). Bila ada ``msec=$msec``, nilainya dipakai sebagai waktu request
presisi milidetik (epoch ms) di field ``timestamp_ms``; bila tidak ada,
fallback parse bracket ``[$time_local]`` (presisi detik, ms = 000).

Contoh:
45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644
"https://43.157.206.80:443/" "Mozilla/5.0 ..." msec=1788803495.969 rt=0.006

Baris yang tidak sesuai format (cleaning, PRD 1.5.3) dikembalikan sebagai None
sehingga pemanggil dapat melewati/mencatatnya sebagai invalid tanpa crash.
"""

import re
from typing import Optional, Dict, Any

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services.time_utils import parse_msec_field, parse_timestamp_ms

# ---------------------------------------------------------------------------
# Regex combined log Nginx.
# Dibuat toleran: request line bisa tidak utuh (mis. "-"), dan beberapa klien
# mengirim method/protocol tidak standar (PROPFIND, dll). Field tambahan
# (msec=, rt=, dst.) ditangkap sebagai grup opsional "extras".
# ---------------------------------------------------------------------------
_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                       # alamat IP / host
    r'\s+\S+'                             # ident (biasanya "-")
    r'\s+(?P<remote_user>\S+)'            # remote_user (biasanya "-")
    r'\s+\[(?P<timestamp>[^\]]+)\]'       # [time_local]
    r'\s+"(?P<request>[^"]*)"'            # "request line"
    r'\s+(?P<status>\d{3})'               # status code
    r'\s+(?P<body_bytes>\d+|-)'           # body bytes sent (bisa "-")
    r'\s+"(?P<referrer>[^"]*)"'           # "referer"
    r'\s+"(?P<user_agent>[^"]*)"'         # "user-agent"
    r'(?P<extras>.*?)\s*$'                # field tambahan opsional (msec=... dst.)
)

# Pecah request line: "<method> <request_uri> HTTP/<version>".
_REQUEST_PATTERN = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/(?P<protocol_version>[\d.]+)$'
)


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse satu baris access log Nginx.

    Mengembalikan dict berisi field hasil parsing, atau None bila baris
    tidak valid / gagal diparse (untuk dilewati oleh pemanggil).
    """
    if not line or not line.strip():
        return None

    line = line.strip()
    match = _LOG_PATTERN.match(line)
    if not match:
        return None

    g = match.groupdict()

    # Pecah request line menjadi method, uri, protocol.
    method = None
    request_uri = None
    protocol = None
    req_match = _REQUEST_PATTERN.match(g["request"].strip())
    if req_match:
        method = req_match.group("method")
        request_uri = req_match.group("uri")
        protocol = "HTTP/" + req_match.group("protocol_version")
    else:
        # Request line tidak standar (mis. kosong, malformed). Simpan apa adanya
        # agar tidak kehilangan data, tetapi method/uri tetap dapat None.
        request_uri = g["request"].strip() or None

    # body_bytes_sent: "-" berarti 0 byte.
    body_raw = g["body_bytes"]
    body_bytes_sent = 0 if body_raw == "-" else int(body_raw)

    # Waktu request presisi ms: prioritas field msec=$msec (epoch ms),
    # fallback parse bracket [$time_local] (presisi detik).
    extras = (g.get("extras") or "").strip()
    timestamp_ms = parse_msec_field(extras)
    if timestamp_ms is None:
        timestamp_ms = parse_timestamp_ms(g["timestamp"])

    return {
        "ip": g["ip"],
        "remote_user": g["remote_user"],
        "timestamp": g["timestamp"],
        "timestamp_ms": timestamp_ms,
        "method": method,
        "request_uri": request_uri,
        "protocol": protocol,
        "status_code": int(g["status"]),
        "body_bytes_sent": body_bytes_sent,
        "referrer": g["referrer"],
        "user_agent": g["user_agent"],
        "raw_log": line,
    }


# ---------------------------------------------------------------------------
# Uji mandiri:  python services/nginx_parser.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    samples = [
        # Format lama (tanpa field tambahan) — tetap harus lolos parse.
        '45.205.1.80 - - [08/Jun/2026:20:14:50 +0800] "GET / HTTP/1.1" 302 5 "-" "Mozilla/5.0"',
        '45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644 "https://43.157.206.80:443/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        '45.205.1.80 - - [08/Jun/2026:20:14:51 +0800] "PROPFIND / HTTP/1.1" 405 166 "http://43.157.206.80:443/" "-"',
        # Format baru server DVWA: field tambahan msec/rt/time_ms setelah user-agent.
        '182.10.99.158 - - [08/Sep/2026:01:51:35 +0800] "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%22xss%21%22%29%3C%2Fscript%3E HTTP/1.1" 200 1590 "https://dvwa.zhillanazmi.id/vulnerabilities/xss_r/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36" msec=1788803495.969 rt=0.006 time_ms=2026-09-08T01:51:35.969',
        'baris-ngawur-tidak-sesuai-format',
    ]
    for s in samples:
        result = parse_log_line(s)
        print("INPUT :", s[:70])
        print("PARSED:", json.dumps(result, ensure_ascii=False))
        print("-" * 60)
