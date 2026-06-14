"""
nginx_parser.py - Parser untuk Nginx access log format combined.

Format yang didukung (PRD 1.9):
<ip> - <remote_user> [<time_local>] "<method> <request_uri> HTTP/<version>"
<status> <body_bytes_sent> "<http_referer>" "<http_user_agent>"

Contoh:
45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644
"https://43.157.206.80:443/" "Mozilla/5.0 ..."

Baris yang tidak sesuai format (cleaning, PRD 1.5.3) dikembalikan sebagai None
sehingga pemanggil dapat melewati/mencatatnya sebagai invalid tanpa crash.
"""

import re
from typing import Optional, Dict, Any

# ---------------------------------------------------------------------------
# Regex combined log Nginx.
# Dibuat toleran: request line bisa tidak utuh (mis. "-"), dan beberapa klien
# mengirim method/protocol tidak standar (PROPFIND, dll).
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
    r'\s*$'
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

    return {
        "ip": g["ip"],
        "remote_user": g["remote_user"],
        "timestamp": g["timestamp"],
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
        '45.205.1.80 - - [08/Jun/2026:20:14:50 +0800] "GET / HTTP/1.1" 302 5 "-" "Mozilla/5.0"',
        '45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644 "https://43.157.206.80:443/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        '45.205.1.80 - - [08/Jun/2026:20:14:51 +0800] "PROPFIND / HTTP/1.1" 405 166 "http://43.157.206.80:443/" "-"',
        'baris-ngawur-tidak-sesuai-format',
    ]
    for s in samples:
        result = parse_log_line(s)
        print("INPUT :", s[:70])
        print("PARSED:", json.dumps(result, ensure_ascii=False))
        print("-" * 60)
