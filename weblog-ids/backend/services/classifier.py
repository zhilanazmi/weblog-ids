"""
classifier.py - Klasifikasi request, penentuan severity, dan rekomendasi.

Berdasarkan daftar rule yang terpicu (output rule_engine.match_rules):
- classify()                -> label Normal / XSS / SQLi / Multiple
- determine_severity()      -> none / low / medium / high / critical
- generate_recommendation() -> teks rekomendasi mitigasi (PRD 1.14)

Severity tiap rule dipetakan dari skor CVSS v3.1 sesuai Tabel 3.3 & 3.4
pada Penentuan Severity.md. Fungsi determine_severity() memilih severity
tertinggi dari rule yang terpicu, lalu menyesuaikan dengan konteks request:
- method POST + payload XSS    -> indikasi Stored XSS  -> Critical (9.0-9.1)
- status code blokir/gagal     -> payload tak tereksekusi -> Low (Attempt)
"""

from typing import List, Dict, Any

# Urutan severity mengikuti skala kualitatif CVSS v3.1 (Tabel 3.2).
_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Status code yang menandakan request DITOLAK server (WAF / aturan keamanan /
# bad request). Payload terdeteksi tetapi tidak tereksekusi -> severity Low
# ("XSS/SQLi Attempt (gagal/blocked)" pada Tabel 3.3 & 3.4). 444 adalah
# kode khusus Nginx (koneksi ditutup tanpa respons).
_BLOCKED_STATUS = {400, 403, 405, 406, 444}


def classify(matched_rules: List[Dict[str, Any]]) -> str:
    """
    Tentukan label request dari rule yang terpicu (PRD 1.5.8):
    - tidak ada rule       -> "Normal"
    - hanya XSS            -> "XSS"
    - hanya SQLi           -> "SQLi"
    - XSS dan SQLi sekaligus-> "Multiple"
    """
    if not matched_rules:
        return "Normal"

    attack_types = {r.get("attack_type") for r in matched_rules}
    has_xss = "XSS" in attack_types
    has_sqli = "SQLi" in attack_types

    if has_xss and has_sqli:
        return "Multiple"
    if has_xss:
        return "XSS"
    if has_sqli:
        return "SQLi"
    # Ada rule terpicu tetapi attack_type tak dikenal -> tetap tandai.
    return "Multiple"


def determine_severity(
    matched_rules: List[Dict[str, Any]],
    method: str = None,
    status_code: int = None,
) -> str:
    """
    Tentukan severity berdasarkan CVSS v3.1 (Tabel 3.2-3.4 Penentuan Severity).

    Tahap 1: ambil severity tertinggi dari rule yang terpicu (nilai severity
    tiap rule sudah dipetakan dari base score CVSS: 0.1-3.9 Low, 4.0-6.9
    Medium, 7.0-8.9 High, 9.0-10.0 Critical).

    Tahap 2: penyesuaian konteks request:
    - status_code termasuk _BLOCKED_STATUS -> payload diblokir server ->
      "Attempt (gagal/blocked)" -> Low.
    - method POST dengan payload XSS -> payload dikirim ke endpoint yang
      menyimpan input (mis. guestbook DVWA) -> Stored XSS, persistent dan
      menyebar ke semua pengguna -> Critical.
    """
    if not matched_rules:
        return "none"

    severities = {(r.get("severity") or "").lower() for r in matched_rules}
    base = max(
        (s for s in severities if s in _SEVERITY_ORDER),
        key=lambda s: _SEVERITY_ORDER[s],
        default="low",
    )

    # Attempt/blocked: payload terdeteksi tapi request ditolak server.
    if status_code is not None and status_code in _BLOCKED_STATUS:
        return "low"

    # Stored XSS: payload dikirim via POST (akan disimpan backend) -> Critical.
    if method and str(method).upper() == "POST" and any(
        r.get("attack_type") == "XSS" for r in matched_rules
    ):
        return "critical"

    return base


def generate_recommendation(
    label: str, severity: str, ip: str = "", request_uri: str = ""
) -> str:
    """
    Hasilkan rekomendasi mitigasi berdasarkan label & severity (PRD 1.14).
    Untuk label Normal mengembalikan "-".
    """
    if label == "Normal":
        return "-"

    parts: List[str] = []

    if label in ("XSS", "Multiple"):
        parts.append(
            "Indikasi XSS: lakukan validasi input dan output encoding pada "
            f"endpoint {request_uri or 'terkait'}, serta periksa parameter yang dikirim."
        )
    if label in ("SQLi", "Multiple"):
        parts.append(
            "Indikasi SQL Injection: gunakan prepared statement/parameterized "
            f"query, validasi parameter, dan periksa query backend pada {request_uri or 'endpoint terkait'}."
        )

    if severity == "critical":
        parts.append(
            f"Severity KRITIS: blokir segera IP {ip or 'penyerang'}, lakukan "
            "incident response, dan audit integritas/kerahasiaan data karena "
            "serangan berpotensi manipulasi atau ekstraksi data penuh."
        )
    elif severity == "high":
        parts.append(
            f"Severity tinggi: pertimbangkan pemblokiran sementara IP {ip or 'penyerang'} "
            "apabila request berulang, atau terapkan rate limiting."
        )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Uji mandiri:  python services/classifier.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    cases = [
        # (matched_rules, method, status_code, keterangan)
        ([], "GET", 200, "Normal"),
        ([{"attack_type": "XSS", "severity": "medium"}], "GET", 200, "XSS Reflected/DOM"),
        ([{"attack_type": "XSS", "severity": "medium"}], "POST", 200, "Stored XSS via POST"),
        ([{"attack_type": "XSS", "severity": "medium"}], "GET", 403, "XSS blocked (Attempt)"),
        ([{"attack_type": "SQLi", "severity": "critical"}], "GET", 200, "Auth Bypass"),
        ([{"attack_type": "SQLi", "severity": "critical"}], "GET", 403, "Auth Bypass blocked"),
        ([{"attack_type": "SQLi", "severity": "high"}], "GET", 200, "Union-Based"),
        ([{"attack_type": "SQLi", "severity": "medium"}], "GET", 200, "Error/Time-Based"),
        (
            [
                {"attack_type": "XSS", "severity": "medium"},
                {"attack_type": "SQLi", "severity": "high"},
            ],
            "GET",
            200,
            "Multiple",
        ),
    ]
    for matched, method, status, note in cases:
        label = classify(matched)
        sev = determine_severity(matched, method=method, status_code=status)
        rec = generate_recommendation(label, sev, "1.2.3.4", "/vuln/")
        print(f"KASUS   : {note} ({method} {status})")
        print(f"RULES   : {[r.get('attack_type') for r in matched]}")
        print(f"LABEL   : {label} | SEVERITY: {sev}")
        print(f"RECOMMEND: {rec}")
        print("-" * 60)
