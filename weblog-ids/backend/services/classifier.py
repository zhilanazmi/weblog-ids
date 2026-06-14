"""
classifier.py - Klasifikasi request, penentuan severity, dan rekomendasi.

Berdasarkan daftar rule yang terpicu (output rule_engine.match_rules):
- classify()                -> label Normal / XSS / SQLi / Multiple
- determine_severity()      -> none / low / medium / high
- generate_recommendation() -> teks rekomendasi mitigasi (PRD 1.14)
"""

from typing import List, Dict, Any


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


def determine_severity(matched_rules: List[Dict[str, Any]]) -> str:
    """
    Tentukan severity tertinggi dari rule yang terpicu:
    - tidak ada rule -> "none"
    - ada "high"     -> "high"
    - ada "medium"   -> "medium"
    - sisanya        -> "low"
    """
    if not matched_rules:
        return "none"

    severities = {(r.get("severity") or "").lower() for r in matched_rules}
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


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

    if severity == "high":
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
        [],
        [{"attack_type": "XSS", "severity": "high"}],
        [{"attack_type": "SQLi", "severity": "medium"}],
        [
            {"attack_type": "XSS", "severity": "medium"},
            {"attack_type": "SQLi", "severity": "high"},
        ],
    ]
    for c in cases:
        label = classify(c)
        sev = determine_severity(c)
        rec = generate_recommendation(label, sev, "1.2.3.4", "/vuln/")
        print(f"RULES   : {[r.get('attack_type') for r in c]}")
        print(f"LABEL   : {label} | SEVERITY: {sev}")
        print(f"RECOMMEND: {rec}")
        print("-" * 60)
