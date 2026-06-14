"""
config.py - Konfigurasi terpusat WebLog-IDS.

Semua nilai bisa dioverride lewat environment variable agar fleksibel
saat dikembangkan di Windows maupun dijalankan di server Linux produksi.
"""

import os
from pathlib import Path

# Direktori dasar backend (folder tempat file ini berada)
BASE_DIR = Path(__file__).resolve().parent


def _env_bool(name: str, default: bool) -> bool:
    """Helper baca environment variable bertipe boolean."""
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Log source
# ---------------------------------------------------------------------------
# Path file access log Nginx yang dipantau (Linux, sesuai PRD).
# Bisa dioverride lewat environment variable LOG_FILE_PATH bila diperlukan,
# contoh untuk uji lokal:
#   export LOG_FILE_PATH=/tmp/dvwa_access.log
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/var/log/nginx/dvwa_access.log")

# Jika True, watcher membaca file dari AWAL (memproses semua log lama).
# Jika False (default), watcher mulai dari AKHIR file (hanya log baru),
# meniru perilaku `tail -f`.
READ_FROM_BEGINNING = _env_bool("READ_FROM_BEGINNING", False)

# Jeda polling watcher dalam detik saat tidak ada baris baru.
# Nilai kecil = latensi rendah (PRD: < 1 detik setelah log ditulis).
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.5"))

# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------
# Batas maksimal recursive URL decoding untuk menangani double/triple encoding.
MAX_DECODE_ROUND = int(os.getenv("MAX_DECODE_ROUND", "3"))

# ---------------------------------------------------------------------------
# Database (MySQL)
# ---------------------------------------------------------------------------
# Konfigurasi koneksi MySQL. Semua nilai bisa dioverride lewat environment
# variable agar kredensial TIDAK perlu di-hardcode di kode/repo.
# Default mengikuti setup umum XAMPP: user root, password kosong.
# Contoh override (Linux/produksi):
#   export DB_PASSWORD='rahasia'
#   export DB_HOST=127.0.0.1
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")  # kosong = default XAMPP
DB_NAME = os.getenv("DB_NAME", "weblog_ids")
DB_CHARSET = os.getenv("DB_CHARSET", "utf8mb4")

# ---------------------------------------------------------------------------
# Rule set
# ---------------------------------------------------------------------------
RULES_DIR = BASE_DIR / "rules"
XSS_RULES_PATH = os.getenv("XSS_RULES_PATH", str(RULES_DIR / "xss_rules.json"))
SQLI_RULES_PATH = os.getenv("SQLI_RULES_PATH", str(RULES_DIR / "sqli_rules.json"))
