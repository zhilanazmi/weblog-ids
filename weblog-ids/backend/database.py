"""
database.py - Lapisan akses database MySQL untuk WebLog-IDS.

Menggunakan PyMySQL (driver murni Python, mudah dipasang di Windows/Linux).
Semua kredensial diambil dari config.py (yang membaca environment variable),
sehingga password tidak pernah di-hardcode di kode ini.

Seluruh query memakai parameterized query (placeholder %s) agar aman dari
SQL injection -- ini penting karena data yang disimpan justru berasal dari
request berbahaya (payload XSS/SQLi).
"""

import json
from typing import Optional, Dict, Any, List

import os
import sys

import pymysql
from pymysql.cursors import DictCursor

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config


# ---------------------------------------------------------------------------
# Definisi tabel (dipakai init_db). CREATE TABLE IF NOT EXISTS agar idempotent:
# aman dipanggil berulang kali tanpa menimpa data yang sudah ada.
# ---------------------------------------------------------------------------
_CREATE_ACCESS_LOGS = """
CREATE TABLE IF NOT EXISTS access_logs (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    ip              VARCHAR(45),
    timestamp       VARCHAR(64),
    method          VARCHAR(10),
    request_uri     TEXT,
    protocol        VARCHAR(20),
    status_code     INT,
    body_bytes_sent INT,
    referrer        TEXT,
    user_agent      TEXT,
    raw_log         TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

_CREATE_DETECTION_RESULTS = """
CREATE TABLE IF NOT EXISTS detection_results (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    log_id             INT,
    decoded_payload    TEXT,
    normalized_payload TEXT,
    label              VARCHAR(20),
    severity           VARCHAR(20),
    matched_rules      TEXT,
    recommendation     TEXT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id) REFERENCES access_logs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

_CREATE_RULES = """
CREATE TABLE IF NOT EXISTS rules (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    rule_code   VARCHAR(20),
    name        VARCHAR(100),
    attack_type VARCHAR(20),
    pattern     TEXT,
    severity    VARCHAR(20),
    description TEXT,
    is_active   TINYINT(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

_CREATE_EVALUATION_RESULTS = """
CREATE TABLE IF NOT EXISTS evaluation_results (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    total_data      INT,
    true_positive   INT,
    true_negative   INT,
    false_positive  INT,
    false_negative  INT,
    accuracy        DOUBLE,
    precision_score DOUBLE,
    recall_score    DOUBLE,
    f1_score        DOUBLE,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

_ALL_TABLES = [
    _CREATE_ACCESS_LOGS,
    _CREATE_DETECTION_RESULTS,
    _CREATE_RULES,
    _CREATE_EVALUATION_RESULTS,
]


# ---------------------------------------------------------------------------
# Koneksi
# ---------------------------------------------------------------------------
def get_connection(use_database: bool = True) -> pymysql.connections.Connection:
    """
    Membuat dan mengembalikan koneksi MySQL baru.

    Parameter use_database=False dipakai khusus saat init_db() perlu membuat
    database-nya dulu (database belum tentu ada saat pertama kali dijalankan).

    autocommit=True dipilih agar setiap operasi simpan langsung permanen tanpa
    perlu commit manual -- cocok untuk alur realtime per-baris log.
    """
    kwargs = dict(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        charset=config.DB_CHARSET,
        cursorclass=DictCursor,
        autocommit=True,
    )
    if use_database:
        kwargs["database"] = config.DB_NAME
    return pymysql.connect(**kwargs)


# ---------------------------------------------------------------------------
# Inisialisasi
# ---------------------------------------------------------------------------
def init_db() -> None:
    """
    Membuat database (jika belum ada) lalu semua tabel (CREATE TABLE IF NOT
    EXISTS). Dipanggil saat startup FastAPI. Aman dipanggil berulang.
    """
    # Tahap 1: buat database tanpa memilih DB dulu (DB mungkin belum ada).
    conn = get_connection(use_database=False)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` "
                f"CHARACTER SET {config.DB_CHARSET} COLLATE utf8mb4_unicode_ci"
            )
    finally:
        conn.close()

    # Tahap 2: koneksi ke database tersebut, lalu buat semua tabel.
    conn = get_connection(use_database=True)
    try:
        with conn.cursor() as cur:
            for ddl in _ALL_TABLES:
                cur.execute(ddl)
    finally:
        conn.close()

    print(f"[Database] init_db selesai. Database '{config.DB_NAME}' siap.")


# ---------------------------------------------------------------------------
# Operasi simpan
# ---------------------------------------------------------------------------
def save_access_log(parsed_log: Dict[str, Any]) -> int:
    """
    Menyimpan satu baris hasil parsing ke tabel access_logs.
    Mengembalikan id baris yang baru dibuat (lastrowid) untuk dihubungkan
    ke detection_results.

    Memakai placeholder %s (parameterized) agar nilai dari log -- yang bisa
    berisi payload berbahaya -- tidak pernah diinterpretasikan sebagai SQL.
    """
    sql = """
        INSERT INTO access_logs
            (ip, timestamp, method, request_uri, protocol, status_code,
             body_bytes_sent, referrer, user_agent, raw_log)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = (
        parsed_log.get("ip"),
        parsed_log.get("timestamp"),
        parsed_log.get("method"),
        parsed_log.get("request_uri"),
        parsed_log.get("protocol"),
        parsed_log.get("status_code"),
        parsed_log.get("body_bytes_sent"),
        parsed_log.get("referrer"),
        parsed_log.get("user_agent"),
        parsed_log.get("raw_log"),
    )
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid
    finally:
        conn.close()


def save_detection_result(log_id: int, hasil_deteksi: Dict[str, Any]) -> int:
    """
    Menyimpan hasil deteksi yang terkait dengan satu access_log (log_id).

    hasil_deteksi diharapkan berisi:
        decoded_payload, normalized_payload, label, severity,
        matched_rules (list/iterable), recommendation

    matched_rules diserialisasi menjadi JSON string (mis. ["XSS-001"]) agar
    muat di kolom TEXT dan mudah dibaca kembali.
    """
    matched = hasil_deteksi.get("matched_rules", [])
    # Bila berupa list of dict, ambil id-nya; bila sudah list string, pakai apa adanya.
    if matched and isinstance(matched[0], dict):
        matched_codes = [m.get("id") for m in matched]
    else:
        matched_codes = list(matched)
    matched_json = json.dumps(matched_codes, ensure_ascii=False)

    sql = """
        INSERT INTO detection_results
            (log_id, decoded_payload, normalized_payload, label, severity,
             matched_rules, recommendation)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    params = (
        log_id,
        hasil_deteksi.get("decoded_payload"),
        hasil_deteksi.get("normalized_payload"),
        hasil_deteksi.get("label"),
        hasil_deteksi.get("severity"),
        matched_json,
        hasil_deteksi.get("recommendation"),
    )
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Uji mandiri:  python database.py
# Membuat database + tabel, lalu menampilkan daftar tabel.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW TABLES")
            tables = [list(row.values())[0] for row in cur.fetchall()]
            print("[Database] Tabel tersedia:", tables)
    finally:
        conn.close()
