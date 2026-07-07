-- =====================================================================
-- WebLog-IDS - Skema Database MySQL
-- =====================================================================
-- File ini bisa dijalankan manual lewat phpMyAdmin (tab SQL) atau CLI:
--   mysql -u root -p < schema.sql
--
-- Catatan: database.py juga otomatis membuat tabel ini lewat init_db()
-- saat backend pertama kali dijalankan. File ini disediakan untuk setup
-- manual / dokumentasi / keperluan import di phpMyAdmin.
-- =====================================================================

-- Membuat database dengan charset utf8mb4 agar mendukung karakter luas
-- (termasuk payload serangan yang mengandung simbol/unicode).
CREATE DATABASE IF NOT EXISTS weblog_ids
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE weblog_ids;

-- ---------------------------------------------------------------------
-- Tabel access_logs: hasil parsing tiap baris access log Nginx.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_logs (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    ip              VARCHAR(45),          -- VARCHAR(45) agar muat IPv6
    timestamp       VARCHAR(64),          -- time_local mentah dari log
    method          VARCHAR(10),
    request_uri     TEXT,                 -- TEXT karena URI bisa panjang
    protocol        VARCHAR(20),
    status_code     INT,
    body_bytes_sent INT,
    referrer        TEXT,
    user_agent      TEXT,
    raw_log         TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- Tabel detection_results: hasil deteksi untuk tiap access_log.
-- matched_rules disimpan sebagai TEXT berisi JSON, mis. ["XSS-001","SQLI-002"].
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_results (
    id                 INT AUTO_INCREMENT PRIMARY KEY,
    log_id             INT,
    decoded_payload    TEXT,
    normalized_payload TEXT,
    label              VARCHAR(20),
    severity           VARCHAR(20),
    matched_rules      TEXT,
    recommendation     TEXT,
    actual_label       VARCHAR(20) NULL DEFAULT NULL,
    labeled_at         DATETIME NULL DEFAULT NULL,
    labeled_by         VARCHAR(100) NULL DEFAULT NULL,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id) REFERENCES access_logs(id)
);

-- ---------------------------------------------------------------------
-- Tabel rules: penyimpanan rule di database (opsional, untuk manajemen rule).
-- Sumber utama rule tetap file JSON; tabel ini untuk fitur lanjutan.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    rule_code   VARCHAR(20),
    name        VARCHAR(100),
    attack_type VARCHAR(20),
    pattern     TEXT,
    severity    VARCHAR(20),
    description TEXT,
    is_active   TINYINT(1) DEFAULT 1
);

-- ---------------------------------------------------------------------
-- Tabel evaluation_results: menyimpan hasil evaluasi metrik deteksi.
-- ---------------------------------------------------------------------
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
);

-- ---------------------------------------------------------------------
-- Tabel evaluation_runs: snapshot hasil evaluasi OvR strict 4-kelas.
-- json_result menyimpan confusion matrix, metrik per kelas, dan overall.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evaluation_runs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    run_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    accuracy    DOUBLE,
    macro_f1    DOUBLE,
    json_result LONGTEXT
);
