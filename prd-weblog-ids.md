# PRD dan Prompt Implementasi WebLog-IDS

## Judul Sistem

**WebLog-IDS: Sistem Deteksi Intrusi Berbasis Analisis Log Akses Nginx secara Realtime dengan Pendekatan Rule-Based untuk Serangan XSS dan SQL Injection**

## Judul Tugas Akhir

**MITIGASI INTRUSION DETECTION BERBASIS ANALISIS LOG AKSES WEB SERVER DENGAN PENDEKATAN RULE-BASED UNTUK SERANGAN XSS DAN SQL INJECTION**

---

# 1. Product Requirements Document (PRD)

## 1.1 Latar Belakang

Aplikasi web memiliki potensi menjadi target serangan seperti Cross Site Scripting (XSS) dan SQL Injection (SQLi). Kedua jenis serangan ini sering dikirim melalui parameter URL, query string, maupun request HTTP yang diterima oleh web server. Pada web server Nginx, aktivitas request tersebut dapat direkam dalam bentuk access log.

Access log Nginx menyimpan informasi penting seperti alamat IP, waktu akses, method HTTP, URI request, status code, referrer, dan user-agent. Informasi tersebut dapat dianalisis untuk mendeteksi indikasi payload berbahaya. Oleh karena itu, dibutuhkan sistem intrusion detection berbasis analisis log akses web server yang mampu membaca log secara otomatis dan melakukan deteksi berdasarkan rule atau pola tertentu.

Sistem yang dikembangkan akan memantau file log Nginx secara realtime, membaca setiap baris log baru, melakukan parsing dan preprocessing, lalu mencocokkan request dengan rule XSS dan SQLi. Hasil deteksi akan ditampilkan dalam bentuk dashboard, alert, statistik, dan laporan evaluasi.

## 1.2 Tujuan Sistem

Tujuan utama sistem adalah membangun prototipe intrusion detection berbasis analisis log akses Nginx yang mampu mendeteksi indikasi serangan XSS dan SQL Injection menggunakan pendekatan rule-based.

Tujuan khusus sistem adalah:

1. Membaca file `/var/log/nginx/dvwa_access.log` secara otomatis ketika terdapat update log baru.
2. Melakukan parsing terhadap format combined log Nginx.
3. Melakukan preprocessing berupa decoding dan normalisasi request.
4. Mendeteksi pola XSS dan SQLi menggunakan rule berbasis regex.
5. Memberikan label Normal, XSS, atau SQLi pada setiap request.
6. Menyimpan hasil deteksi ke database.
7. Menampilkan alert dan dashboard realtime.
8. Menghasilkan laporan hasil deteksi dan evaluasi.

## 1.3 Ruang Lingkup Sistem

Sistem berfokus pada analisis access log Nginx, khususnya file:

```text
/var/log/nginx/dvwa_access.log
```

Sistem mendeteksi dua jenis serangan utama, yaitu XSS dan SQL Injection. Sistem menggunakan pendekatan rule-based dengan regex dan pattern matching. Sistem membaca log secara realtime dengan pendekatan log tailing seperti mekanisme `tail -f`. Sistem menghasilkan output berupa klasifikasi request, alert, statistik, dan rekomendasi mitigasi.

Sistem tidak bertugas menggantikan Web Application Firewall secara penuh. Sistem juga tidak melakukan pemblokiran otomatis terhadap IP pada server produksi. Jika ada fitur mitigasi, mitigasi berupa rekomendasi tindakan, seperti daftar IP mencurigakan, endpoint yang diserang, severity, dan saran pemblokiran atau pemeriksaan lebih lanjut.

## 1.4 Pengguna Sistem

Pengguna utama sistem adalah administrator server, peneliti keamanan web, mahasiswa/peneliti Tugas Akhir, dan penguji sistem pada lingkungan DVWA. Pada konteks penelitian ini, pengguna sistem adalah peneliti yang menjalankan DVWA dan Nginx, lalu mengamati bagaimana request normal, XSS, dan SQLi terdeteksi melalui log.

## 1.5 Kebutuhan Fungsional

### 1.5.1 Realtime Log Monitoring

Sistem harus dapat memantau file log Nginx secara realtime. Ketika terdapat baris log baru pada `/var/log/nginx/dvwa_access.log`, sistem harus otomatis membaca baris tersebut tanpa perlu upload manual.

### 1.5.2 Parsing Log Nginx

Sistem harus dapat melakukan parsing format access log Nginx combined. Field minimal yang harus diekstrak adalah:

- IP
- Timestamp
- Method HTTP
- Request URI
- Protocol
- Status code
- Body bytes sent
- Referrer
- User-agent
- Raw log

### 1.5.3 Cleaning Data

Sistem harus dapat melakukan cleaning data. Baris log yang tidak sesuai format atau gagal diparse tidak boleh menghentikan sistem. Baris tersebut dapat dilewati dan dicatat sebagai invalid log.

### 1.5.4 Ekstraksi Request

Sistem harus dapat melakukan ekstraksi request URI menjadi path, query string, dan parameter. Fokus inspeksi utama adalah request URI, query string, dan nilai parameter karena payload XSS dan SQLi biasanya muncul di bagian tersebut.

### 1.5.5 URL Decoding dan Normalisasi

Sistem harus dapat melakukan decoding URL. Payload seperti:

```text
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

harus diubah menjadi:

```text
<script>alert(1)</script>
```

Sistem juga harus dapat melakukan decoding beberapa kali dengan batas maksimal tertentu untuk menangani double encoding. Sistem harus dapat melakukan normalisasi payload, seperti lowercase, penghapusan spasi berlebih, penyatuan representasi karakter tertentu, dan pembersihan format agar rule matching lebih konsisten.

### 1.5.6 Rule Set XSS dan SQLi

Sistem harus memiliki rule set XSS dan SQLi. Rule set dapat disimpan dalam file JSON agar mudah ditambah atau diubah. Setiap rule minimal memiliki nama rule, jenis serangan, pattern regex, severity, dan deskripsi.

### 1.5.7 Rule Matching

Sistem harus dapat melakukan rule matching. Payload hasil preprocessing harus dibandingkan dengan rule XSS dan SQLi. Jika ada rule yang cocok, sistem menyimpan informasi rule yang terpicu.

### 1.5.8 Klasifikasi Request

Sistem harus dapat melakukan klasifikasi request menjadi:

- Normal
- XSS
- SQLi
- Multiple, jika cocok dengan rule XSS dan SQLi sekaligus

Jika tidak ada rule yang cocok, request diberi label Normal. Jika cocok dengan rule XSS, diberi label XSS. Jika cocok dengan rule SQLi, diberi label SQLi.

### 1.5.9 Penyimpanan Database

Sistem harus dapat menyimpan hasil parsing dan hasil deteksi ke database. Data yang disimpan meliputi raw log, field parsing, decoded payload, label prediksi, matched rules, severity, rekomendasi mitigasi, dan waktu pemrosesan.

### 1.5.10 Dashboard Realtime

Sistem harus dapat menampilkan dashboard realtime. Dashboard menampilkan total log diproses, jumlah Normal, jumlah XSS, jumlah SQLi, daftar alert terbaru, top IP mencurigakan, endpoint paling sering diserang, dan rule paling sering terpicu.

### 1.5.11 Alert Realtime

Sistem harus dapat menampilkan alert realtime. Jika request terdeteksi sebagai XSS atau SQLi, dashboard harus menampilkan alert yang memuat timestamp, IP, method, URI, payload hasil decoding, jenis serangan, severity, rule yang terpicu, dan rekomendasi mitigasi.

### 1.5.12 Export Report

Sistem harus dapat mengekspor hasil deteksi ke CSV. Export minimal berisi timestamp, IP, method, URI, label, severity, matched rules, dan recommendation.

### 1.5.13 Manajemen Rule

Sistem menyediakan halaman atau endpoint untuk melihat rule set. Jika memungkinkan, sistem dapat menyediakan fitur tambah, ubah, aktif/nonaktif rule, tetapi fitur ini bersifat opsional untuk versi awal.

### 1.5.14 Evaluasi

Sistem harus menyediakan fitur evaluasi. Jika data log memiliki label aktual, sistem dapat menghitung accuracy, precision, recall, F1-score, false positive, dan false negative. Jika tidak ada label aktual, sistem tetap menampilkan statistik deteksi dan rule yang terpicu.

## 1.6 Kebutuhan Non-Fungsional

Sistem harus berjalan pada lingkungan Linux server yang memiliki Nginx dan DVWA. Sistem harus dapat membaca file log di `/var/log/nginx/dvwa_access.log` dengan permission yang sesuai. Sistem harus tetap berjalan walaupun terdapat baris log yang tidak valid. Sistem harus membaca log baru dengan jeda rendah, misalnya kurang dari 1 detik setelah log ditulis oleh Nginx.

Sistem harus modular agar setiap komponen dapat diuji secara terpisah. Modul parser, preprocessor, rule engine, classifier, evaluator, dan log watcher harus dipisahkan. Sistem harus mudah dikembangkan dengan penambahan rule baru. Sistem harus aman untuk penelitian, yaitu tidak melakukan serangan aktif dan tidak memblokir otomatis tanpa persetujuan pengguna.

## 1.7 Tech Stack

Tech stack utama yang direkomendasikan:

```text
Bahasa pemrograman : Python
Backend API        : FastAPI
Realtime           : WebSocket
Database           : SQLite untuk prototipe, PostgreSQL untuk pengembangan lanjutan
Rule engine        : Python Regex
Frontend           : React
Chart/dashboard    : Recharts atau Chart.js
Data processing    : Pandas
Evaluasi           : Scikit-learn atau perhitungan manual
Server             : Linux
Web server log     : Nginx access log
Target uji         : DVWA
```

Untuk versi yang lebih cepat dibuat:

```text
Python + Streamlit + SQLite + Regex + Pandas + Plotly
```

Namun untuk hasil yang lebih profesional dan sesuai kebutuhan realtime, pilihan terbaik adalah:

```text
FastAPI + React + WebSocket + SQLite
```

## 1.8 Arsitektur Sistem

```text
Nginx / DVWA
    ↓
/var/log/nginx/dvwa_access.log
    ↓
Realtime Log Watcher
    ↓
Log Reader
    ↓
Nginx Log Parser
    ↓
Request Extractor
    ↓
Cleaning Data
    ↓
URL Decoding & Normalization
    ↓
Payload Builder
    ↓
Rule Matching Engine
    ↓
Classifier Normal/XSS/SQLi
    ↓
Database
    ↓
Realtime Alert & Dashboard
    ↓
Report / Evaluation / Mitigation Recommendation
```

Komponen `Realtime Log Watcher` bertugas membaca baris baru pada file log secara otomatis. Komponen ini menjadi pembeda utama dari sistem upload log biasa.

## 1.9 Format Log yang Didukung

Sistem mendukung format combined log Nginx seperti berikut:

```text
<ip> - <remote_user> [<time_local>] "<method> <request_uri> HTTP/<version>" <status> <body_bytes_sent> "<http_referer>" "<http_user_agent>"
```

Contoh:

```text
45.205.1.80 - - [08/Jun/2026:20:14:50 +0800] "GET / HTTP/1.1" 302 5 "-" "Mozilla/5.0"
```

Contoh lain:

```text
45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644 "https://43.157.206.80:443/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
```

Hasil parsing:

```json
{
  "ip": "45.148.10.67",
  "timestamp": "08/Jun/2026:20:16:30 +0800",
  "method": "GET",
  "request_uri": "/login.php",
  "protocol": "HTTP/1.1",
  "status_code": 200,
  "body_bytes_sent": 644,
  "referrer": "https://43.157.206.80:443/",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}
```

## 1.10 Rule Set

### 1.10.1 Rule XSS Minimal

```json
[
  {
    "id": "XSS-001",
    "name": "XSS Script Tag",
    "attack_type": "XSS",
    "pattern": "<\\s*script[^>]*>.*?<\\s*/\\s*script\\s*>",
    "severity": "high",
    "description": "Mendeteksi penggunaan tag script pada request"
  },
  {
    "id": "XSS-002",
    "name": "XSS Event Handler",
    "attack_type": "XSS",
    "pattern": "on(error|load|click|mouseover|focus)\\s*=",
    "severity": "medium",
    "description": "Mendeteksi event handler JavaScript pada parameter"
  },
  {
    "id": "XSS-003",
    "name": "XSS JavaScript URI",
    "attack_type": "XSS",
    "pattern": "javascript\\s*:",
    "severity": "high",
    "description": "Mendeteksi penggunaan skema javascript:"
  },
  {
    "id": "XSS-004",
    "name": "XSS Alert Function",
    "attack_type": "XSS",
    "pattern": "(alert|prompt|confirm)\\s*\\(",
    "severity": "medium",
    "description": "Mendeteksi fungsi JavaScript umum pada payload XSS"
  }
]
```

### 1.10.2 Rule SQLi Minimal

```json
[
  {
    "id": "SQLI-001",
    "name": "SQLi Union Select",
    "attack_type": "SQLi",
    "pattern": "union\\s+select",
    "severity": "high",
    "description": "Mendeteksi pola UNION SELECT"
  },
  {
    "id": "SQLI-002",
    "name": "SQLi Boolean Based",
    "attack_type": "SQLi",
    "pattern": "('|\\\")?\\s*(or|and)\\s+('|\\\")?\\d+('|\\\")?\\s*=\\s*('|\\\")?\\d+",
    "severity": "high",
    "description": "Mendeteksi pola boolean-based SQL injection"
  },
  {
    "id": "SQLI-003",
    "name": "SQLi Comment Pattern",
    "attack_type": "SQLi",
    "pattern": "(--|#|/\\*|\\*/)",
    "severity": "medium",
    "description": "Mendeteksi komentar SQL yang umum digunakan dalam SQLi"
  },
  {
    "id": "SQLI-004",
    "name": "SQLi Time Based",
    "attack_type": "SQLi",
    "pattern": "(sleep\\s*\\(|benchmark\\s*\\()",
    "severity": "high",
    "description": "Mendeteksi time-based SQL injection"
  },
  {
    "id": "SQLI-005",
    "name": "SQLi Information Schema",
    "attack_type": "SQLi",
    "pattern": "information_schema",
    "severity": "high",
    "description": "Mendeteksi akses ke information_schema"
  }
]
```

## 1.11 Database

Skema database minimal:

```sql
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    timestamp TEXT,
    method TEXT,
    request_uri TEXT,
    protocol TEXT,
    status_code INTEGER,
    body_bytes_sent INTEGER,
    referrer TEXT,
    user_agent TEXT,
    raw_log TEXT,
    created_at TEXT
);

CREATE TABLE detection_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER,
    decoded_payload TEXT,
    normalized_payload TEXT,
    label TEXT,
    severity TEXT,
    matched_rules TEXT,
    recommendation TEXT,
    created_at TEXT,
    FOREIGN KEY(log_id) REFERENCES access_logs(id)
);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_code TEXT,
    name TEXT,
    attack_type TEXT,
    pattern TEXT,
    severity TEXT,
    description TEXT,
    is_active INTEGER
);

CREATE TABLE evaluation_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_data INTEGER,
    true_positive INTEGER,
    true_negative INTEGER,
    false_positive INTEGER,
    false_negative INTEGER,
    accuracy REAL,
    precision_score REAL,
    recall_score REAL,
    f1_score REAL,
    created_at TEXT
);
```

## 1.12 API Endpoint

Endpoint backend:

```text
GET    /api/health
GET    /api/logs
GET    /api/detections
GET    /api/detections/latest
GET    /api/dashboard/summary
GET    /api/dashboard/top-attacker-ip
GET    /api/dashboard/attack-types
GET    /api/dashboard/rule-triggered
GET    /api/rules
POST   /api/rules
PUT    /api/rules/{id}
DELETE /api/rules/{id}
GET    /api/reports/export-csv
POST   /api/evaluate
WS     /ws/alerts
```

Endpoint WebSocket `/ws/alerts` digunakan untuk mengirim alert realtime ke frontend setiap kali sistem mendeteksi XSS atau SQLi.

## 1.13 Tampilan Dashboard

Dashboard minimal memiliki halaman ringkasan, hasil deteksi, alert realtime, statistik IP, statistik rule, manajemen rule, dan export report.

Halaman ringkasan menampilkan total log yang diproses, total Normal, total XSS, total SQLi, jumlah alert hari ini, dan status log watcher.

Halaman hasil deteksi menampilkan tabel dengan kolom timestamp, IP, method, request URI, decoded payload, label, severity, matched rules, dan recommendation.

Halaman alert realtime menampilkan alert terbaru tanpa refresh browser.

Halaman statistik menampilkan grafik jumlah deteksi berdasarkan jenis serangan, top IP mencurigakan, endpoint paling sering terdeteksi, dan rule paling sering terpicu.

## 1.14 Rekomendasi Mitigasi

Sistem menghasilkan rekomendasi mitigasi berdasarkan label dan severity.

Contoh rekomendasi:

```text
Jika label = XSS dan severity = high:
Rekomendasi: Periksa endpoint terkait, lakukan validasi input dan output encoding, serta pertimbangkan pemblokiran sementara IP apabila request berulang.

Jika label = SQLi dan severity = high:
Rekomendasi: Periksa parameter endpoint, pastikan penggunaan prepared statement, dan pertimbangkan pemblokiran IP apabila terjadi percobaan berulang.

Jika IP melakukan serangan lebih dari 5 kali:
Rekomendasi: Tambahkan IP ke daftar blokir sementara atau lakukan rate limiting.
```

## 1.15 Kriteria Keberhasilan

Sistem dianggap berhasil apabila:

1. Dapat membaca update log baru dari `/var/log/nginx/dvwa_access.log` secara otomatis.
2. Dapat melakukan parsing log Nginx combined.
3. Dapat mendeteksi payload XSS encoded seperti `%3Cscript%3Ealert(1)%3C%2Fscript%3E`.
4. Dapat mendeteksi pola SQLi seperti `union select`, `' or 1=1`, `sleep()`, dan `information_schema`.
5. Dapat menyimpan hasil deteksi ke database.
6. Dapat menampilkan alert realtime pada dashboard.
7. Dapat mengekspor hasil deteksi.
8. Dapat menampilkan statistik hasil deteksi.

---

# 2. Prompt Implementasi Lengkap

Prompt berikut dapat digunakan untuk meminta AI/coding assistant membuat program WebLog-IDS.

```text
Saya ingin kamu membuat aplikasi bernama WebLog-IDS.

Konteks:
Saya sedang mengerjakan Tugas Akhir berjudul:
"MITIGASI INTRUSION DETECTION BERBASIS ANALISIS LOG AKSES WEB SERVER DENGAN PENDEKATAN RULE-BASED UNTUK SERANGAN XSS DAN SQL INJECTION"

Saya ingin membuat sistem intrusion detection berbasis analisis log akses Nginx. Sistem harus membaca file log Nginx secara realtime, khususnya file:

/var/log/nginx/dvwa_access.log

Setiap ada baris log baru yang ditambahkan oleh Nginx, program harus otomatis membaca baris tersebut, melakukan parsing, preprocessing, rule matching, klasifikasi, menyimpan hasil ke database, dan menampilkan alert/dashboard.

Tujuan sistem:
1. Membaca access log Nginx secara realtime seperti tail -f.
2. Melakukan parsing format combined log Nginx.
3. Mengekstrak field ip, timestamp, method, request_uri, protocol, status_code, body_bytes_sent, referrer, user_agent, dan raw_log.
4. Melakukan cleaning terhadap baris log yang gagal diparse.
5. Melakukan decoding URL, termasuk payload encoded seperti %3Cscript%3Ealert(1)%3C%2Fscript%3E.
6. Melakukan recursive decoding maksimal 3 kali.
7. Melakukan normalisasi payload menjadi lowercase, strip whitespace, dan menghapus spasi berlebih.
8. Melakukan rule matching berbasis regex untuk mendeteksi XSS dan SQL Injection.
9. Memberikan label Normal, XSS, atau SQLi.
10. Menyimpan hasil parsing dan hasil deteksi ke database.
11. Menampilkan dashboard realtime.
12. Mengirim alert realtime ketika ditemukan XSS atau SQLi.
13. Menyediakan export hasil deteksi ke CSV.
14. Menyediakan statistik jumlah Normal, XSS, SQLi, top attacker IP, endpoint paling sering diserang, dan rule paling sering terpicu.
15. Memberikan rekomendasi mitigasi berbasis hasil deteksi.

Tech stack yang harus digunakan:
Backend: Python FastAPI
Realtime: WebSocket
Database: SQLite
Frontend: React
Rule engine: Python regex
Chart: Recharts atau Chart.js

Buat struktur project seperti ini:

weblog-ids/
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── requirements.txt
│   ├── services/
│   │   ├── log_watcher.py
│   │   ├── nginx_parser.py
│   │   ├── preprocessor.py
│   │   ├── rule_engine.py
│   │   ├── classifier.py
│   │   ├── alert_service.py
│   │   ├── report_service.py
│   │   └── evaluation_service.py
│   ├── routes/
│   │   ├── log_routes.py
│   │   ├── detection_routes.py
│   │   ├── dashboard_routes.py
│   │   ├── rule_routes.py
│   │   ├── report_routes.py
│   │   └── websocket_routes.py
│   └── rules/
│       ├── xss_rules.json
│       └── sqli_rules.json
├── frontend/
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       ├── api/
│       │   └── api.js
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── DetectionResults.jsx
│       │   ├── RealtimeAlerts.jsx
│       │   └── Rules.jsx
│       └── components/
│           ├── SummaryCards.jsx
│           ├── AlertTable.jsx
│           ├── AttackTypeChart.jsx
│           ├── TopIpChart.jsx
│           └── RuleTriggeredChart.jsx
└── README.md

Format log yang harus didukung:

<ip> - <remote_user> [<time_local>] "<method> <request_uri> HTTP/<version>" <status> <body_bytes_sent> "<http_referer>" "<http_user_agent>"

Contoh log:

45.205.1.80 - - [08/Jun/2026:20:14:50 +0800] "GET / HTTP/1.1" 302 5 "-" "Mozilla/5.0"

45.205.1.80 - - [08/Jun/2026:20:14:51 +0800] "PROPFIND / HTTP/1.1" 405 166 "http://43.157.206.80:443/" "-"

45.148.10.67 - - [08/Jun/2026:20:16:30 +0800] "GET /login.php HTTP/1.1" 200 644 "https://43.157.206.80:443/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

Parser harus menggunakan regex yang robust untuk format combined log tersebut.

Log watcher:
Buat service log_watcher.py yang membaca file /var/log/nginx/dvwa_access.log secara realtime.
Gunakan pendekatan seperti tail -f.
Saat program startup, default-nya mulai membaca dari akhir file, bukan dari awal file, agar hanya memproses log baru.
Namun berikan opsi konfigurasi READ_FROM_BEGINNING=True/False di config.py.
Jika file belum ada atau permission ditolak, tampilkan error yang jelas.

Preprocessing:
Buat fungsi recursive_decode(value, max_round=3).
Gunakan urllib.parse.unquote_plus.
Lakukan lowercasing.
Hapus spasi berlebih.
Payload inspeksi harus dibuat dari request_uri hasil decoding dan normalisasi.

Rule XSS:
Simpan rule di backend/rules/xss_rules.json dengan isi minimal:

[
  {
    "id": "XSS-001",
    "name": "XSS Script Tag",
    "attack_type": "XSS",
    "pattern": "<\\s*script[^>]*>.*?<\\s*/\\s*script\\s*>",
    "severity": "high",
    "description": "Mendeteksi penggunaan tag script pada request"
  },
  {
    "id": "XSS-002",
    "name": "XSS Event Handler",
    "attack_type": "XSS",
    "pattern": "on(error|load|click|mouseover|focus)\\s*=",
    "severity": "medium",
    "description": "Mendeteksi event handler JavaScript pada parameter"
  },
  {
    "id": "XSS-003",
    "name": "XSS JavaScript URI",
    "attack_type": "XSS",
    "pattern": "javascript\\s*:",
    "severity": "high",
    "description": "Mendeteksi penggunaan skema javascript:"
  },
  {
    "id": "XSS-004",
    "name": "XSS Alert Function",
    "attack_type": "XSS",
    "pattern": "(alert|prompt|confirm)\\s*\\(",
    "severity": "medium",
    "description": "Mendeteksi fungsi JavaScript umum pada payload XSS"
  }
]

Rule SQLi:
Simpan rule di backend/rules/sqli_rules.json dengan isi minimal:

[
  {
    "id": "SQLI-001",
    "name": "SQLi Union Select",
    "attack_type": "SQLi",
    "pattern": "union\\s+select",
    "severity": "high",
    "description": "Mendeteksi pola UNION SELECT"
  },
  {
    "id": "SQLI-002",
    "name": "SQLi Boolean Based",
    "attack_type": "SQLi",
    "pattern": "('|\\\")?\\s*(or|and)\\s+('|\\\")?\\d+('|\\\")?\\s*=\\s*('|\\\")?\\d+",
    "severity": "high",
    "description": "Mendeteksi pola boolean-based SQL injection"
  },
  {
    "id": "SQLI-003",
    "name": "SQLi Comment Pattern",
    "attack_type": "SQLi",
    "pattern": "(--|#|/\\*|\\*/)",
    "severity": "medium",
    "description": "Mendeteksi komentar SQL yang umum digunakan dalam SQLi"
  },
  {
    "id": "SQLI-004",
    "name": "SQLi Time Based",
    "attack_type": "SQLi",
    "pattern": "(sleep\\s*\\(|benchmark\\s*\\()",
    "severity": "high",
    "description": "Mendeteksi time-based SQL injection"
  },
  {
    "id": "SQLI-005",
    "name": "SQLi Information Schema",
    "attack_type": "SQLi",
    "pattern": "information_schema",
    "severity": "high",
    "description": "Mendeteksi akses ke information_schema"
  }
]

Rule engine:
Buat fungsi load_rules().
Buat fungsi match_rules(payload) yang mengembalikan list matched rules.
Gunakan re.search dengan re.IGNORECASE.
Jika tidak ada rule cocok, hasilnya list kosong.

Classifier:
Buat fungsi classify(matched_rules).
Jika terdapat attack_type XSS, label XSS.
Jika terdapat attack_type SQLi, label SQLi.
Jika tidak ada rule, label Normal.
Jika cocok keduanya, boleh label Multiple atau simpan label utama berdasarkan prioritas. Saya lebih memilih label Multiple jika cocok keduanya.

Severity:
Jika matched_rules kosong, severity = "none".
Jika ada high, severity = "high".
Jika tidak ada high tetapi ada medium, severity = "medium".
Jika hanya low, severity = "low".

Recommendation:
Buat fungsi generate_recommendation(label, severity, ip, request_uri).
Jika label XSS high, rekomendasikan validasi input, output encoding, pemeriksaan endpoint, dan pertimbangkan blokir IP jika berulang.
Jika label SQLi high, rekomendasikan prepared statement, validasi parameter, pemeriksaan query backend, dan pertimbangkan blokir IP jika berulang.
Jika Normal, rekomendasi "-".

Database SQLite:
Buat database dengan tabel:

access_logs:
id, ip, timestamp, method, request_uri, protocol, status_code, body_bytes_sent, referrer, user_agent, raw_log, created_at

detection_results:
id, log_id, decoded_payload, normalized_payload, label, severity, matched_rules, recommendation, created_at

rules:
id, rule_code, name, attack_type, pattern, severity, description, is_active

evaluation_results:
id, total_data, true_positive, true_negative, false_positive, false_negative, accuracy, precision_score, recall_score, f1_score, created_at

Backend API:
Buat endpoint:
GET /api/health
GET /api/logs
GET /api/detections
GET /api/detections/latest
GET /api/dashboard/summary
GET /api/dashboard/top-attacker-ip
GET /api/dashboard/attack-types
GET /api/dashboard/rule-triggered
GET /api/rules
POST /api/rules
PUT /api/rules/{id}
DELETE /api/rules/{id}
GET /api/reports/export-csv
POST /api/evaluate
WebSocket /ws/alerts

FastAPI startup:
Saat backend startup, jalankan log watcher pada background thread atau asyncio task.
Setiap baris log baru:
1. parse log
2. jika gagal, skip
3. preprocess request_uri
4. match rules
5. classify
6. generate severity
7. generate recommendation
8. save access_log
9. save detection_result
10. jika label XSS/SQLi/Multiple, kirim alert ke WebSocket clients

Frontend React:
Buat dashboard sederhana.

Halaman Dashboard:
- Summary cards: total logs, total normal, total XSS, total SQLi, total alert.
- Grafik attack types.
- Grafik top attacker IP.
- Grafik rule paling sering terpicu.
- Tabel alert terbaru.

Halaman DetectionResults:
- Tabel semua hasil deteksi.
- Kolom: timestamp, ip, method, request_uri, decoded_payload, label, severity, matched_rules, recommendation.
- Tambahkan filter berdasarkan label.

Halaman RealtimeAlerts:
- Koneksi ke WebSocket /ws/alerts.
- Tampilkan alert baru secara realtime tanpa refresh.
- Jika ada alert XSS atau SQLi, tampilkan card alert dengan warna severity.

Halaman Rules:
- Tampilkan daftar rule XSS dan SQLi.
- Jika sempat, buat fitur tambah/edit/delete rule.
- Jika terlalu kompleks, cukup tampilkan rule.

Export CSV:
Endpoint /api/reports/export-csv harus menghasilkan file CSV dari detection_results.

README:
Buat instruksi instalasi dan menjalankan:
1. cd backend
2. python3 -m venv venv
3. source venv/bin/activate
4. pip install -r requirements.txt
5. uvicorn main:app --host 0.0.0.0 --port 8000
6. cd frontend
7. npm install
8. npm run dev

Tambahkan catatan permission:
Program perlu akses baca ke /var/log/nginx/dvwa_access.log.
Jika permission denied, jalankan dengan sudo untuk pengujian atau tambahkan user ke group yang bisa membaca log Nginx.

Contoh:
sudo usermod -aG adm $USER
ls -l /var/log/nginx/dvwa_access.log

Tambahkan juga contoh uji:
Untuk XSS, request contoh:
http://server/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E

Untuk SQLi, request contoh:
http://server/dvwa/vulnerabilities/sqli/?id=1%27%20or%201%3D1--&Submit=Submit

Catatan keamanan:
Aplikasi hanya digunakan pada lingkungan pengujian DVWA atau sistem yang memiliki izin. Jangan menjalankan pengujian serangan pada sistem pihak ketiga tanpa izin.

Prioritas pengerjaan:
1. Backend log watcher realtime.
2. Parser Nginx combined log.
3. Preprocessing dan rule engine.
4. Database save result.
5. API summary dan detections.
6. WebSocket alert.
7. Frontend dashboard sederhana.
8. Export CSV.
9. README.

Pastikan kode modular, mudah dibaca, dan setiap fungsi penting diberi komentar singkat.
```

---

# 3. Prompt Alternatif Versi Sederhana Streamlit

Gunakan prompt ini jika ingin implementasi lebih cepat untuk demo sidang.

```text
Buat aplikasi WebLog-IDS versi sederhana menggunakan Python Streamlit.

Aplikasi harus membaca file /var/log/nginx/dvwa_access.log secara realtime seperti tail -f.
Setiap log baru diparse, didecode, dinormalisasi, dicocokkan dengan rule regex XSS dan SQLi, lalu ditampilkan pada dashboard Streamlit.

Gunakan:
Python
Streamlit
SQLite
Pandas
Regex
Plotly

Fitur:
1. Realtime log monitoring dari /var/log/nginx/dvwa_access.log.
2. Parser Nginx combined log.
3. URL decoding maksimal 3 kali.
4. Rule XSS dan SQLi berbasis regex.
5. Label Normal, XSS, SQLi, atau Multiple.
6. Simpan hasil ke SQLite.
7. Dashboard total Normal/XSS/SQLi.
8. Tabel alert terbaru.
9. Grafik jenis serangan.
10. Top attacker IP.
11. Rule paling sering terpicu.
12. Export CSV.

Buat file:
app.py
rules/xss_rules.json
rules/sqli_rules.json
database.py
services/parser.py
services/preprocessor.py
services/rule_engine.py
services/log_watcher.py
requirements.txt
README.md

Pastikan aplikasi bisa dijalankan dengan:
streamlit run app.py

Tambahkan catatan bahwa program butuh permission baca ke /var/log/nginx/dvwa_access.log.
```

---

# 4. Rekomendasi Pilihan Implementasi

Jika target utama adalah cepat memiliki program yang bisa didemokan, gunakan versi Streamlit. Versi ini lebih mudah dibuat karena backend dan dashboard berada dalam satu aplikasi Python.

Jika target utama adalah sistem yang lebih rapi, profesional, dan mendekati aplikasi nyata, gunakan versi FastAPI + React + WebSocket. Versi ini lebih sesuai untuk menjelaskan arsitektur sistem realtime pada Bab 3 dan implementasi pada Bab 4.

Rekomendasi akhir untuk Tugas Akhir ini adalah menggunakan **FastAPI + React + WebSocket + SQLite** karena cukup teknis untuk kebutuhan akademik, mendukung realtime monitoring, dan tetap realistis untuk dikembangkan sebagai prototipe.