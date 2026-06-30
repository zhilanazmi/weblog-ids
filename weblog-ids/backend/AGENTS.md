# AGENTS.md — Backend WebLog-IDS

Panduan untuk agent (AI) yang bekerja di folder `backend/`. Baca dulu file ini
sebelum mengubah kode. Sesuaikan semua perubahan dengan konvensi yang sudah
berjalan.

## 1. Gambaran Umum

Backend **WebLog-IDS**: sistem deteksi intrusi berbasis analisis access log
Nginx secara realtime dengan pendekatan rule-based untuk serangan **XSS** dan
**SQL Injection**. Dibangun dengan **FastAPI** + **MySQL**, berjalan sebagai
proses tunggal yang: memantau file log (`tail -f`-like) di thread terpisah,
memproses tiap baris melalui pipeline deteksi, menyimpan hasil ke MySQL, dan
menyiarkan alert serangan ke dashboard via WebSocket.

Spesifikasi lengkap lihat `../../prd-weblog-ids.md` (repositori root). Komentar
kode sering merujuk nomor PRD, mis. "PRD 1.5.5".

## 2. Tech Stack

- **Python 3.10+** (pakai type hints: `typing.Optional/List/Dict/Any`)
- **FastAPI 0.111.0** + **uvicorn[standard] 0.30.1** (ASGI)
- **Pydantic 2.7.4** (validasi)
- **PyMySQL 1.4.6** — driver MySQL murni Python (tanpa dependency C, mudah di
  Windows). `pymysql.cursors.DictCursor` (baris sebagai dict).
- **pandas 2.2.2** + **scikit-learn 1.5.0** (statistik/CSV/evaluasi metrik)
- Database: **MySQL** (`weblog_ids`, charset `utf8mb4`)

Versi terkunci di `requirements.txt`. **Jangan tambah dependency** baru tanpa
alasan kuat; preferensi kode adalah stdlib + dependency yang sudah ada.

## 3. Struktur Direktori

```
backend/
├── main.py                # Entry point FastAPI (lifespan, CORS, registrasi router)
├── config.py              # Konfigurasi terpusat (baca env var, default aman)
├── database.py            # Lapisan akses MySQL (PyMySQL), init_db(), CRUD
├── app_state.py           # State runtime lintas modul (singleton) -> hindari circular import
├── detection_pipeline.py  # Orkestrasi: parse->preprocess->rule->classify->save->alert
├── schema.sql             # Skema DB untuk setup manual (phpMyAdmin/CLI)
├── requirements.txt
├── ws_client_test.py      # Client uji WebSocket (demo alert realtime)
├── routes/                # APIRouter per-domain
│   ├── detection_routes.py    # /api/logs, /api/detections, /api/recent-attacks
│   ├── dashboard_routes.py    # /api/dashboard/*
│   ├── websocket_routes.py    # /ws/alerts
│   └── report_routes.py       # /api/reports/export-csv
├── services/              # Logika bisnis (tanpa HTTP layer)
│   ├── log_watcher.py     # Realtime watcher (thread, polling, tail -f)
│   ├── nginx_parser.py    # Regex parser combined log Nginx
│   ├── preprocessor.py    # recursive URL-decode + normalisasi payload
│   ├── rule_engine.py     # Muat rule JSON + precompile regex + match
│   ├── classifier.py      # Label/severity/rekomendasi
│   ├── alert_service.py   # ConnectionManager WebSocket (broadcast)
│   └── report_service.py  # Bangun isi CSV dari DB
├── rules/                 # Rule set (JSON, sumber kebenaran rule)
│   ├── xss_rules.json
│   └── sqli_rules.json
└── sample_logs/           # Contoh access log untuk pengujian
```

## 4. Cara Menjalankan

Pastikan MySQL berjalan (mis. XAMPP: user `root`, password kosong, db
`weblog_ids`). Tabel dibuat otomatis saat startup via `database.init_db()`;
untuk setup manual: `mysql -u root -p < schema.sql` atau jalankan
`python database.py`.

```bash
# Install dependency (sekali)
pip install -r requirements.txt

# Jalankan server (dari folder backend/)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Health check
curl http://localhost:8000/api/health
```

`main.py` TIDAK punya blok `if __name__ == "__main__"` — harus lewat uvicorn
karena memakai `lifespan` async. Jangan tambahkan `uvicorn.run()` inline.

### Uji mandiri per modul

Hampir tiap modul punya blok `if __name__ == "__main__"` untuk uji cepat tanpa
menjalankan server penuh. Pakai ini untuk verifikasi cepat:

```bash
python database.py            # init DB + SHOW TABLES
python detection_pipeline.py  # proses sample log -> simpan ke MySQL
python services/nginx_parser.py
python services/preprocessor.py
python services/rule_engine.py
python services/classifier.py
python services/log_watcher.py   # tail -f file log (Ctrl+C berhenti)
python ws_client_test.py         # dengarkan alert WebSocket (demo)
```

## 5. Konfigurasi

Semua nilai dibaca dari **environment variable** lewat `config.py` dengan
default aman. **Jangan hardcode** kredensial/path di kode lain — selalu impor
dari `config`.

| Env var | Default | Keterangan |
|---|---|---|
| `LOG_FILE_PATH` | `/var/log/nginx/dvwa_access.log` | File log yang dipantau |
| `READ_FROM_BEGINNING` | `False` | True=baca dari awal; False=tail -f (akhir) |
| `POLL_INTERVAL` | `0.5` | Detik jeda polling watcher |
| `MAX_DECODE_ROUND` | `3` | Batas recursive URL-decode |
| `DB_HOST` | `localhost` | |
| `DB_PORT` | `3306` | |
| `DB_USER` | `root` | |
| `DB_PASSWORD` | `` (kosong) | default XAMPP |
| `DB_NAME` | `weblog_ids` | |
| `DB_CHARSET` | `utf8mb4` | |
| `XSS_RULES_PATH` | `rules/xss_rules.json` | |
| `SQLI_RULES_PATH` | `rules/sqli_rules.json` | |

## 6. Arsitektur & Alur Deteksi

Pipeline tiap baris log (`detection_pipeline.DetectionPipeline.process_line`):

```
parse (nginx_parser) -> preprocess (preprocessor.build_payload)
  -> rule match (rule_engine.match_rules) -> classify (classifier)
  -> severity -> recommend -> save access_log -> save detection_result
  -> [jika serangan] broadcast alert WebSocket
```

Penjenjangan kritis **threading vs asyncio**:
- `LogWatcher` berjalan di **thread sinkron** daemon (`threading.Thread`).
- `manager.broadcast()` adalah **coroutine** yang harus dijalankan di event loop
  FastAPI — tidak boleh dipanggil langsung dari thread watcher.
- Jembatan: `asyncio.run_coroutine_threadsafe(manager.broadcast(...),
  app_state.loop)` di `detection_pipeline._broadcast_alert`. Referensi loop
  diisi `app_state.loop = asyncio.get_running_loop()` saat startup (`main.py`).

`app_state` (singleton) ada justru agar `routes/` bisa baca status watcher tanpa
meng-impor `main.py` (yang sudah meng-impor `routes/` -> **circular import**).
Saat menambah state lintas modul, taruh di `app_state.py`, JANGAN di `main.py`.

Label serangan: `Normal`, `XSS`, `SQLi`, `Multiple` (XSS+SQLi sekaligus).
Severity: `none`/`low`/`medium`/`high`. Konstanta label serangan
`_ATTACK_LABELS = ("XSS", "SQLi", "Multiple")` dipakai di `detection_pipeline`
dan `detection_routes` untuk memicu alert.

## 7. Konvensi Kode (WAJIB diikuti)

- **Bahasa**: docstring & komentar **Bahasa Indonesia**. Setiap modul diawali
  docstring `"""..."""` yang menjelaskan tujuan + catatan desain. Komentar
  inline pakai `#`. JANGAN tambah komentar Inggris kecuali menyelaraskan kode
  lama yang sudah begitu.
- **Tidak ada komentar yang menjelaskan hal trivial** — kode yang ada memakai
  komentar untuk "mengapa" (justifikasi desain), bukan "apa". Ikuti pola ini.
- **Pola `sys.path` injection** di tiap modul yang butuh `import config`/`import
  database`:
  ```python
  _BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))      # services: dirname x2
  if _BACKEND_DIR not in sys.path:
      sys.path.insert(0, _BACKEND_DIR)
  ```
  Ini agar modul bisa dijalankan langsung (`python services/x.py`) DAN diimpor
  sebagai paket. Modul di `services/` pakai `os.path.dirname` **dua kali**
  (naik ke `backend/`); modul di root pakai **sekali**. Pertahankan pola ini
  saat menambah modul baru.
- **Import**: stdlib dulu, lalu pihak ketiga, lalu modul lokal (`import config`,
  `import database`, `from services.x import y`). Kelompokkan dengan baris
  kosong.
- **Type hints** wajib pada signature fungsi publik (`-> Dict[str, Any]`,
  `Optional[...]`).
- **Router**: tiap domain file sendiri dengan `APIRouter(prefix="/api",
  tags=[...])`, didaftarkan di `main.py` lewat `app.include_router(...)`.
  Prefix `/api` sudah di tiap router — JANGAN tambah prefix lagi di `main.py`.
- **Endpoint** mengembalikan `Dict[str, Any]` berisi `count`/`data`/metadata.
  Parameter query divalidasi via `fastapi.Query` (mis. `Query(50, ge=1, le=500)`).
- **Singleton**: `app_state` (di `app_state.py`) dan `manager` (di
  `alert_service.py`) adalah instance global tingkat modul. Jangan buat ulang.
- **Logging**: sengaja memakai `print` dengan prefix `[Modul]` (mis.
  `[Pipeline]`, `[RuleEngine]`). Tidak ada framework logging — jangan
  memperkenalkan `logging` tanpa alasan.
- **File rule** (`rules/*.json`): tiap rule butuh field `id`, `name`,
  `attack_type` (`XSS`/`SQLi`), `pattern` (regex), `severity`, `description`.
  Pattern di-compile dengan `re.IGNORECASE`. Menambah rule = edit JSON, bukan
  kode (sesuai PRD 1.10).

## 8. Aturan Keamanan (KRITIS)

- **SQL WAJIB parameterized** dengan placeholder `%s` (PyMySQL). JANGAN PERNAH
  sisipkan nilai ke string SQL via f-string/format kecuali untuk struktur query
  yang statis (mis. daftar placeholder dinamis, lihat pola
  `detection_routes.get_recent_attacks`). Ini krusial karena data yang disimpan
  **berasal dari request berbahaya** (payload XSS/SQLi).
- **Kredensial tidak boleh hardcode**. Semua lewat `config.py` -> env var.
- Tutup koneksi DB di `finally` (`conn.close()`) — pola yang sudah dipakai di
  semua route/service. Pertahankan.
- `re` pattern dari rule JSON dipakai dengan `re.search` + `IGNORECASE`, bukan
  `re.fullmatch` (cocokkan sebagian payload).

## 9. Verifikasi

Tidak ada framework test/lint resmi (tidak ada `pytest`, `ruff`, `mypy`, atau
skrip `npm run`-setara). Verifikasi dilakukan via:

1. **Blok `if __name__ == "__main__"`** di tiap modul (lihat §4) — jalankan
   modul yang diubah untuk memastikan tidak error.
2. **Uji end-to-end**: jalankan `uvicorn main:app --reload`, lalu tambah baris
   log ke `LOG_FILE_PATH` (atau set `LOG_FILE_PATH` ke file di `sample_logs/`
   dengan `READ_FROM_BEGINNING=True`) dan cek endpoint
   `/api/detections` + `/api/dashboard/summary`.
3. **Cek kesehatan**: `GET /api/health` -> `{"status":"ok"}`.

Saat selesai mengubah kode, jalankan minimal blok `__main__` modul terkait dan
impor `main.py` untuk memastikan tidak ada syntax/import error:
```bash
python -c "import main"   # cek semua import & registrasi router
```

## 10. Catatan

- CORS hanya mengizinkan `http://localhost:5173` (Vite) dan `:3000` (CRA) —
  frontend dev. Saat tambah origin, edit `main.py`.
- `schema.sql` adalah duplikat dokumentasi dari DDL di `database.py`; bila ubah
  skema, **perbarui keduanya**.
- `catatan_teknis.txt` berisi catatan ad-hoc proyek — bukan kode, tapi baca bila
  relevan.
