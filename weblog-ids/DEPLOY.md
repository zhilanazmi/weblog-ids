# Panduan Deploy WebLog-IDS di VPS (Nginx + Domain)

Panduan lengkap men-deploy **WebLog-IDS** (backend FastAPI + frontend React/Vite + MySQL) di VPS Ubuntu dengan Nginx sebagai reverse proxy dan domain:

```
https://weblog-ids.zhillanazmi.id
```

## Gambaran Arsitektur Produksi

```
Browser
  │  https://weblog-ids.zhillanazmi.id
  ▼
Nginx (port 443/80)
  ├── /              → statis frontend (hasil build Vite, folder dist/)
  ├── /api/*         → proxy ke uvicorn (127.0.0.1:8001)
  └── /ws/alerts     → proxy WebSocket ke uvicorn (127.0.0.1:8001)

Backend FastAPI (uvicorn, systemd service "weblog-ids")
  ├── MySQL (database weblog_ids)
  └── LogWatcher → membaca /var/log/nginx/dvwa_access.log (tail -f)
```

> Backend sengaja hanya listen di `127.0.0.1` — semua akses dari luar
> dilewatkan Nginx. Port 8001 tidak perlu (dan tidak boleh) dibuka publik.

---

## 0. Prasyarat

- VPS Ubuntu 20.04/22.04/24.04 dengan akses root/sudo.
- Domain `weblog-ids.zhillanazmi.id` sudah dibuat **A record** ke IP publik VPS.
- Nginx sudah terpasang (jika belum: `sudo apt install nginx`).

Asumsi path di VPS:

| Hal | Nilai |
|---|---|
| Direktori aplikasi | `/var/www/weblog-ids` |
| User sistem aplikasi | `weblog` |
| Port backend | `8001` (hanya localhost) |
| Database | `weblog_ids` (MySQL) |
| File log yang dipantau | `/var/log/nginx/dvwa_access.log` |

---

## 1. Upload Kode ke VPS

Dari komputer lokal (sesuaikan user/IP VPS):

```bash
# Opsi A: via git (disarankan)
ssh user@IP_VPS "sudo mkdir -p /var/www/weblog-ids && sudo chown $USER /var/www/weblog-ids"
git clone <repo-anda> /tmp/weblog-ids
rsync -av --exclude node_modules --exclude .git /tmp/weblog-ids/ user@IP_VPS:/var/www/weblog-ids/

# Opsi B: via scp (tanpa node_modules dan venv)
scp -r ../weblog-ids user@IP_VPS:/tmp/
ssh user@IP_VPS "mv /tmp/weblog-ids /var/www/weblog-ids"
```

Jangan upload `node_modules/` dan `__pycache__/` — akan dibuat ulang di VPS.

## 2. Buat User Sistem & Permission

Backend berjalan sebagai user khusus non-root, dan harus bisa membaca log Nginx
(group `adm`):

```bash
sudo adduser --system --group --home /var/www/weblog-ids --shell /bin/bash weblog
sudo usermod -aG adm weblog          # izin baca /var/log/nginx/*
sudo chown -R weblog:weblog /var/www/weblog-ids
```

## 3. Install Dependensi Sistem

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mysql-server nodejs npm certbot python3-certbot-nginx
```

## 4. Setup Database MySQL

```bash
sudo mysql
```

```sql
CREATE DATABASE weblog_ids CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'weblog'@'localhost' IDENTIFIED by 'PASSWORD_KUAT_DISINI';
GRANT ALL PRIVILEGES ON weblog_ids.* TO 'weblog'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> Semua tabel dibuat **otomatis** saat backend startup via `database.init_db()`.
> Tidak perlu import `schema.sql` manual.

## 5. Setup Backend

```bash
cd /var/www/weblog-ids/backend
sudo -u weblog python3 -m venv venv
sudo -u weblog ./venv/bin/pip install -r requirements.txt
```

### 5.1 File Environment Produksi

Buat file `/var/www/weblog-ids/backend/.env` berisi konfigurasi produksi
(tidak boleh masuk repo):

```bash
sudo -u weblog tee /var/www/weblog-ids/backend/.env > /dev/null <<'EOF'
# ---- Database ----
DB_HOST=localhost
DB_PORT=3306
DB_USER=weblog
DB_PASSWORD=PASSWORD_KUAT_DISINI
DB_NAME=weblog_ids
DB_CHARSET=utf8mb4

# ---- Log source ----
LOG_FILE_PATH=/var/log/nginx/dvwa_access.log
READ_FROM_BEGINNING=false
POLL_INTERVAL=0.5

# ---- Preprocessing ----
MAX_DECODE_ROUND=3
EOF
sudo chmod 600 /var/www/weblog-ids/backend/.env
sudo chown weblog:weblog /var/www/weblog-ids/backend/.env
```

### 5.2 Penyesuaian Kode Wajib: CORS

`main.py` saat ini hanya mengizinkan origin dev (`localhost:5173`/`:3000`).
Karena produksi memakai domain sendiri dan frontend disajikan dari origin yang
sama lewat Nginx (proxy `/api` + `/ws`), tambahkan domain ke daftar origins.
Edit `/var/www/weblog-ids/backend/main.py`:

```python
allow_origins=[
    "http://localhost:5173",
    "http://localhost:3000",
    "https://weblog-ids.zhillanazmi.id",
],
```

> Praktik terbaik: lakukan perubahan ini di repo (lokal), commit, lalu
> pull/upload ulang agar tidak hilang saat deploy berikutnya.

### 5.3 File Log yang Dipantau

Backend memantau `/var/log/nginx/dvwa_access.log`. Buat file-nya agar watcher
tidak error saat startup jika belum ada traffic:

```bash
sudo touch /var/log/nginx/dvwa_access.log
sudo chown www-data:adm /var/log/nginx/dvwa_access.log
sudo chmod 640 /var/log/nginx/dvwa_access.log
```

Lalu arahkan access log vhost target (mis. DVWA atau aplikasi yang dimonitor)
ke file tersebut — di konfigurasi Nginx server block aplikasi tersebut:

```nginx
access_log /var/log/nginx/dvwa_access.log combined;
```

> **Catatan logrotate**: saat logrotate memutar log Nginx, watcher akan
> kehilangan posisi baca. Solusi paling aman: pastikan `/etc/logrotate.d/nginx`
> memakai `copytruncate`, atau restart service `weblog-ids` setelah rotasi.

## 6. Systemd Service Backend

Buat `/etc/systemd/system/weblog-ids.service`:

```bash
sudo tee /etc/systemd/system/weblog-ids.service > /dev/null <<'EOF'
[Unit]
Description=WebLog-IDS Backend (FastAPI + uvicorn)
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=weblog
Group=weblog
WorkingDirectory=/var/www/weblog-ids/backend
EnvironmentFile=/var/www/weblog-ids/backend/.env
ExecStart=/var/www/weblog-ids/backend/venv/bin/uvicorn main:app \
    --host 127.0.0.1 \
    --port 8001 \
    --workers 1 \
    --no-access-log
Restart=always
RestartSec=3

# Hardening ringan
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

> **PENTING: `--workers 1` wajib.** Backend memakai `app_state` singleton dan
   thread `LogWatcher` tunggal; lebih dari 1 worker akan membuat duplikat
   watcher dan state tidak konsisten.

Aktifkan:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weblog-ids
sudo systemctl status weblog-ids
```

Cek kesehatan:

```bash
curl http://127.0.0.1:8001/api/health
# harus: {"status":"ok"}
```

## 7. Build & Deploy Frontend

Frontend perlu tahu alamat backend produksi. Karena Nginx mem-proxy `/api` dan
`/ws` dari domain yang sama, cukup arahkan ke domain:

```bash
cd /var/www/weblog-ids/frontend

# .env.production untuk build
sudo -u weblog tee .env.production > /dev/null <<'EOF'
VITE_API_BASE_URL=https://weblog-ids.zhillanazmi.id
EOF

sudo -u weblog npm install
sudo -u weblog npm run build     # hasil di dist/
```

> `WS_URL` otomatis diturunkan dari `BASE_URL` (https → wss), sehingga
> WebSocket akan ke `wss://weblog-ids.zhillanazmi.id/ws/alerts` — sudah benar
> tanpa konfigurasi tambahan.

Build ulang di setiap ada perubahan frontend:

```bash
cd /var/www/weblog-ids/frontend && sudo -u weblog npm run build
```

## 8. Konfigurasi Nginx

Buat `/etc/nginx/sites-available/weblog-ids.conf`:

```bash
sudo tee /etc/nginx/sites-available/weblog-ids.conf > /dev/null <<'EOF'
# WebLog-IDS - frontend statis + reverse proxy backend FastAPI
server {
    listen 80;
    server_name weblog-ids.zhillanazmi.id;

    # ---- Frontend (hasil build Vite) ----
    root /var/www/weblog-ids/frontend/dist;
    index index.html;

    # SPA fallback: route React (/detections, /alerts) dilayani index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache aset build Vite (nama file sudah hashed)
    location /assets/ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # ---- Backend REST API ----
    location /api/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ---- WebSocket /ws/alerts ----
    location /ws/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;   # jaga koneksi WS idle tidak diputus cepat
        proxy_send_timeout 300s;
    }
}
EOF
```

Aktifkan site dan tes:

```bash
sudo ln -s /etc/nginx/sites-available/weblog-ids.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

Izinkan Nginx membaca folder dist (user `weblog`):

```bash
sudo chmod 755 /var/www /var/www/weblog-ids /var/www/weblog-ids/frontend
```

## 9. HTTPS dengan Certbot

```bash
sudo certbot --nginx -d weblog-ids.zhillanazmi.id
```

Certbot otomatis: menerbitkan sertifikat Let's Encrypt, menambah redirect
HTTP→HTTPS, dan menyiapkan renewal otomatis (`systemctl list-timers | grep certbot`).

## 10. Firewall (opsional tapi disarankan)

```bash
sudo ufw allow 'Nginx Full'   # 80 + 443
sudo ufw allow OpenSSH
sudo ufw enable
```

Port 8001 dan 3306 **tidak** dibuka — backend & MySQL cukup diakses lokal.

---

## 11. Verifikasi End-to-End

1. **Backend hidup:**
   ```bash
   systemctl is-active weblog-ids        # active
   curl http://127.0.0.1:8001/api/health # {"status":"ok"}
   ```
2. **Lewat domain:**
   ```bash
   curl https://weblog-ids.zhillanazmi.id/api/health
   ```
3. **Frontend**: buka `https://weblog-ids.zhillanazmi.id` di browser —
   Dashboard harus menampilkan ringkasan (awalnya 0) tanpa pesan error.
4. **Watcher & deteksi**: picu log serangan ke file yang dipantau:
   ```bash
   echo '127.0.0.1 - - [22/Aug/2026:10:00:00 +0700] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "test"' | sudo tee -a /var/log/nginx/dvwa_access.log
   ```
   Dalam < 1 detik alert XSS harus muncul di halaman **Alert Realtime**
   (WebSocket) dan di tabel **Hasil Deteksi**.
5. **CSV export**: klik export CSV di halaman Hasil Deteksi — file terunduh.

## 12. Perintah Operasional Harian

```bash
# Log backend
sudo journalctl -u weblog-ids -f

# Restart / stop backend
sudo systemctl restart weblog-ids
sudo systemctl stop weblog-ids

# Update aplikasi (setelah pull/upload kode baru)
cd /var/www/weblog-ids/backend && sudo -u weblog ./venv/bin/pip install -r requirements.txt
cd /var/www/weblog-ids/frontend && sudo -u weblog npm install && sudo -u weblog npm run build
sudo systemctl restart weblog-ids
```

## 13. Troubleshooting

| Gejala | Kemungkinan penyebab & solusi |
|---|---|
| `502 Bad Gateway` | Backend mati → `systemctl status weblog-ids` + `journalctl -u weblog-ids -n 50` |
| Dashboard error "HTTP ..." saat diakses via domain | CORS belum memuat domain produksi (§5.2), atau `VITE_API_BASE_URL` build masih `localhost:8001` (§7) |
| Halaman `/detections` 404 saat refresh | `try_files ... /index.html` belum ada di Nginx (§8) |
| Alert realtime tidak muncul | Cek `location /ws/` punya header `Upgrade`/`Connection "upgrade"` (§8); cek tab Network browser → WS |
| Watcher error permission log | User `weblog` belum masuk group `adm`, atau `logrotate` mengubah permission → `sudo usermod -aG adm weblog && sudo systemctl restart weblog-ids` |
| Backend gagal koneksi DB | `.env` salah password / MySQL belum jalan → `sudo systemctl status mysql` |
| Deteksi berhenti setelah beberapa hari | logrotate memutus watcher → pakai `copytruncate` atau restart berkala (§5.3) |
| Data kosong terus | `READ_FROM_BEGINNING=false` hanya memproses log **baru**; picu baris log baru atau set `READ_FROM_BEGINNING=true` sekali untuk memproses log lama |
