# Panduan Deploy WebLog-IDS di Server Kampus (Nginx + IP Lokal)

Varian deploy untuk **server kampus / jaringan lokal**: diakses lewat IP (atau
hostname jaringan) **tanpa domain publik dan tanpa HTTPS**. Untuk deploy VPS
dengan domain + Certbot, lihat `DEPLOY.md`.

Asumsi contoh di panduan ini (sesuaikan):

| Hal | Nilai contoh |
|---|---|
| IP server kampus | `192.168.1.50` |
| Port publik | `80` (jika sudah dipakai, pakai `8080` — lihat §8.2) |
| Direktori aplikasi | `/var/www/weblog-ids` |
| User sistem aplikasi | `weblog` |
| Port backend (localhost saja) | `8001` |
| Database | `weblog_ids` (MySQL) |
| File log yang dipantau | `/var/log/nginx/dvwa_access.log` |

> **Catatan khas server kampus**: server kampus sering dipakai bersama
> (multi-aplikasi). Pastikan dulu port mana yang masih bebas:
> `sudo ss -tlnp | grep -E ':(80|8080|8001)\b'`.

## Gambaran Arsitektur Produksi

```
Browser (di jaringan kampus)
  │  http://192.168.1.50
  ▼
Nginx (port 80)
  ├── /              → statis frontend (hasil build Vite, folder dist/)
  ├── /api/*         → proxy ke uvicorn (127.0.0.1:8001)
  └── /ws/alerts     → proxy WebSocket ke uvicorn (127.0.0.1:8001)

Backend FastAPI (uvicorn, systemd service "weblog-ids")
  ├── MySQL (database weblog_ids)
  └── LogWatcher → membaca /var/log/nginx/dvwa_access.log (tail -f)
```

> Backend sengaja hanya listen di `127.0.0.1` — semua akses dari luar
> dilewatkan Nginx. Port 8001 dan 3306 tidak dibuka publik.

---

## 0. Prasyarat

- Server kampus dengan Ubuntu 20.04/22.04/24.04 dan akses sudo.
- Nginx sudah terpasang (jika belum: `sudo apt install nginx`).
- Kamu tahu IP statis server di jaringan kampus (`ip a` / tanya admin kampus).
- Browser pengakses berada satu jaringan dengan server (atau lewat VPN kampus).

---

## 1. Upload Kode ke Server

Dari komputer lokal (sesuaikan user/IP server):

```bash
# Opsi A: via git (disarankan)
git clone <repo-anda> /tmp/weblog-ids
rsync -av --exclude node_modules --exclude .git --exclude venv \
    --exclude __pycache__ /tmp/weblog-ids/ user@192.168.1.50:/tmp/weblog-ids/
ssh user@192.168.1.50
sudo mkdir -p /var/www/weblog-ids
sudo rsync -a /tmp/weblog-ids/ /var/www/weblog-ids/

# Opsi B: via scp (tanpa node_modules, venv, __pycache__)
scp -r ../weblog-ids user@192.168.1.50:/tmp/
ssh user@192.168.1.50 "sudo mv /tmp/weblog-ids /var/www/weblog-ids"
```

## 2. Buat User Sistem & Permission

Backend berjalan sebagai user khusus non-root, dan harus bisa membaca log
Nginx (group `adm`):

```bash
sudo adduser --system --group --home /var/www/weblog-ids --shell /bin/bash weblog
sudo usermod -aG adm weblog          # izin baca /var/log/nginx/*
sudo chown -R weblog:weblog /var/www/weblog-ids
```

> `--no-create-home` tidak dipakai karena home user sekaligus jadi WorkingDirectory
> service; bila home sudah ada, perintah di atas aman diabaikan error-nya.

## 3. Install Dependensi Sistem

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mysql-server nodejs npm
```

> Node.js dari repo Ubuntu umumnya cukup untuk build Vite. Bila `npm run build`
> gagal karena versi Node terlalu tua (< 18), pasang via NodeSource:
> `curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs`

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
>
> Di server kampus, MySQL (`bind-address` default 127.0.0.1) tidak perlu
> diubah — backend satu mesin dengan database.

## 5. Setup Backend

```bash
cd /var/www/weblog-ids/backend
sudo -u weblog python3 -m venv venv
sudo -u weblog ./venv/bin/pip install -r requirements.txt
```

### 5.1 File Environment Produksi

Buat file `/var/www/weblog-ids/backend/.env` (tidak boleh masuk repo):

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

### 5.2 Penyesuaian Kode: CORS (opsional, aman untuk dilewati)

Karena frontend produksi disajikan Nginx dari **origin yang sama** dengan
proxy `/api` + `/ws` (sama-sama `http://192.168.1.50`), browser tidak
mengirim preflight CORS sama sekali — konfigurasi CORS `main.py` saat ini
sudah tidak menghalangi. CORS hanya relevan bila kamu membuka frontend dari
origin lain (mis. `npm run dev` di laptop lintas jaringan).

Bila tetap ingin aman bila ada akses lintas origin nanti, edit `main.py`:

```python
allow_origins=[
    "http://localhost:5173",
    "http://localhost:3000",
    "http://192.168.1.50",
    "http://192.168.1.50:8080",
],
```

> Lakukan perubahan ini di repo lokal, commit, lalu upload ulang — jangan
> edit langsung di server saja agar tidak hilang saat deploy berikutnya.

### 5.3 File Log yang Dipantau

Backend memantau `/var/log/nginx/dvwa_access.log`. Buat file-nya agar watcher
tidak error saat startup jika belum ada traffic:

```bash
sudo touch /var/log/nginx/dvwa_access.log
sudo chown www-data:adm /var/log/nginx/dvwa_access.log
sudo chmod 640 /var/log/nginx/dvwa_access.log
```

Lalu arahkan access log vhost target (mis. DVWA atau aplikasi kampus yang
dimonitor) ke file tersebut — di konfigurasi Nginx server block aplikasi
tersebut:

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
> thread `LogWatcher` tunggal; lebih dari 1 worker akan membuat duplikat
> watcher dan state tidak konsisten.

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
`/ws` dari origin yang sama, cukup arahkan ke IP server:

```bash
cd /var/www/weblog-ids/frontend

# .env.production untuk build (sesuaikan IP/port dengan §8)
sudo -u weblog tee .env.production > /dev/null <<'EOF'
VITE_API_BASE_URL=http://192.168.1.50
EOF

sudo -u weblog npm install
sudo -u weblog npm run build     # hasil di dist/
```

> `WS_URL` otomatis diturunkan dari `BASE_URL` (http → ws), sehingga
> WebSocket akan ke `ws://192.168.1.50/ws/alerts` — sudah benar tanpa
> konfigurasi tambahan. Di jaringan lokal HTTP, browser tidak memblokir
> `ws://` dari halaman `http://` (beda dengan `wss://` di HTTPS).

Build ulang di setiap ada perubahan frontend:

```bash
cd /var/www/weblog-ids/frontend && sudo -u weblog npm run build
```

## 8. Konfigurasi Nginx

### 8.1 Port 80 masih bebas (ideal)

Buat `/etc/nginx/sites-available/weblog-ids.conf`:

```bash
sudo tee /etc/nginx/sites-available/weblog-ids.conf > /dev/null <<'EOF'
# WebLog-IDS - frontend statis + reverse proxy backend FastAPI (server kampus)
server {
    listen 80;
    # Tanpa domain: pakai IP. "_" menangkap request via IP/hostname apa pun.
    server_name 192.168.1.50 _;

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

### 8.2 Port 80 sudah dipakai aplikasi lain (umum di server kampus)

Jika port 80 dipakai web server kampus/DVWA, jalankan WebLog-IDS di port lain
(mis. `8080`) sebagai server block terpisah:

```nginx
server {
    listen 8080;
    server_name _;

    # ... (isi sama persis dengan §8.1 mulai dari root / hingga location /ws/)
}
```

Lalu sesuaikan `.env.production` frontend + rebuild (§7):

```
VITE_API_BASE_URL=http://192.168.1.50:8080
```

> Jangan pakai `default_server` bila server kampus punya situs default —
> cukup bedakan port/listen agar tidak bentrok.

### 8.3 Aktifkan site

```bash
sudo ln -s /etc/nginx/sites-available/weblog-ids.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

Izinkan Nginx membaca folder dist (user `weblog`):

```bash
sudo chmod 755 /var/www /var/www/weblog-ids /var/www/weblog-ids/frontend
```

## 9. Firewall

Server kampus biasanya di belakang firewall kampus. Di level server, cukup
buka SSH dan port publik Nginx — **batasi ke subnet kampus** bila memungkinkan:

```bash
sudo ufw allow OpenSSH
sudo ufw allow from 192.168.1.0/24 to any port 80 proto tcp
# bila pakai port 8080 (§8.2):
# sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
sudo ufw enable
```

Port 8001 dan 3306 **tidak** dibuka — backend & MySQL cukup diakses lokal.

> Koordinasikan dengan admin kampus bila akses dari luar subnet (mis. Wi-Fi
> eduroam/guest) perlu dijembatani — itu di luar kendali server.

## 10. Verifikasi End-to-End

1. **Backend hidup:**
   ```bash
   systemctl is-active weblog-ids        # active
   curl http://127.0.0.1:8001/api/health # {"status":"ok"}
   ```
2. **Lewat IP server** (dari laptop di jaringan kampus):
   ```bash
   curl http://192.168.1.50/api/health
   ```
3. **Frontend**: buka `http://192.168.1.50` di browser — Dashboard harus
   menampilkan ringkasan (awalnya 0) tanpa pesan error.
4. **Watcher & deteksi**: picu log serangan ke file yang dipantau:
   ```bash
   echo '127.0.0.1 - - [22/Aug/2026:10:00:00 +0700] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "test"' | sudo tee -a /var/log/nginx/dvwa_access.log
   ```
   Dalam < 1 detik alert XSS harus muncul di halaman **Alert Realtime**
   (WebSocket) dan di tabel **Hasil Deteksi**.
5. **CSV export**: klik export CSV di halaman Hasil Deteksi — file terunduh.

## 11. Perintah Operasional Harian

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

## 12. Troubleshooting

| Gejala | Kemungkinan penyebab & solusi |
|---|---|
| `502 Bad Gateway` | Backend mati → `systemctl status weblog-ids` + `journalctl -u weblog-ids -n 50` |
| Dashboard error "HTTP ..." saat diakses via IP | `VITE_API_BASE_URL` build masih `localhost:8000` → set `.env.production` (§7) lalu rebuild |
| Halaman `/detections` 404 saat refresh | `try_files ... /index.html` belum ada di Nginx (§8) |
| Alert realtime tidak muncul | Cek `location /ws/` punya header `Upgrade`/`Connection "upgrade"` (§8); cek tab Network browser → WS |
| Tidak bisa diakses dari laptop lain | IP keliru / firewall kampus memblokir / UFW belum mengizinkan subnet (§9); tes `ping` + `curl` dari laptop |
| Nginx gagal reload `bind() failed` | Port sudah dipakai aplikasi lain → pakai port lain (§8.2), cek `sudo ss -tlnp` |
| Watcher error permission log | User `weblog` belum masuk group `adm`, atau `logrotate` mengubah permission → `sudo usermod -aG adm weblog && sudo systemctl restart weblog-ids` |
| Backend gagal koneksi DB | `.env` salah password / MySQL belum jalan → `sudo systemctl status mysql` |
| Deteksi berhenti setelah beberapa hari | logrotate memutus watcher → pakai `copytruncate` atau restart berkala (§5.3) |
| Data kosong terus | `READ_FROM_BEGINNING=false` hanya memproses log **baru**; picu baris log baru atau set `READ_FROM_BEGINNING=true` sekali untuk memproses log lama |
| Server kampus mati/listrik padam | `systemctl enable` (§6) membuat backend auto-start; Nginx default sudah enabled |
