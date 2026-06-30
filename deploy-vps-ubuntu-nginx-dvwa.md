# Panduan Deploy WebLog-IDS di VPS Ubuntu dengan Nginx dan DVWA

Project ini punya 2 bagian:

- Backend FastAPI: port `8000`
- Frontend React/Vite: build static, serve lewat Nginx
- Nginx DVWA tetap jalan, IDS baca log `/var/log/nginx/dvwa_access.log`
- MySQL/MariaDB perlu database `weblog_ids`

Asumsi VPS Ubuntu, Nginx + DVWA sudah aktif.

## 1. Siapkan log DVWA di Nginx

Cari server block DVWA:

```bash
sudo nginx -T | grep -n "server_name\|root\|access_log"
```

Di config DVWA, pastikan ada access log khusus:

```nginx
access_log /var/log/nginx/dvwa_access.log;
```

Contoh:

```nginx
server {
    listen 80;
    server_name dvwa.domain.com;

    root /var/www/dvwa;
    index index.php index.html;

    access_log /var/log/nginx/dvwa_access.log;
    error_log /var/log/nginx/dvwa_error.log;

    # config PHP DVWA existing tetap
}
```

Reload Nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo touch /var/log/nginx/dvwa_access.log
```

## 2. Buat user agar backend bisa baca log

Cek permission log:

```bash
ls -l /var/log/nginx/dvwa_access.log
```

Jika service pakai user `weblogids`, kasih akses:

```bash
sudo useradd --system --home /opt/weblog-ids --shell /usr/sbin/nologin weblogids
sudo usermod -aG adm weblogids
sudo chown root:adm /var/log/nginx/dvwa_access.log
sudo chmod 640 /var/log/nginx/dvwa_access.log
```

## 3. Upload project ke VPS

Taruh project di `/opt/weblog-ids`:

```bash
sudo mkdir -p /opt/weblog-ids
sudo chown -R $USER:$USER /opt/weblog-ids
cd /opt/weblog-ids
git clone <URL_REPO_KAMU> .
```

Kalau upload manual pakai `scp`, folder penting:

```text
/opt/weblog-ids/weblog-ids/backend
/opt/weblog-ids/weblog-ids/frontend
```

## 4. Install dependency sistem

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm mysql-server
```

Kalau Node.js bawaan Ubuntu terlalu lama, pakai NodeSource Node 20:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

## 5. Setup database MySQL

Masuk MySQL:

```bash
sudo mysql
```

Buat database dan user:

```sql
CREATE DATABASE IF NOT EXISTS weblog_ids CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'weblogids'@'localhost' IDENTIFIED BY 'PASSWORD_KUAT_DI_SINI';
GRANT ALL PRIVILEGES ON weblog_ids.* TO 'weblogids'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Import schema opsional, karena backend juga menjalankan `init_db()` otomatis. Tetap aman import manual:

```bash
mysql -u weblogids -p weblog_ids < /opt/weblog-ids/weblog-ids/backend/schema.sql
```

## 6. Setup backend FastAPI

```bash
cd /opt/weblog-ids/weblog-ids/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Test manual:

```bash
DB_HOST=127.0.0.1 \
DB_PORT=3306 \
DB_USER=weblogids \
DB_PASSWORD='PASSWORD_KUAT_DI_SINI' \
DB_NAME=weblog_ids \
LOG_FILE_PATH=/var/log/nginx/dvwa_access.log \
uvicorn main:app --host 127.0.0.1 --port 8000
```

Cek dari shell lain:

```bash
curl http://127.0.0.1:8000/api/health
```

Output seharusnya:

```json
{"status":"ok","service":"WebLog-IDS"}
```

## 7. Buat systemd backend

Buat env file:

```bash
sudo nano /etc/weblog-ids.env
```

Isi:

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=weblogids
DB_PASSWORD=PASSWORD_KUAT_DI_SINI
DB_NAME=weblog_ids
LOG_FILE_PATH=/var/log/nginx/dvwa_access.log
READ_FROM_BEGINNING=false
POLL_INTERVAL=0.5
```

Amankan env file:

```bash
sudo chmod 600 /etc/weblog-ids.env
```

Buat service:

```bash
sudo nano /etc/systemd/system/weblog-ids.service
```

Isi:

```ini
[Unit]
Description=WebLog-IDS FastAPI Backend
After=network.target mysql.service nginx.service
Requires=mysql.service

[Service]
User=weblogids
Group=weblogids
WorkingDirectory=/opt/weblog-ids/weblog-ids/backend
EnvironmentFile=/etc/weblog-ids.env
ExecStart=/opt/weblog-ids/weblog-ids/backend/.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Pastikan ownership:

```bash
sudo chown -R weblogids:weblogids /opt/weblog-ids
sudo usermod -aG adm weblogids
```

Start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weblog-ids
sudo systemctl status weblog-ids
```

Lihat log service:

```bash
journalctl -u weblog-ids -f
```

## 8. Setup frontend React

Frontend default ke `localhost:8000`, jadi wajib set URL backend public sebelum build.

Jika pakai domain sama, misal dashboard di `ids.domain.com`, backend lewat path `/api` dan websocket `/ws`, pakai:

```bash
cd /opt/weblog-ids/weblog-ids/frontend
cat > .env.production <<'EOF'
VITE_API_BASE_URL=https://ids.domain.com
VITE_WS_URL=wss://ids.domain.com/ws/alerts
EOF

npm install
npm run build
```

Hasil build:

```text
/opt/weblog-ids/weblog-ids/frontend/dist
```

## 9. Nginx reverse proxy dashboard dan API

Buat config baru:

```bash
sudo nano /etc/nginx/sites-available/weblog-ids
```

Contoh HTTP:

```nginx
server {
    listen 80;
    server_name ids.domain.com;

    root /opt/weblog-ids/weblog-ids/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600;
    }
}
```

Enable config:

```bash
sudo ln -s /etc/nginx/sites-available/weblog-ids /etc/nginx/sites-enabled/weblog-ids
sudo nginx -t
sudo systemctl reload nginx
```

Jika pakai HTTPS:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d ids.domain.com
```

Setelah HTTPS aktif, rebuild frontend dengan `https/wss`, lalu reload Nginx.

## 10. Rekomendasi domain

Paling rapi pakai subdomain terpisah:

- `dvwa.domain.com` = DVWA
- `ids.domain.com` = dashboard WebLog-IDS

Jangan gabung root DVWA dengan dashboard, agar route tidak tabrakan.

## 11. Test end-to-end

Cek backend:

```bash
curl http://127.0.0.1:8000/api/health
curl http://ids.domain.com/api/health
```

Buka dashboard:

```text
http://ids.domain.com
```

Trigger log DVWA:

```bash
curl "http://dvwa.domain.com/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
curl "http://dvwa.domain.com/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"
```

Cek log masuk:

```bash
sudo tail -f /var/log/nginx/dvwa_access.log
journalctl -u weblog-ids -f
```

Cek data deteksi:

```bash
curl http://ids.domain.com/api/detections/latest?n=10
```

## 12. Masalah umum

### Backend gagal baca log

Cek akses user service:

```bash
sudo -u weblogids tail -n 1 /var/log/nginx/dvwa_access.log
```

Kalau permission denied:

```bash
sudo usermod -aG adm weblogids
sudo chown root:adm /var/log/nginx/dvwa_access.log
sudo chmod 640 /var/log/nginx/dvwa_access.log
sudo systemctl restart weblog-ids
```

### Dashboard masih error localhost

Frontend belum rebuild dengan `.env.production`.

Fix:

```bash
cd /opt/weblog-ids/weblog-ids/frontend
cat > .env.production <<'EOF'
VITE_API_BASE_URL=https://ids.domain.com
VITE_WS_URL=wss://ids.domain.com/ws/alerts
EOF
npm run build
sudo systemctl reload nginx
```

### WebSocket tidak connect

Pastikan Nginx punya blok:

```nginx
location /ws/ {
    proxy_pass http://127.0.0.1:8000/ws/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### CORS error

Kalau frontend dan backend sama domain lewat Nginx (`https://ids.domain.com/api`), CORS aman.

Kalau beda domain/port, `main.py` saat ini cuma allow `localhost`, jadi perlu ubah `allow_origins`.

Rekomendasi: satu domain via Nginx seperti config di atas, jadi tidak perlu ubah kode.

## Urutan ringkas

```bash
# VPS
sudo apt update
sudo apt install -y python3-venv python3-pip nodejs npm mysql-server nginx

# DB
sudo mysql
# buat database/user weblogids

# Backend
cd /opt/weblog-ids/weblog-ids/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
cat > .env.production <<'EOF'
VITE_API_BASE_URL=https://ids.domain.com
VITE_WS_URL=wss://ids.domain.com/ws/alerts
EOF
npm install
npm run build

# systemd + nginx reverse proxy
sudo systemctl enable --now weblog-ids
sudo nginx -t && sudo systemctl reload nginx
```
