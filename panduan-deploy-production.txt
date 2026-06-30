# Panduan Deploy Production WebLog-IDS di VPS Ubuntu

Dokumen ini berisi panduan menjalankan project Tugas Akhir WebLog-IDS pada VPS Ubuntu dengan mode production menggunakan Nginx sebagai reverse proxy, FastAPI sebagai backend, React sebagai frontend, dan Nginx access log DVWA sebagai sumber data deteksi.

Project ini digunakan untuk kebutuhan defensive security dan penelitian Tugas Akhir, yaitu deteksi indikasi serangan XSS dan SQL Injection berbasis analisis access log web server pada lingkungan uji yang sah seperti DVWA.

## 1. Gambaran Arsitektur Deployment

Pada mode production, arsitektur yang direkomendasikan adalah sebagai berikut:

```text
Client Browser
    |
    | HTTP/HTTPS
    v
Nginx Reverse Proxy
    |
    |-- Serve frontend React build
    |
    |-- Proxy /api/ ke FastAPI backend
    |
    |-- Proxy /ws/ ke WebSocket FastAPI

FastAPI Backend
    |
    |-- Membaca /var/log/nginx/dvwa_access.log secara realtime
    |-- Parsing log Nginx combined format
    |-- Preprocessing request
    |-- Rule matching XSS dan SQL Injection
    |-- Klasifikasi Normal/XSS/SQLi/Multiple
    |-- Simpan hasil ke database
    |-- Kirim alert realtime via WebSocket

DVWA + Nginx
    |
    |-- Menghasilkan access log ke /var/log/nginx/dvwa_access.log
```

Rekomendasi port:

```text
DVWA              : port 80 atau domain/subdomain khusus
FastAPI backend   : 127.0.0.1:8000, tidak diekspos langsung ke publik
Dashboard frontend: disajikan oleh Nginx
WebSocket alert   : lewat reverse proxy Nginx
```

## 2. Asumsi Struktur Project

Panduan ini mengasumsikan project berada di:

```bash
/opt/weblog-ids
```

Dengan struktur umum:

```bash
/opt/weblog-ids
├── backend
│   ├── main.py
│   ├── database.py
│   ├── requirements.txt
│   ├── venv
│   └── ...
├── frontend
│   ├── package.json
│   ├── src
│   └── ...
└── ...
```

Jika struktur project berbeda, sesuaikan path pada command dan konfigurasi.

## 3. Pastikan Access Log DVWA Aktif

Cek konfigurasi Nginx untuk DVWA. File konfigurasi biasanya berada di salah satu lokasi berikut:

```bash
/etc/nginx/sites-available/dvwa
/etc/nginx/sites-available/default
```

Edit file konfigurasi:

```bash
sudo nano /etc/nginx/sites-available/dvwa
```

Pastikan server block DVWA memiliki access log khusus:

```nginx
access_log /var/log/nginx/dvwa_access.log combined;
error_log /var/log/nginx/dvwa_error.log;
```

Contoh ringkas konfigurasi DVWA:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/html/dvwa;
    index index.php index.html index.htm;

    access_log /var/log/nginx/dvwa_access.log combined;
    error_log /var/log/nginx/dvwa_error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    }
}
```

Catatan: versi PHP-FPM bisa berbeda, misalnya `php8.2-fpm.sock` atau `php8.3-fpm.sock`. Cek dengan:

```bash
ls /run/php/
```

Tes konfigurasi dan reload Nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Cek apakah log DVWA muncul:

```bash
sudo tail -f /var/log/nginx/dvwa_access.log
```

Akses DVWA dari browser, lalu pastikan baris log baru muncul.

## 4. Setup Backend FastAPI

Masuk ke folder backend:

```bash
cd /opt/weblog-ids/backend
```

Install dependency sistem:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

Buat virtual environment jika belum ada:

```bash
python3 -m venv venv
```

Aktifkan virtual environment:

```bash
source venv/bin/activate
```

Install dependency Python:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Jika backend menggunakan MySQL/MariaDB dengan PyMySQL dan muncul error terkait autentikasi `caching_sha2_password`, install package berikut:

```bash
pip install cryptography
```

Tambahkan ke `requirements.txt` agar dependency tidak hilang saat deploy ulang:

```bash
echo "cryptography" >> requirements.txt
```

## 5. Konfigurasi Database Backend

Pada project WebLog-IDS, database dapat menggunakan SQLite untuk prototipe atau MySQL/MariaDB jika project sudah memakai PyMySQL. Karena project yang sedang dijalankan di VPS menggunakan PyMySQL, pastikan tidak memakai user `root` MySQL untuk aplikasi.

Buat database dan user khusus:

```bash
sudo mysql
```

Lalu jalankan perintah SQL berikut:

```sql
CREATE DATABASE IF NOT EXISTS weblog_ids CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'weblog_user'@'localhost' IDENTIFIED BY 'weblog_pass_123';

GRANT ALL PRIVILEGES ON weblog_ids.* TO 'weblog_user'@'localhost';

FLUSH PRIVILEGES;

EXIT;
```

Jika backend membaca konfigurasi dari file `.env`, isi seperti ini:

```env
DB_HOST=localhost
DB_USER=weblog_user
DB_PASSWORD=weblog_pass_123
DB_NAME=weblog_ids
DB_PORT=3306
```

Jika konfigurasi database masih hardcode di `database.py`, cari bagian berikut:

```bash
grep -n "root\|DB_USER\|DB_PASSWORD\|DB_NAME\|MYSQL\|pymysql" database.py
```

Ubah user database dari `root` menjadi user aplikasi:

```python
DB_HOST = "localhost"
DB_USER = "weblog_user"
DB_PASSWORD = "weblog_pass_123"
DB_NAME = "weblog_ids"
DB_PORT = 3306
```

Catatan keamanan: password di atas hanya contoh untuk pengujian. Untuk VPS production yang benar-benar terbuka ke publik, gunakan password yang lebih kuat.

## 6. Konfigurasi Path Log Nginx

Pastikan backend membaca log DVWA dari:

```text
/var/log/nginx/dvwa_access.log
```

Cari konfigurasi log pada backend:

```bash
cd /opt/weblog-ids/backend
grep -R "dvwa_access.log\|LOG_FILE\|READ_FROM_BEGINNING\|/var/log/nginx" -n . --exclude-dir=venv
```

Pastikan nilai konfigurasinya sesuai:

```python
LOG_FILE_PATH = "/var/log/nginx/dvwa_access.log"
READ_FROM_BEGINNING = False
```

Untuk testing awal, `READ_FROM_BEGINNING` boleh diubah menjadi:

```python
READ_FROM_BEGINNING = True
```

Namun untuk demo realtime yang menyerupai mekanisme `tail -f`, gunakan:

```python
READ_FROM_BEGINNING = False
```

## 7. Permission Baca Log Nginx

Backend akan dijalankan oleh user Linux, misalnya `ubuntu`. User tersebut harus memiliki izin baca terhadap file log Nginx.

Cek permission log:

```bash
ls -l /var/log/nginx/dvwa_access.log
```

Tes baca log sebagai user saat ini:

```bash
tail -n 5 /var/log/nginx/dvwa_access.log
```

Jika muncul `Permission denied`, tambahkan user `ubuntu` ke group `adm`:

```bash
sudo usermod -aG adm ubuntu
```

Setelah itu logout dan login ulang ke VPS. Kemudian cek:

```bash
groups
tail -n 5 /var/log/nginx/dvwa_access.log
```

Jika masih bermasalah, gunakan ACL:

```bash
sudo setfacl -m u:ubuntu:r /var/log/nginx/dvwa_access.log
sudo setfacl -m u:ubuntu:rx /var/log/nginx
```

## 8. Test Backend Secara Manual

Sebelum dibuat sebagai service, jalankan backend manual:

```bash
cd /opt/weblog-ids/backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

Jika entry point berada di `app/main.py`, gunakan:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Backend berhasil jika muncul:

```text
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Cek API dari dalam VPS:

```bash
curl -i http://127.0.0.1:8000
```

Jika tersedia endpoint health:

```bash
curl -i http://127.0.0.1:8000/health
```

Cek dokumentasi FastAPI dari browser:

```text
http://IP_VPS:8000/docs
```

Untuk production, port 8000 nantinya tidak perlu dibuka publik karena akan diakses melalui Nginx reverse proxy.

## 9. Buat Backend Menjadi Service systemd

Buat file service:

```bash
sudo nano /etc/systemd/system/weblog-ids-backend.service
```

Isi dengan konfigurasi berikut:

```ini
[Unit]
Description=WebLog-IDS FastAPI Backend
After=network.target nginx.service mysql.service

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/weblog-ids/backend
Environment="PATH=/opt/weblog-ids/backend/venv/bin"
ExecStart=/opt/weblog-ids/backend/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Jika database menggunakan MariaDB, service database bisa bernama `mariadb.service`, sehingga bagian `[Unit]` dapat disesuaikan menjadi:

```ini
After=network.target nginx.service mariadb.service
```

Aktifkan service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable weblog-ids-backend
sudo systemctl start weblog-ids-backend
```

Cek status:

```bash
sudo systemctl status weblog-ids-backend
```

Lihat log backend:

```bash
journalctl -u weblog-ids-backend -f
```

Tes backend dari VPS:

```bash
curl -i http://127.0.0.1:8000
```

## 10. Build Frontend React

Masuk ke folder frontend:

```bash
cd /opt/weblog-ids/frontend
```

Install Node.js dan npm jika belum ada:

```bash
sudo apt install nodejs npm -y
```

Install dependency frontend:

```bash
npm install
```

Buat atau edit file `.env` frontend:

```bash
nano .env
```

Jika frontend dan backend disajikan oleh Nginx pada domain yang sama, gunakan path relatif:

```env
VITE_API_BASE_URL=/api
VITE_WS_URL=ws://your-domain.com/ws/alerts
```

Jika menggunakan HTTPS, gunakan:

```env
VITE_API_BASE_URL=/api
VITE_WS_URL=wss://your-domain.com/ws/alerts
```

Jika sementara masih memakai IP VPS tanpa HTTPS:

```env
VITE_API_BASE_URL=http://IP_VPS/api
VITE_WS_URL=ws://IP_VPS/ws/alerts
```

Build frontend:

```bash
npm run build
```

Hasil build biasanya berada di:

```bash
/opt/weblog-ids/frontend/dist
```

## 11. Konfigurasi Nginx Reverse Proxy untuk WebLog-IDS

Buat file konfigurasi Nginx:

```bash
sudo nano /etc/nginx/sites-available/weblog-ids
```

Contoh konfigurasi jika dashboard menggunakan domain atau subdomain sendiri:

```nginx
server {
    listen 80;
    server_name ids.your-domain.com;

    root /opt/weblog-ids/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
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
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

Jika belum memakai domain dan ingin memakai IP VPS, gunakan:

```nginx
server {
    listen 80;
    server_name _;

    root /opt/weblog-ids/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
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
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

Aktifkan konfigurasi:

```bash
sudo ln -s /etc/nginx/sites-available/weblog-ids /etc/nginx/sites-enabled/weblog-ids
```

Tes konfigurasi Nginx:

```bash
sudo nginx -t
```

Reload Nginx:

```bash
sudo systemctl reload nginx
```

Akses dashboard:

```text
http://IP_VPS
```

atau:

```text
http://ids.your-domain.com
```

## 12. Catatan Jika DVWA Sudah Menggunakan Port 80

Jika DVWA sudah memakai port 80 pada server block default, ada beberapa opsi deployment:

Pertama, gunakan subdomain berbeda:

```text
DVWA      : http://dvwa.your-domain.com
WebLog-IDS: http://ids.your-domain.com
```

Kedua, gunakan port berbeda untuk WebLog-IDS, misalnya 8080:

```nginx
server {
    listen 8080;
    server_name _;

    root /opt/weblog-ids/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Jika memakai port 8080, buka firewall:

```bash
sudo ufw allow 8080
```

Lalu akses:

```text
http://IP_VPS:8080
```

Untuk kebutuhan demo Tugas Akhir, port berbeda seperti ini cukup realistis dan mudah dijelaskan.

## 13. Firewall VPS

Cek status UFW:

```bash
sudo ufw status
```

Jika menggunakan HTTP biasa:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80
```

Jika memakai HTTPS:

```bash
sudo ufw allow 443
```

Jika dashboard memakai port 8080:

```bash
sudo ufw allow 8080
```

Untuk production, jangan buka port 8000 ke publik. Backend cukup listen di `127.0.0.1:8000` dan diakses oleh Nginx.

Jika sebelumnya sudah membuka port 8000 untuk testing, bisa ditutup:

```bash
sudo ufw deny 8000
```

## 14. Testing Alur Realtime

Buka terminal untuk memantau log DVWA:

```bash
sudo tail -f /var/log/nginx/dvwa_access.log
```

Buka terminal lain untuk memantau backend:

```bash
journalctl -u weblog-ids-backend -f
```

Akses DVWA dari browser, lalu lakukan request uji pada lingkungan DVWA milik sendiri. Setelah request masuk, alur yang diharapkan adalah:

```text
Request ke DVWA
→ Nginx menulis baris baru ke /var/log/nginx/dvwa_access.log
→ log_watcher membaca baris baru secara realtime
→ nginx_parser melakukan parsing combined log
→ preprocessor melakukan URL decoding dan normalisasi
→ rule_engine mencocokkan pola XSS/SQLi
→ classifier memberi label Normal/XSS/SQLi/Multiple
→ hasil deteksi disimpan ke database
→ alert dikirim ke dashboard melalui WebSocket
```

Cek dashboard WebLog-IDS. Data yang idealnya tampil meliputi total log, total Normal, total XSS, total SQLi, total alert, top attacker IP, endpoint paling sering diserang, rule paling sering terpicu, dan alert terbaru.

## 15. Perintah Operasional Harian

Restart backend:

```bash
sudo systemctl restart weblog-ids-backend
```

Stop backend:

```bash
sudo systemctl stop weblog-ids-backend
```

Start backend:

```bash
sudo systemctl start weblog-ids-backend
```

Cek status backend:

```bash
sudo systemctl status weblog-ids-backend
```

Lihat log backend:

```bash
journalctl -u weblog-ids-backend -f
```

Reload Nginx setelah perubahan konfigurasi:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Cek proses port:

```bash
ss -tulpn | grep -E "8000|80|8080|443"
```

## 16. Troubleshooting

Jika dashboard tidak bisa dibuka, cek Nginx:

```bash
sudo nginx -t
sudo systemctl status nginx
journalctl -u nginx -n 50
```

Jika API tidak bisa diakses lewat `/api`, cek backend:

```bash
sudo systemctl status weblog-ids-backend
curl -i http://127.0.0.1:8000
```

Jika WebSocket tidak tersambung, pastikan konfigurasi Nginx memiliki:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

Jika backend gagal membaca log:

```bash
ls -l /var/log/nginx/dvwa_access.log
tail -n 5 /var/log/nginx/dvwa_access.log
groups
```

Jika database MySQL menolak akses:

```bash
sudo mysql
```

Lalu pastikan user aplikasi sudah ada:

```sql
SELECT user, host FROM mysql.user;
SHOW GRANTS FOR 'weblog_user'@'localhost';
```

Jika muncul error `cryptography package is required`, aktifkan venv dan install:

```bash
cd /opt/weblog-ids/backend
source venv/bin/activate
pip install cryptography
```

Jika frontend tidak mengarah ke API yang benar, cek file `.env` frontend lalu build ulang:

```bash
cd /opt/weblog-ids/frontend
cat .env
npm run build
sudo systemctl reload nginx
```

## 17. Rekomendasi Penjelasan untuk Bab 4

Pada Bab 4 bagian implementasi dan pengujian, deployment ini dapat dijelaskan sebagai implementasi sistem pada lingkungan VPS Ubuntu. Nginx digunakan sebagai web server untuk DVWA sekaligus reverse proxy untuk dashboard WebLog-IDS. Backend FastAPI dijalankan sebagai service systemd agar tetap aktif secara otomatis, sedangkan frontend React dibuild menjadi file statis dan disajikan melalui Nginx.

Sumber data utama sistem adalah access log Nginx pada file `/var/log/nginx/dvwa_access.log`. Setiap request baru dari DVWA menghasilkan baris log baru, kemudian backend membaca baris tersebut secara realtime. Data log diproses melalui tahapan parsing, preprocessing, rule matching, klasifikasi, penyimpanan ke database, dan pengiriman alert ke dashboard melalui WebSocket.

Model deployment ini dipilih karena realistis untuk prototipe Tugas Akhir, mudah direplikasi, dan cukup untuk menunjukkan fungsi utama sistem intrusion detection berbasis analisis log web server secara realtime.

## 18. Checklist Akhir Deployment

Gunakan checklist berikut untuk memastikan deployment sudah siap demo:

```text
[ ] DVWA bisa diakses dari browser
[ ] /var/log/nginx/dvwa_access.log bertambah saat DVWA diakses
[ ] Backend FastAPI berjalan sebagai service systemd
[ ] curl http://127.0.0.1:8000 berhasil dari VPS
[ ] Frontend React sudah dibuild ke folder dist
[ ] Nginx berhasil serve dashboard WebLog-IDS
[ ] Endpoint /api berhasil diproxy ke backend
[ ] WebSocket /ws berhasil tersambung
[ ] Backend memiliki izin baca access log Nginx
[ ] Hasil deteksi tersimpan ke database
[ ] Dashboard menampilkan data deteksi dan alert realtime
```