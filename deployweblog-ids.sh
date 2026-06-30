#!/usr/bin/env bash
#
# deployweblog-ids.sh
# ----------------------------------------------------------------------------
# Deploy weblog-ids dari repo git ke /opt/weblog-ids (produksi).
#
# Alur:
#   git pull (main) -> rsync backend -> pip install -> rsync frontend
#                     -> npm install -> npm run build -> restart backend
#
# Aman: .env, venv, node_modules, dist, __pycache__ TIDAK ditimpa.
# Domain/nginx/SSL/systemd tidak disentuh.
#
# Pakai:  ./deployweblog-ids.sh
#         ./deployweblog-ids.sh --no-pull     # skip git pull (sudah pull manual)
# ----------------------------------------------------------------------------

set -euo pipefail

# ---------- konfigurasi ----------
REPO="/home/ubuntu/weblog-ids/weblog-ids"
BRANCH="main"
DEST="/opt/weblog-ids"
BACKEND_VENV="${DEST}/backend/venv"
SERVICE="weblog-ids-backend"

# ---------- warna (mati kalau bukan TTY) ----------
if [ -t 1 ]; then
    C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'
    C_RED='\033[1;31m'; C_CYAN='\033[1;36m'; C_RST='\033[0m'
else
    C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_CYAN=''; C_RST=''
fi

log()    { printf "${C_CYAN}>>> %s${C_RST}\n" "$*"; }
ok()     { printf "${C_GREEN}[OK] %s${C_RST}\n" "$*"; }
warn()   { printf "${C_YELLOW}[!!] %s${C_RST}\n" "$*"; }
die()    { printf "${C_RED}[XX] %s${C_RST}\n" "$*" >&2; exit 1; }

# ---------- prasyarat ----------
command -v rsync  >/dev/null 2>&1 || die "rsync belum terpasang"
command -v npm    >/dev/null 2>&1 || die "npm belum terpasang"
[ -d "${REPO}" ]                 || die "repo tidak ditemukan: ${REPO}"
[ -d "${DEST}/backend" ]         || die "tujuan backend tidak ada: ${DEST}/backend"
[ -d "${DEST}/frontend" ]        || die "tujuan frontend tidak ada: ${DEST}/frontend"
[ -x "${BACKEND_VENV}/bin/pip" ] || die "venv pip tidak ada: ${BACKEND_VENV}/bin/pip"

DO_PULL=1
[ "${1:-}" = "--no-pull" ] && DO_PULL=0

# ---------- 0. info awal ----------
log "Deploy weblog-ids -> ${DEST}"
[ "$DO_PULL" -eq 1 ] && log "Akan git pull branch ${BRANCH}" || warn "Skip git pull (--no-pull)"

# ---------- 1. git pull ----------
if [ "$DO_PULL" -eq 1 ]; then
    log "git pull origin ${BRANCH} di ${REPO}"
    git -C "${REPO}" fetch origin "${BRANCH}"
    git -C "${REPO}" pull origin "${BRANCH}"
    ok "kode terbaru diambil"
fi

# snapshot commit untuk laporan
COMMIT=$(git -C "${REPO}" rev-parse --short HEAD 2>/dev/null || echo "unknown")
log "commit: ${COMMIT}"

# ---------- 2. rsync backend ----------
log "rsync backend (kecualikan venv, .env, __pycache__)"
rsync -av --delete \
    --exclude='venv/' \
    --exclude='.venv/' \
    --exclude='__pycache__/' \
    --exclude='.env' \
    --exclude='.git/' \
    "${REPO}/backend/" "${DEST}/backend/"
ok "backend tersinkron"

# ---------- 3. pip install (bila requirements berubah) ----------
log "pip install -r requirements.txt (venv)"
"${BACKEND_VENV}/bin/pip" install --quiet -r "${DEST}/backend/requirements.txt"
ok "dependensi backend terpasang"

# ---------- 4. rsync frontend ----------
log "rsync frontend (kecualikan node_modules, dist, .env)"
rsync -av --delete \
    --exclude='node_modules/' \
    --exclude='dist/' \
    --exclude='.env' \
    --exclude='.git/' \
    "${REPO}/frontend/" "${DEST}/frontend/"
ok "frontend tersinkron"

# ---------- 5. npm install + build ----------
log "npm install (frontend)"
( cd "${DEST}/frontend" && npm install --no-audit --no-fund )

log "npm run build (frontend -> dist)"
( cd "${DEST}/frontend" && npm run build )
ok "frontend dibangun ulang"

# ---------- 6. restart backend ----------
log "restart ${SERVICE}"
sudo systemctl restart "${SERVICE}"
sleep 1
if systemctl is-active --quiet "${SERVICE}"; then
    ok "service ${SERVICE} aktif"
else
    die "service ${SERVICE} gagal start. Cek: sudo journalctl -u ${SERVICE} -n 50 --no-pager"
fi

# ---------- 7. smoke test ----------
log "smoke test 127.0.0.1:8001"
HTTP=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8001/ || echo "000")
# 404 itu normal (root route belum didefinisikan); yang penting bukan 000/502/503
case "$HTTP" in
    000) warn "backend tidak merespons (${HTTP})" ;;
    502|503|504) warn "backend bermasalah (HTTP ${HTTP})" ;;
    *) ok "backend merespons (HTTP ${HTTP})" ;;
esac

echo
ok "Deploy selesai. commit=${COMMIT}"
printf "${C_GREEN}Cek: https://weblog-ids.zhilanazmi.id${C_RST}\n"
