"""
main.py - Entry point FastAPI WebLog-IDS.

Saat startup:
1. init_db()  -> pastikan database & tabel MySQL tersedia.
2. Jalankan log watcher di background thread; tiap baris log baru diproses
   pipeline (parse -> deteksi -> simpan ke MySQL).

API yang aktif tahap ini: detections & dashboard summary (REST). WebSocket,
export CSV, evaluasi, dan frontend menyusul di tahap berikutnya.
"""

import os
import sys
import asyncio

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config
import database
from detection_pipeline import DetectionPipeline
from services.log_watcher import LogWatcher
from app_state import app_state
from routes.detection_routes import router as detection_router
from routes.dashboard_routes import router as dashboard_router
from routes.websocket_routes import router as websocket_router
from routes.report_routes import router as report_router

# Referensi global agar watcher bisa dihentikan saat shutdown.
_watcher: LogWatcher = None
_pipeline: DetectionPipeline = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle FastAPI: setup saat startup, cleanup saat shutdown."""
    global _watcher, _pipeline

    # 1. Siapkan database (idempotent).
    database.init_db()

    # 2. Simpan referensi event loop utama FastAPI. Watcher berjalan di thread
    #    sinkron, jadi ia butuh referensi loop ini untuk menjadwalkan broadcast
    #    WebSocket secara thread-safe (lihat detection_pipeline).
    app_state.loop = asyncio.get_running_loop()

    # 3. Siapkan pipeline (memuat rule sekali).
    _pipeline = DetectionPipeline()

    # 3. Jalankan watcher di background; tiap baris diteruskan ke pipeline.
    def handle_line(line: str):
        try:
            _pipeline.process_line(line)
        except Exception as e:
            # Satu baris bermasalah tidak boleh menjatuhkan watcher.
            print(f"[main] Gagal memproses baris log: {e}")

    _watcher = LogWatcher(on_line=handle_line)
    _watcher.start_background()
    # Simpan referensi watcher ke app_state agar endpoint dashboard bisa
    # melaporkan status watcher tanpa circular import ke main.py.
    app_state.watcher = _watcher
    print(f"[main] Watcher berjalan memantau: {config.LOG_FILE_PATH}")

    yield

    # Shutdown: hentikan watcher.
    if _watcher:
        _watcher.stop()
    print("[main] Shutdown selesai.")


app = FastAPI(title="WebLog-IDS", version="0.1.0", lifespan=lifespan)

# CORS: izinkan origin frontend React (Vite default 5173, CRA default 3000)
# agar dashboard di tahap berikutnya bisa memanggil API dari browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Daftarkan router REST (prefix /api sudah didefinisikan di tiap router).
app.include_router(detection_router)
app.include_router(dashboard_router)
# Router WebSocket alert realtime (/ws/alerts).
app.include_router(websocket_router)
# Router export CSV (/api/reports/export-csv).
app.include_router(report_router)


@app.get("/api/health")
def health():
    """Endpoint sederhana untuk cek backend hidup."""
    return {"status": "ok", "service": "WebLog-IDS"}
