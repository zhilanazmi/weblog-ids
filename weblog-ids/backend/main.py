"""
main.py - Entry point FastAPI WebLog-IDS.

Pada tahap ini fokusnya lapisan database + integrasi pipeline. API dashboard,
WebSocket, dan frontend belum dikerjakan (menyusul di tahap berikutnya).

Saat startup:
1. init_db()  -> pastikan database & tabel MySQL tersedia.
2. Jalankan log watcher di background thread; tiap baris log baru diproses
   pipeline (parse -> deteksi -> simpan ke MySQL).
"""

import os
import sys

from contextlib import asynccontextmanager
from fastapi import FastAPI

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config
import database
from detection_pipeline import DetectionPipeline
from services.log_watcher import LogWatcher

# Referensi global agar watcher bisa dihentikan saat shutdown.
_watcher: LogWatcher = None
_pipeline: DetectionPipeline = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle FastAPI: setup saat startup, cleanup saat shutdown."""
    global _watcher, _pipeline

    # 1. Siapkan database (idempotent).
    database.init_db()

    # 2. Siapkan pipeline (memuat rule sekali).
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
    print(f"[main] Watcher berjalan memantau: {config.LOG_FILE_PATH}")

    yield

    # Shutdown: hentikan watcher.
    if _watcher:
        _watcher.stop()
    print("[main] Shutdown selesai.")


app = FastAPI(title="WebLog-IDS", version="0.1.0", lifespan=lifespan)


@app.get("/api/health")
def health():
    """Endpoint sederhana untuk cek backend hidup."""
    return {"status": "ok", "service": "WebLog-IDS"}
