"""
websocket_routes.py - Endpoint WebSocket untuk alert realtime.

Client (dashboard) terhubung ke /ws/alerts dan menunggu push alert dari server.
Tidak ada polling: server yang mengirim begitu ada deteksi serangan.
"""

import os
import sys

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services.alert_service import manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    """
    Endpoint WebSocket alert.

    Alur:
    1. manager.connect() menerima handshake & menyimpan koneksi.
    2. Loop await receive_text() HANYA untuk menjaga koneksi tetap terbuka dan
       mendeteksi saat client putus. Pesan dari client tidak diproses (alert
       bersifat satu arah server -> client), tapi receive diperlukan agar
       FastAPI dapat menangkap event disconnect.
    3. Saat WebSocketDisconnect, koneksi dihapus dari daftar aktif.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Menunggu pesan apa pun dari client; berfungsi sebagai "keep-alive"
            # sekaligus titik deteksi disconnect.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        # Jaga-jaga error tak terduga: tetap bersihkan koneksi.
        manager.disconnect(websocket)
        print(f"[WebSocket] Koneksi ditutup karena error: {e}")
