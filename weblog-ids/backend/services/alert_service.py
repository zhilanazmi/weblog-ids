"""
alert_service.py - Manajemen koneksi WebSocket & broadcast alert realtime.

ConnectionManager menyimpan semua koneksi WebSocket yang aktif, lalu mengirim
(broadcast) alert ke seluruh client sekaligus. Dipakai agar dashboard bisa
menerima notifikasi serangan tanpa polling.

Catatan desain threading vs asyncio:
- Method di sini bersifat async (dipanggil dari event loop FastAPI).
- Log watcher berjalan di thread sinkron terpisah, sehingga broadcast TIDAK
  boleh dipanggil langsung dari thread itu. Jembatannya ada di
  detection_pipeline (asyncio.run_coroutine_threadsafe). Lihat komentar di sana.
"""

import asyncio
from typing import List, Dict, Any

from fastapi import WebSocket


class ConnectionManager:
    """Mengelola daftar koneksi WebSocket aktif dan broadcast pesan."""

    def __init__(self):
        # Daftar koneksi aktif. List sederhana cukup untuk skala prototipe.
        self.active_connections: List[WebSocket] = []
        # Lock async untuk melindungi list saat connect/disconnect/broadcast
        # berjalan bersamaan, mencegah race condition pada event loop.
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Terima handshake koneksi baru lalu simpan ke daftar aktif."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        print(
            f"[AlertService] Client terhubung. Total aktif: "
            f"{len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """
        Hapus koneksi yang putus dari daftar. Sengaja sinkron (bukan async)
        agar bisa dipanggil dari blok except WebSocketDisconnect tanpa await.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(
            f"[AlertService] Client terputus. Total aktif: "
            f"{len(self.active_connections)}"
        )

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        Kirim message (dict -> JSON) ke SEMUA client aktif.

        Bila satu client sudah putus/error saat pengiriman, koneksi itu
        dikumpulkan lalu dihapus SETELAH loop selesai. Dengan begitu satu
        koneksi bermasalah tidak menghentikan broadcast ke client lain
        (sesuai kebutuhan: broadcast harus tahan terhadap koneksi mati).
        """
        # Salin daftar di dalam lock agar iterasi aman dari perubahan konkuren.
        async with self._lock:
            targets = list(self.active_connections)

        dead: List[WebSocket] = []
        for connection in targets:
            try:
                # send_json otomatis serialisasi dict menjadi teks JSON.
                await connection.send_json(message)
            except Exception:
                # Koneksi gagal dikirimi (kemungkinan sudah putus) -> tandai.
                dead.append(connection)

        # Bersihkan koneksi mati yang terdeteksi saat broadcast.
        if dead:
            async with self._lock:
                for connection in dead:
                    if connection in self.active_connections:
                        self.active_connections.remove(connection)
            print(f"[AlertService] {len(dead)} koneksi mati dibersihkan.")


# Instance global tunggal yang dibagikan antara route WebSocket dan pipeline.
manager = ConnectionManager()
