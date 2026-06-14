"""
app_state.py - Penyimpan status runtime aplikasi yang dibagikan antar modul.

Dipisah agar routes (mis. dashboard) bisa membaca status watcher tanpa harus
meng-import main.py -- ini menghindari circular import (main.py meng-import
routes, jadi routes tidak boleh meng-import main.py).
"""

from typing import Optional


class AppState:
    """Menyimpan referensi objek runtime yang dipakai lintas modul."""

    def __init__(self):
        # Referensi ke LogWatcher aktif. Diisi oleh main.py saat startup.
        self.watcher = None
        # Referensi ke event loop utama FastAPI. Diisi saat startup agar thread
        # watcher (sinkron) bisa menjadwalkan coroutine broadcast WebSocket ke
        # loop ini secara thread-safe (asyncio.run_coroutine_threadsafe).
        self.loop = None

    def is_watcher_running(self) -> bool:
        """True bila watcher ada dan thread-nya masih hidup."""
        w = self.watcher
        if w is None:
            return False
        thread = getattr(w, "_thread", None)
        return bool(thread and thread.is_alive())


# Instance tunggal (singleton sederhana) yang di-import modul lain.
app_state = AppState()
