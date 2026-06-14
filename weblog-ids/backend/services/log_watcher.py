"""
log_watcher.py - Realtime log watcher untuk Nginx access log.

Membaca file log secara realtime mirip `tail -f`:
- Default mulai membaca dari AKHIR file (hanya log baru).
- Bisa diatur membaca dari AWAL via config.READ_FROM_BEGINNING.
- Menangani file yang belum ada (menunggu sampai dibuat).
- Menangani permission denied dengan pesan error yang jelas.
- Menangani log rotation / truncation (file diganti atau dipotong).

Pendekatan: polling dengan jeda POLL_INTERVAL agar portabel di Windows
maupun Linux tanpa dependency tambahan.
"""

import os
import sys
import time
import threading
from typing import Callable, Optional

# Pastikan folder 'backend' ada di sys.path agar 'import config' berhasil
# baik saat diimpor sebagai paket maupun dijalankan langsung dari folder services.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config


class LogWatcher:
    """Memantau satu file log dan memanggil callback untuk tiap baris baru."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        read_from_beginning: Optional[bool] = None,
        poll_interval: Optional[float] = None,
        on_line: Optional[Callable[[str], None]] = None,
    ):
        # Ambil nilai dari config bila tidak dioverride lewat argumen.
        self.file_path = file_path or config.LOG_FILE_PATH
        self.read_from_beginning = (
            config.READ_FROM_BEGINNING
            if read_from_beginning is None
            else read_from_beginning
        )
        self.poll_interval = poll_interval or config.POLL_INTERVAL
        self.on_line = on_line

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Kontrol lifecycle
    # ------------------------------------------------------------------
    def start_background(self) -> None:
        """Menjalankan watcher pada thread terpisah (non-blocking)."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self.run, name="log-watcher", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Memberi sinyal stop dan menunggu thread berhenti."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Loop utama
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Loop blocking: tunggu file, buka, lalu tail baris baru."""
        # 1. Tunggu sampai file tersedia (Nginx mungkin belum membuatnya).
        if not self._wait_for_file():
            return  # di-stop sebelum file muncul

        try:
            # utf-8-sig aman: membuang BOM bila ada. Nginx menulis log tanpa BOM,
            # jadi pada kondisi normal ini berperilaku sama seperti utf-8 biasa.
            f = open(self.file_path, "r", encoding="utf-8-sig", errors="replace")
        except PermissionError:
            raise PermissionError(
                f"[LogWatcher] Permission ditolak saat membaca '{self.file_path}'. "
                f"Pada Linux, tambahkan user ke group log (mis. 'sudo usermod -aG adm $USER') "
                f"atau jalankan dengan hak akses yang sesuai."
            )

        with f:
            # 2. Posisi awal: akhir file (default) atau awal file.
            if self.read_from_beginning:
                f.seek(0, os.SEEK_SET)
            else:
                f.seek(0, os.SEEK_END)

            # Simpan inode awal untuk deteksi rotasi (best-effort, lintas OS).
            last_inode = self._current_inode()

            # 3. Loop baca baris baru.
            while not self._stop_event.is_set():
                line = f.readline()

                if line:
                    # Baris penuh diterima (diakhiri newline). Kirim ke callback.
                    if line.endswith("\n"):
                        self._emit(line.rstrip("\n"))
                    else:
                        # Baris parsial (belum ada newline). Mundurkan posisi
                        # agar dibaca ulang utuh pada iterasi berikutnya.
                        f.seek(f.tell() - len(line))
                        time.sleep(self.poll_interval)
                    continue

                # Tidak ada data baru: cek rotasi/truncation lalu tidur sejenak.
                if self._is_rotated(f, last_inode):
                    f.close()
                    if not self._wait_for_file():
                        return
                    f = open(
                        self.file_path, "r", encoding="utf-8-sig", errors="replace"
                    )
                    f.seek(0, os.SEEK_SET)  # file baru: baca dari awal
                    last_inode = self._current_inode()
                    continue

                time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Helper internal
    # ------------------------------------------------------------------
    def _emit(self, line: str) -> None:
        """Kirim satu baris ke callback bila ada isinya."""
        if not line.strip():
            return
        if self.on_line:
            self.on_line(line)

    def _wait_for_file(self) -> bool:
        """Tunggu hingga file ada. Return False bila di-stop lebih dulu."""
        warned = False
        while not self._stop_event.is_set():
            if os.path.exists(self.file_path):
                return True
            if not warned:
                print(
                    f"[LogWatcher] File '{self.file_path}' belum ada. "
                    f"Menunggu file dibuat..."
                )
                warned = True
            time.sleep(self.poll_interval)
        return False

    def _current_inode(self) -> Optional[int]:
        """Ambil inode file saat ini (None bila tidak tersedia/Windows)."""
        try:
            st = os.stat(self.file_path)
            return st.st_ino if st.st_ino != 0 else None
        except OSError:
            return None

    def _is_rotated(self, f, last_inode: Optional[int]) -> bool:
        """Deteksi log rotation (truncation atau penggantian file)."""
        try:
            disk_size = os.path.getsize(self.file_path)
        except OSError:
            return True  # file hilang -> anggap dirotasi

        # Truncation: file di-disk lebih kecil dari posisi baca saat ini.
        if disk_size < f.tell():
            return True

        # Penggantian file: inode berubah (efektif di Linux).
        current_inode = self._current_inode()
        if last_inode is not None and current_inode is not None:
            if current_inode != last_inode:
                return True

        return False


def watch_log(on_line: Callable[[str], None], **kwargs) -> LogWatcher:
    """Helper singkat: buat watcher, jalankan di background, kembalikan instance."""
    watcher = LogWatcher(on_line=on_line, **kwargs)
    watcher.start_background()
    return watcher


# ---------------------------------------------------------------------------
# Mode mandiri untuk pengujian manual:
#   python services/log_watcher.py
# Akan mencetak tiap baris baru dari file log yang dikonfigurasi.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[LogWatcher] Memantau: {config.LOG_FILE_PATH}")
    print(f"[LogWatcher] READ_FROM_BEGINNING = {config.READ_FROM_BEGINNING}")
    print(f"[LogWatcher] POLL_INTERVAL = {config.POLL_INTERVAL}s")
    print("[LogWatcher] Tekan Ctrl+C untuk berhenti.\n")

    def _print_line(line: str) -> None:
        print(f"[NEW] {line}")

    w = LogWatcher(on_line=_print_line)
    try:
        w.run()
    except KeyboardInterrupt:
        print("\n[LogWatcher] Dihentikan oleh user.")
    except PermissionError as e:
        print(str(e))
