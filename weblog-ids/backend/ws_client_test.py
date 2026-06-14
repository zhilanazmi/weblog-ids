"""
ws_client_test.py - Client uji WebSocket alert WebLog-IDS.

Menghubungkan ke /ws/alerts lalu mencetak setiap alert JSON yang diterima dari
server secara realtime. Berguna untuk demo: jalankan skrip ini, lalu picu log
serangan, dan amati alert muncul tanpa polling.

Cara pakai:
    pip install websockets
    python ws_client_test.py
    # atau tentukan URL lain:
    python ws_client_test.py ws://localhost:8000/ws/alerts
"""

import asyncio
import json
import sys

import websockets

DEFAULT_URL = "ws://localhost:8000/ws/alerts"


async def listen(url: str):
    print(f"[client] Menghubungkan ke {url} ...")
    async with websockets.connect(url) as ws:
        print("[client] Terhubung. Menunggu alert (Ctrl+C untuk berhenti)...\n")
        while True:
            raw = await ws.recv()
            # Server mengirim JSON; tampilkan rapi agar mudah dibaca saat demo.
            try:
                data = json.loads(raw)
                print("[ALERT] " + json.dumps(data, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                print("[ALERT] (raw) " + raw)
            print("-" * 60)


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    try:
        asyncio.run(listen(url))
    except KeyboardInterrupt:
        print("\n[client] Dihentikan oleh user.")
    except Exception as e:
        print(f"[client] Error: {e}")


if __name__ == "__main__":
    main()
