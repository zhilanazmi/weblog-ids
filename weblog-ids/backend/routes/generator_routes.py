"""
generator_routes.py - Endpoint REST untuk menjalankan attack generator.

Generator berjalan di background thread agar HTTP request tidak menunggu
selama pengiriman payload (bisa puluhan request x delay). Status proses
disimpan di memori agar frontend bisa polling progres.
"""

import os
import sys
import threading
import urllib3
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from attack_generator.generator import AttackGenerator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/api/generator", tags=["generator"])

# State proses generator (single-run sederhana, cukup untuk skripsi).
_STATE: Dict[str, Any] = {
    "running": False,
    "summary": None,
    "error": None,
}


class GenerateRequest(BaseModel):
    """Payload untuk menjalankan generator dari dashboard."""

    target: str = Field("https://dvwa.zhilanazmi.id", description="Base URL DVWA lewat Nginx")
    xss: int = Field(20, ge=0, le=500)
    sqli: int = Field(20, ge=0, le=500)
    normal: int = Field(30, ge=0, le=500)
    multiple: int = Field(5, ge=0, le=200)
    delay: float = Field(0.5, ge=0.0, le=10.0)


def _run_in_background(payload: GenerateRequest) -> None:
    """Jalankan generator dan simpan ringkasan/error ke _STATE."""
    global _STATE
    try:
        gen = AttackGenerator(target_url=payload.target, delay=payload.delay)
        summary = gen.run_full_test(
            xss_count=payload.xss,
            sqli_count=payload.sqli,
            normal_count=payload.normal,
            multiple_count=payload.multiple,
        )
        _STATE["summary"] = summary
        _STATE["error"] = None
    except Exception as e:  # noqa: BLE001
        _STATE["error"] = str(e)
    finally:
        _STATE["running"] = False


@router.post("/run")
def run_generator(payload: GenerateRequest) -> Dict[str, Any]:
    """Mulai generator di background; return segera tanpa menunggu selesai."""
    global _STATE
    if _STATE.get("running"):
        return {"started": False, "message": "Generator sedang berjalan.", "state": _STATE}

    _STATE = {"running": True, "summary": None, "error": None}
    thread = threading.Thread(target=_run_in_background, args=(payload,), daemon=True)
    thread.start()
    return {"started": True, "message": "Generator dimulai di background.", "state": _STATE}


@router.get("/status")
def generator_status() -> Dict[str, Any]:
    """Ambil status proses generator terakhir untuk polling progres di UI."""
    return _STATE
