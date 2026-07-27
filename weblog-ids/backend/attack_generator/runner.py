"""
runner.py - CLI entry point untuk attack_generator.

Contoh:
    python -m attack_generator.runner --target https://dvwa.zhilanazmi.id --full
    python -m attack_generator.runner --target https://dvwa.zhilanazmi.id --xss 50
    python -m attack_generator.runner --xss 20 --sqli 20 --normal 30 --multiple 5
"""

import argparse
import os
import sys
import urllib3

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from attack_generator.generator import AttackGenerator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TARGET = "https://dvwa.zhilanazmi.id"


def main() -> None:
    parser = argparse.ArgumentParser(description="WebLog-IDS attack generator (ground truth)")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Base URL DVWA lewat Nginx")
    parser.add_argument("--xss", type=int, default=0, help="Jumlah payload XSS")
    parser.add_argument("--sqli", type=int, default=0, help="Jumlah payload SQLi")
    parser.add_argument("--normal", type=int, default=0, help="Jumlah request normal")
    parser.add_argument("--multiple", type=int, default=0, help="Jumlah payload campuran")
    parser.add_argument("--full", action="store_true", help="Jalankan set lengkap default")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay antar request (detik)")
    parser.add_argument("--source-ip", default="", help="IP sumber (dokumentasi)")
    args = parser.parse_args()

    gen = AttackGenerator(target_url=args.target, delay=args.delay, source_ip=args.source_ip)

    if args.full:
        gen.run_full_test()
        return

    if args.normal:
        gen.send_normal(args.normal)
    if args.xss:
        gen.send_xss(args.xss)
    if args.sqli:
        gen.send_sqli(args.sqli)
    if args.multiple:
        gen.send_multiple(args.multiple)

    if not (args.normal or args.xss or args.sqli or args.multiple):
        parser.print_help()


if __name__ == "__main__":
    main()
