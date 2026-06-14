"""
rule_engine.py - Memuat rule set dan mencocokkan payload dengan regex.

Rule disimpan di file JSON (PRD 1.10) agar mudah ditambah/diubah tanpa
mengubah kode. Setiap rule minimal punya: id, name, attack_type, pattern,
severity, description.
"""

import json
import re
from typing import List, Dict, Any

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import config


def _load_rule_file(path: str) -> List[Dict[str, Any]]:
    """Baca satu file rule JSON. Return list kosong bila file tidak ada."""
    if not os.path.exists(path):
        print(f"[RuleEngine] File rule tidak ditemukan: {path}")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[RuleEngine] Gagal parse JSON '{path}': {e}")
        return []
    return data if isinstance(data, list) else []


def load_rules(
    xss_path: str = None, sqli_path: str = None
) -> List[Dict[str, Any]]:
    """
    Muat seluruh rule (XSS + SQLi) dan precompile regex-nya.

    Setiap rule mendapat field tambahan:
        - _regex   : objek pola terkompilasi (re.IGNORECASE)
        - is_active: default True bila tidak disertakan di file
    Rule dengan pattern invalid akan dilewati dengan peringatan.
    """
    xss_path = xss_path or config.XSS_RULES_PATH
    sqli_path = sqli_path or config.SQLI_RULES_PATH

    raw_rules = _load_rule_file(xss_path) + _load_rule_file(sqli_path)

    compiled: List[Dict[str, Any]] = []
    for rule in raw_rules:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            rule["_regex"] = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print(f"[RuleEngine] Pattern invalid pada rule {rule.get('id')}: {e}")
            continue
        rule.setdefault("is_active", True)
        compiled.append(rule)

    return compiled


def match_rules(
    payload: str, rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Cocokkan payload (hasil preprocessing) dengan daftar rule.

    Menggunakan re.search + IGNORECASE. Hanya rule aktif yang diuji.
    Mengembalikan daftar rule yang terpicu (tanpa field internal _regex);
    list kosong bila tidak ada yang cocok.
    """
    matched: List[Dict[str, Any]] = []
    if not payload:
        return matched

    for rule in rules:
        if not rule.get("is_active", True):
            continue
        regex = rule.get("_regex")
        if regex is None:
            continue
        if regex.search(payload):
            matched.append(
                {
                    "id": rule.get("id"),
                    "name": rule.get("name"),
                    "attack_type": rule.get("attack_type"),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                }
            )
    return matched


# ---------------------------------------------------------------------------
# Uji mandiri:  python services/rule_engine.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    rules = load_rules()
    print(f"[RuleEngine] {len(rules)} rule dimuat.")
    tests = [
        "/vuln/?name=<script>alert(1)</script>",
        "/sqli/?id=1' or 1=1--&submit=submit",
        "/?q=union select password from users",
        "/login.php",
    ]
    for t in tests:
        hits = match_rules(t, rules)
        names = [h["id"] for h in hits]
        print(f"PAYLOAD: {t}\n  MATCHED: {names}")
        print("-" * 60)
