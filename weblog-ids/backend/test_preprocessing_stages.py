"""
test_preprocessing_stages.py - Harness pengujian kontribusi tahap preprocessing.

Menguji 13 payload XSS/SQLi melalui preprocessor pada level 1-4
(lihat services/preprocessor.preprocess_payload), lalu mencocokkan hasilnya
terhadap ruleset yang SAMA dengan sistem (dimuat via
services/rule_engine.load_rules, regex di-compile re.IGNORECASE dan
dicocokkan dengan re.search -- mekanisme identik dengan pipeline produksi).

Output:
1. Matriks payload x level (id rule terpicu, dipisah koma; "-" bila kosong).
2. Payload hasil preprocessing per level (repr, agar tab/spasi terlihat).
3. File CSV test_preprocessing_stages.csv (matriks + payload mentah).

Jalankan dari folder backend/:
    python test_preprocessing_stages.py
"""

import csv
import os
import sys
from typing import Dict, List, Tuple

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services import rule_engine
from services.preprocessor import preprocess_payload

# Payload mentah persis seperti dikirim ke URL (belum melalui decoding apa pun).
PAYLOADS: List[Tuple[str, str]] = [
    ("P01", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("P02", "%3C%73%63%72%69%70%74%3Ealert(1)%3C%2F%73%63%72%69%70%74%3E"),
    ("P03", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
    ("P04", "<ScRiPt >alert(1)</ScRiPt>"),
    ("P05", "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"),
    ("P06", "1%27%20OR%20%271%27%3D%271"),
    ("P07", "1%2527%2520OR%2520%25271%2527%253D%25271"),
    ("P08", "1%252527%252520OR%252520%252571%252527%25253D%252571"),
    ("P09", "1%20UNION%20SELECT%20null%2Cnull%2Cnull"),
    ("P10", "1%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54"),
    ("P11", "1' OR '1'='1"),
    ("P12", "1%20UNION%20%20SELECT%20null"),
    ("P13", "1%27%09OR%09%271%27%3D%271"),
]

LEVELS = (1, 2, 3, 4)
CSV_PATH = os.path.join(_BACKEND_DIR, "test_preprocessing_stages.csv")


def run_matrix(
    rules: List[Dict],
) -> Tuple[Dict[Tuple[str, int], List[str]], Dict[Tuple[str, int], str]]:
    """
    Jalankan tiap payload melalui preprocess_payload per level dan cocokkan
    hasilnya dengan rule_engine.match_rules (mekanisme produksi).

    Return (matrix, transformed):
        matrix[(pid, level)]     -> daftar id rule terpicu
        transformed[(pid, level)] -> string hasil preprocessing
    """
    matrix: Dict[Tuple[str, int], List[str]] = {}
    transformed: Dict[Tuple[str, int], str] = {}
    for pid, raw in PAYLOADS:
        for level in LEVELS:
            processed = preprocess_payload(raw, level)
            transformed[(pid, level)] = processed
            hits = rule_engine.match_rules(processed, rules)
            matrix[(pid, level)] = [h["id"] for h in hits]
    return matrix, transformed


def main() -> None:
    rules = rule_engine.load_rules()
    print(f"[Harness] {len(rules)} rule dimuat dari ruleset sistem.")
    print(f"[Harness] PREPROCESS_LEVEL konfigurasi aktif: {__import__('config').PREPROCESS_LEVEL}")
    print()

    matrix, transformed = run_matrix(rules)

    # --- Output a: matriks payload x level ---
    header = f"{'Payload':<8}" + "".join(f"{'T' + str(l):<28}" for l in LEVELS)
    print("MATRIKS RULE TERPICU PER LEVEL")
    print(header)
    print("-" * len(header))
    for pid, _ in PAYLOADS:
        cells = []
        for level in LEVELS:
            ids = matrix[(pid, level)]
            cells.append(",".join(ids) if ids else "-")
        print(f"{pid:<8}" + "".join(f"{c:<28}" for c in cells))
    print()

    # --- Output b: payload hasil preprocessing per level ---
    print("HASIL PREPROCESSING PER LEVEL (repr agar tab/spasi terlihat)")
    for pid, raw in PAYLOADS:
        print(f"{pid} RAW : {raw!r}")
        for level in LEVELS:
            print(f"{pid} T{level}  : {transformed[(pid, level)]!r}")
        print("-" * 60)

    # --- Output c: CSV ---
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["payload_id", "raw_payload"]
            + [f"T{level}_matched_rules" for level in LEVELS]
            + [f"T{level}_preprocessed" for level in LEVELS]
        )
        for pid, raw in PAYLOADS:
            row = [pid, raw]
            row += [
                ",".join(matrix[(pid, level)]) if matrix[(pid, level)] else "-"
                for level in LEVELS
            ]
            row += [transformed[(pid, level)] for level in LEVELS]
            writer.writerow(row)
    print(f"[Harness] Matriks disimpan ke: {CSV_PATH}")

    # Ringkasan deteksi per level (untuk sanity check cepat)
    print()
    print("RINGKASAN: jumlah payload terdeteksi >= 1 rule per level")
    for level in LEVELS:
        detected = sum(1 for pid, _ in PAYLOADS if matrix[(pid, level)])
        print(f"  T{level}: {detected}/{len(PAYLOADS)}")


if __name__ == "__main__":
    main()
