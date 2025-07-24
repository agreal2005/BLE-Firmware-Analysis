#!/usr/bin/env python3
"""
generate_matched_json.py

Filter all_signs_enriched.json with addresses from a CSV and build matched_output.json.

Usage:
    python3 extract_comments.py <csv_file> <enriched_json> <output_json>

    csv_file       CSV with columns: address,name
    enriched_json  JSON produced by enrich.py (list of function dicts)
    output_json    Filename for filtered result
"""

import sys, csv, json
from pathlib import Path

def load_csv(csv_path):
    """Return dict {name: address} from CSV."""
    table = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row["name"].strip()
            addr = row["address"].strip()
            table[name] = addr
    return table

def main(csv_file, enriched_json, out_json):
    csv_map = load_csv(csv_file)

    with open(enriched_json, "r") as f:
        funcs = json.load(f)

    matched = []
    for fn in funcs:
        name = fn.get("name")
        if name in csv_map:
            fn_with_addr = dict(fn)           # shallow copy
            fn_with_addr["address"] = csv_map[name]
            matched.append(fn_with_addr)

    with open(out_json, "w") as f:
        json.dump(matched, f, indent=2)
    print(f"[INFO] Wrote {len(matched)} matched functions to {out_json}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 extract_comments.py <csv_file> <enriched_json> <output_json>")
        sys.exit(1)
    main(*sys.argv[1:])

