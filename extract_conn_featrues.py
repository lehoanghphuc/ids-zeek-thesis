#!/usr/bin/env python3
"""
extract_conn_features.py (v2 - dung dung 8 feature da thong nhat)

Doc file conn.log / nmap_clean.log cua Zeek (JSON Lines - moi dong 1 JSON object)
va tinh ra DUNG 8 feature tuong thich voi model rut gon (Zeek-deployable subset).

KHONG dua them Total Backward Packets / Total Length of Bwd Packets vi 2 cot nay
KHONG ton tai trong dataset CICIDS2017 goc dang dung.

8 feature dau ra (dung thu tu nay, phai khop voi luc train model o buoc sau):
    Destination Port
    Flow Duration
    Total Fwd Packets
    Total Length of Fwd Packets
    Flow Bytes/s
    Flow Packets/s
    Fwd Packets/s
    Bwd Packets/s

Cach dung:
    python3 extract_conn_features.py --input ~/ids_samples/nmap_clean.log --output ~/ids_samples/zeek_features.csv
"""

import argparse
import json
import csv
import sys

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
]

META_COLUMNS = ["_uid", "_src_ip", "_dst_ip", "_ts", "_proto", "_conn_state"]


def safe_div(a, b):
    return a / b if b else 0.0


def extract_one(rec):
    """rec: 1 dict tuong ung 1 dong conn.log da parse JSON."""
    duration = float(rec.get("duration", 0) or 0)
    orig_bytes = float(rec.get("orig_bytes", 0) or 0)
    resp_bytes = float(rec.get("resp_bytes", 0) or 0)
    orig_pkts = float(rec.get("orig_pkts", 0) or 0)
    resp_pkts = float(rec.get("resp_pkts", 0) or 0)
    dst_port = int(rec.get("id.resp_p", 0) or 0)

    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts
    # CICIDS2017 luu Flow Duration theo microseconds, Zeek duration la giay
    duration_us = duration * 1_000_000

    row = {
        "Destination Port": dst_port,
        "Flow Duration": duration_us,
        "Total Fwd Packets": orig_pkts,
        "Total Length of Fwd Packets": orig_bytes,
        "Flow Bytes/s": safe_div(total_bytes, duration),
        "Flow Packets/s": safe_div(total_pkts, duration),
        "Fwd Packets/s": safe_div(orig_pkts, duration),
        "Bwd Packets/s": safe_div(resp_pkts, duration),
        # cot phu de doi chieu / debug, KHONG dua vao model
        "_uid": rec.get("uid", ""),
        "_src_ip": rec.get("id.orig_h", ""),
        "_dst_ip": rec.get("id.resp_h", ""),
        "_ts": rec.get("ts", ""),
        "_proto": rec.get("proto", ""),
        "_conn_state": rec.get("conn_state", ""),
    }
    return row


def read_jsonl(path):
    with open(path, "r", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[bo qua dong {lineno}] JSON loi: {e}", file=sys.stderr)
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="file JSON Lines (vd nmap_clean.log hoac conn.log)")
    ap.add_argument("--output", required=True, help="file CSV dau ra")
    args = ap.parse_args()

    out_columns = FEATURE_COLUMNS + META_COLUMNS
    count = 0
    with open(args.output, "w", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=out_columns)
        writer.writeheader()
        for rec in read_jsonl(args.input):
            try:
                row = extract_one(rec)
            except Exception as e:
                print(f"[bo qua 1 record loi] {e}", file=sys.stderr)
                continue
            writer.writerow(row)
            count += 1

    print(f"Da trich xuat {count} connection -> {args.output}")
    print(f"So feature dua vao model: {len(FEATURE_COLUMNS)} ({', '.join(FEATURE_COLUMNS)})")


if __name__ == "__main__":
    main()