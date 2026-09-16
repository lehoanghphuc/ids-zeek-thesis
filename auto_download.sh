#!/bin/bash
LOG=~/download.log
URL="https://drive.google.com/uc?id=1XuhEMvYQMCiX7gTaFdxTqkLyP6_YmkZ-"
OUT=~/cicids2017_reduced.csv

echo "=== $(date) - bat dau/tiep tuc tai ===" >> $LOG

for i in {1..20}; do
  python3 -m gdown "$URL" -O "$OUT" --continue >> $LOG 2>&1
  if [ -f "$OUT" ]; then
    SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
    if [ "$SIZE" -ge 190000000 ]; then
      echo "=== $(date) - DA TAI XONG, size=$SIZE ===" >> $LOG
      exit 0
    fi
  fi
  echo "=== $(date) - lan thu $i chua xong, thu lai sau 10s ===" >> $LOG
  sleep 10
done