#!/bin/bash
LOG=~/download.log
URL="https://drive.google.com/uc?id=1XuhEMvYQMCiX7gTaFdxTqkLyP6_YmkZ-"
OUT=~/cicids2017_reduced.csv
TARGET_SIZE=190000000

echo "=== $(date) - bat dau vong lap tai (co timeout) ===" >> $LOG

while true; do
  if [ -f "$OUT" ]; then
    SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
    if [ "$SIZE" -ge "$TARGET_SIZE" ]; then
      echo "=== $(date) - DA TAI XONG, size=$SIZE ===" >> $LOG
      exit 0
    fi
  fi
  echo "=== $(date) - thu tai (timeout 90s moi lan) ===" >> $LOG
  timeout 90 python3 -m gdown "$URL" -O "$OUT" --continue -q >> $LOG 2>&1
  echo "=== $(date) - lan nay dung/timeout, thu lai sau 5s ===" >> $LOG
  sleep 5
done