import subprocess
import requests
import os

LOG_FILE = "/opt/zeek/logs/current/notice.log"

# Khuyến nghị: đặt token bằng environment variable
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


def send_telegram(message):
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram credentials are not set")
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    try:
        r = requests.post(
            url,
            data={
                "chat_id": CHAT_ID,
                "text": message
            },
            timeout=5
        )

        print(f"Sent: {r.status_code} {r.text[:100]}")

    except Exception as e:
        print(f"Telegram send failed: {e}")


print("Zeek Telegram alert bot started")
print(f"Watching: {LOG_FILE}")


process = subprocess.Popen(
    ["tail", "-n", "0", "-F", LOG_FILE],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)


for line in process.stdout:

    line = line.rstrip("\n")

    if not line:
        continue

    # Bỏ qua comment/header của Zeek
    if line.startswith("#"):
        continue

    fields = line.split("\t")

    # notice.log phải có ít nhất các field cơ bản
    if len(fields) < 2:
        continue

    # Tìm CustomDetect ở bất kỳ field nào
    if "CustomDetect" not in line:
        continue

    print(f"NEW ZEEK ALERT: {line}")

    # Nếu muốn gửi nguyên dòng log
    send_telegram(
        f"🚨 ZEEK ALERT\n\n{line}"
    )