

# IDS Zeek Thesis

Hệ thống phát hiện xâm nhập (Intrusion Detection System) sử dụng **Zeek** kết hợp cảnh báo qua **Telegram**.

## Mô tả dự án

Dự án này là phần thực nghiệm của khóa luận tốt nghiệp, tập trung vào việc:
- Viết script phát hiện bất thường bằng Zeek
- Gửi cảnh báo real-time qua Telegram Bot

## Cấu trúc thư mục

```
ids-zeek-thesis/
├── zeek-scripts/
│   └── custom-detect.zeek     # Script phát hiện tùy chỉnh của Zeek
├── telegram-alert/
│   └── telegram_alert2.py     # Script gửi cảnh báo qua Telegram
└── README.md
```

## Yêu cầu

- Zeek (trước đây là Bro)
- Python 3
- Telegram Bot Token

## Cách sử dụng

### 1. Zeek Detection Script
```bash
zeek -i <interface> zeek-scripts/custom-detect.zeek
```

### 2. Telegram Alert
```bash
cd telegram-alert
python3 telegram_alert2.py
```

## Tác giả

**Lê Hoàng Phúc**  
Email: lehoanghphuc@gmail.com
```

---

### 2. Lưu file và đẩy lên GitHub

Sau khi dán xong:

- Bấm `Ctrl + O` → Enter (lưu)
- Bấm `Ctrl + X` (thoát)

Rồi chạy các lệnh sau:

```bash
git add README.md
git commit -m "Add README"
git push


---

Chạy xong thì báo mình kết quả nhé.
