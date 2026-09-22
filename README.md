# Xây dựng hệ thống phát hiện xâm nhập mạng (IDS) ứng dụng Machine Learning

Đồ án tốt nghiệp — Trường Đại học Giao thông vận tải TP.HCM (UTH)

**Sinh viên:** Lê Hoàng Phúc — MSSV: 054205009202 — Lớp: CN2302A

---

## 1. Giới thiệu

Đồ án xây dựng một hệ thống **phát hiện xâm nhập mạng (IDS)** trong mô hình mạng doanh nghiệp mô phỏng, kết hợp:

- **Rule-based detection** bằng Zeek (script tùy chỉnh) để phát hiện tấn công theo thời gian thực.
- **Machine Learning** (Random Forest, XGBoost) huấn luyện trên bộ dữ liệu CICIDS2017 để phân loại lưu lượng bình thường/tấn công.
- **Cảnh báo tự động** qua Telegram Bot khi phát hiện hành vi bất thường.

Hệ thống được triển khai trong mô hình mạng doanh nghiệp giả lập trên EVE-NG, gồm firewall, router, các switch/site nội bộ, với Zeek đặt tại điểm "chokepoint" (giữa Firewall và Router) để giám sát toàn bộ lưu lượng North-South.

## 2. Mô hình mạng (Topology)

```
Kali (Attacker) → FW1 (Cisco ASA) → Zeek (IDS, inline bridge) → vIOS (Router)
                                                                      ├── Site A: Switch A → Linux, May1_B
                                                                      ├── Site B: Switch B → May2_b
                                                                      └── Net Cloud (external)
```

- **FW1 (ASA):** kiểm soát truy cập, NAT/PAT giữa Attacker và mạng nội bộ.
- **Zeek (Ubuntu, v8.0.5):** đặt inline tại chokepoint bằng bridge 2 NIC (br0), có thêm NIC thứ 3 riêng cho quản trị.
- **vIOS Router:** định tuyến giữa Site A và Site B.
- **Site A / Site B:** mô phỏng các phòng ban/site trong mạng doanh nghiệp.

## 3. Kịch bản tấn công được kiểm thử

| Tấn công | Công cụ | Cổng/Đối tượng | Phát hiện bởi |
|---|---|---|---|
| Port Scan | Nmap | Toàn dải cổng | `custom-detect.zeek` (Port_Scan) |
| SSH Brute-force | Hydra | Cổng 22 | `custom-detect.zeek` (SSH_Bruteforce) |
| SYN Flood | hping3 | Cổng 80 | `custom-detect.zeek` (SYN_Flood) |

Tất cả cảnh báo được ghi vào `notice.log` và gửi realtime qua Telegram Bot (`IDS_bot`).

## 4. Machine Learning

- **Dataset:** CICIDS2017 (~2.52 triệu dòng), 7 lớp: Normal, DoS, DDoS, Port Scanning, Brute Force, Bots, Web Attacks.
- **Mô hình gốc (52 features):**
  - Binary classification — XGBoost: Accuracy 99.91%, F1 0.9975
  - Multi-class — Random Forest: Accuracy 1.00, F1-macro 0.96
- **Mô hình rút gọn (8 features tương thích với Zeek conn.log thực tế):** Destination Port, Flow Duration, Total Fwd Packets, Total Length of Fwd Packets, Flow Bytes/s, Flow Packets/s, Fwd Packets/s, Bwd Packets/s
  - Random Forest: Accuracy 0.9911, F1-macro 0.8187, F1-weighted 0.9934
  - Hạn chế: các lớp Bots và Web Attacks có F1 thấp do đặc trưng theo-luồng (per-flow) không đủ mô tả các mẫu tấn công đa luồng (multi-flow), đặc biệt là port scan — đây là lý do dự án dùng kiến trúc **hybrid**: Zeek rule-based cho scan/flood, ML cho các tấn công giàu nội dung luồng.

> **Lưu ý:** 2 file dung lượng lớn vượt giới hạn 100MB của GitHub (`cicids2017_reduced.csv`, `rf_zeek_multiclass_ids.pkl`) không được đẩy lên repo — xem mục 7.

## 5. Cấu trúc thư mục dự án

```
ids-zeek-thesis/
├── README.md
├── .gitignore
│
├── eve-ng-topology/              # Cấu hình topology EVE-NG
│   ├── topology-diagram.png      # Sơ đồ mạng
│   ├── asa-fw1-config.txt        # Cấu hình ASA (NAT, ACL, route)
│   └── vios-router-config.txt    # Cấu hình router (interface, routing)
│
├── zeek-scripts/                 # Script phát hiện của Zeek
│   ├── custom-detect.zeek        # Rule-based detection (Port Scan, SYN Flood, SSH Brute-force)
│   └── sample-logs/              # Mẫu conn.log, notice.log minh họa
│       ├── nmap_clean.log
│       └── notice_sample.log
│
├── telegram-alert/                # Pipeline cảnh báo Telegram
│   └── telegram_alert2.py        # tail -F notice.log -> Telegram Bot (có cooldown chống spam)
│
├── ml-model/                      # Machine Learning
│   ├── notebooks/
│   │   ├── train_original_52features.ipynb
│   │   └── train_reduced_8features.ipynb
│   ├── models/
│   │   ├── xgb_multiclass_ids.pkl          # Mô hình gốc 52 features
│   │   ├── rf_multiclass_ids.pkl
│   │   ├── label_encoder_ids.pkl
│   │   ├── xgb_zeek_multiclass_ids.pkl     # Mô hình rút gọn 8 features
│   │   ├── label_encoder_zeek_multiclass.pkl
│   │   └── feature_columns_zeek_multiclass.pkl
│   │   # (rf_zeek_multiclass_ids.pkl >100MB - xem link Google Drive ở README này)
│   ├── extract_conn_featrues.py   # Trích đặc trưng từ conn.log thật của Zeek
│   ├── predict.py                 # Demo dự đoán trên dữ liệu Zeek thật
│   ├── retrain_reduced_model.py
│   ├── eval_saved_model.py
│   └── check_features.py
│
├── datasets/
│   └── README.md                  # Ghi chú + link tải cicids2017_reduced.csv (không đưa file lên Git)
│
├── scripts/
│   ├── auto_download.sh
│   └── auto_download2.sh
│
└── docs/
    ├── SRS_IDS_LeHoangPhuc.docx    # Software Requirements Specification
    ├── BaoCao_DoAnTotNghiep.docx   # Báo cáo đồ án đầy đủ (5 chương)
    └── screenshots/                # Ảnh chụp topology, tấn công, cảnh báo Telegram, kết quả ML
```

## 6. Hướng dẫn cài đặt & chạy

### 6.1. Zeek (trên VM Zeek trong EVE-NG)
```bash
# Cài Zeek 8.0.5 (repo openSUSE)
# Copy script phát hiện vào site policy
cp zeek-scripts/custom-detect.zeek /opt/zeek/share/zeek/site/
zeekctl deploy
```

### 6.2. Cảnh báo Telegram
```bash
cd telegram-alert
python3 telegram_alert2.py
```

### 6.3. Machine Learning — trích đặc trưng & dự đoán
```bash
cd ml-model
python3 extract_conn_featrues.py --input /opt/zeek/spool/zeek/conn.log --output features.csv
python3 predict.py --input features.csv
```

## 7. Dataset & mô hình dung lượng lớn

Do giới hạn 100MB của GitHub, các file sau **không** có trong repo, cần tải riêng:

| File | Dung lượng | Link |
|---|---|---|
| `cicids2017_reduced.csv` | ~192MB | *(thêm link Google Drive)* |
| `rf_zeek_multiclass_ids.pkl` | ~123MB | *(thêm link Google Drive)* |

## 8. Giới hạn & hướng phát triển

- Mô hình ML được huấn luyện offline trên CICIDS2017, chưa tích hợp realtime hoàn toàn vào pipeline Zeek.
- Sử dụng Telegram thay cho Zabbix để cảnh báo do giới hạn thời gian/tài nguyên lab (Zabbix có thể tích hợp ở giai đoạn sau qua `zabbix_sender`).
- Topology là mô hình mạng doanh nghiệp thu nhỏ trong môi trường lab, không phải mạng doanh nghiệp thật.
- Hướng phát triển: tích hợp ML realtime vào Zeek, mở rộng phát hiện East-West traffic, demo Zabbix.

## 9. Công nghệ sử dụng

`EVE-NG` · `Cisco IOS / ASAv` · `Kali Linux` · `Zeek 8.0.5` · `Python (scikit-learn, XGBoost)` · `Telegram Bot API`

## 10. Liên hệ

**Lê Hoàng Phúc**
Email: lehoanghphuc@gmail.com
