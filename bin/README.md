# 🥭 Hướng Dẫn Cài Đặt & Chạy Trực Tiếp (Binary)

Thư mục này chứa đầy đủ tất cả các thành phần để bạn chạy Mango Shield WAF trực tiếp trên máy chủ Linux mà không cần dùng Docker. Chạy trực tiếp sẽ cho hiệu năng tối đa và tích hợp XDP eBPF tốt nhất.

## 📁 Cấu trúc thư mục

- `mango-shield`: File chạy chính (Binary đã được build sẵn cho Linux).
- `config/config.yaml`: File cấu hình lõi của WAF.
- `xdp/`: Chứa mã nguồn C của XDP để gắn vào card mạng (Sẽ được tự động biên dịch).
- `mango-shield.service`: File cấu hình để cài đặt WAF chạy ngầm như một Service (Systemd).
- `scripts/optimize_tcp.sh`: (Nếu có) Kịch bản tối ưu hóa TCP/Kernel Linux chống DDoS.

---

## 🚀 Hướng Dẫn Cài Đặt (Khuyên dùng)

Cách tốt nhất để chạy WAF là thiết lập nó thành một **Systemd Service** để nó tự động chạy khi máy chủ khởi động lại.

### Bước 1: Chuẩn bị thư mục chuẩn
Sao chép toàn bộ nội dung thư mục này vào thư mục `/opt/mango-waf/`:
```bash
sudo mkdir -p /opt/mango-waf
sudo cp -r * /opt/mango-waf/
cd /opt/mango-waf
```

### Bước 2: Cấp quyền thực thi
```bash
sudo chmod +x mango-shield
```

### Bước 3: Kiểm tra cú pháp cấu hình (Tính năng mới)
WAF đã được bổ sung cờ `-test` để giúp bạn kiểm tra file cấu hình trước khi chạy:
```bash
sudo ./mango-shield -config config/config.yaml -test
```
*(Nếu nó báo "Syntax OK", bạn có thể tự tin chạy tiếp)*

### Bước 4: Cài đặt Systemd Service
Copy file service vào hệ thống Linux của bạn:
```bash
sudo cp mango-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### Bước 5: Khởi động và Kích hoạt WAF
```bash
# Cho phép WAF khởi động cùng hệ thống
sudo systemctl enable mango-shield

# Bật WAF ngay lập tức
sudo systemctl start mango-shield

# Xem trạng thái hoạt động
sudo systemctl status mango-shield
```

---

## 📜 Xem Log và Kiểm soát

Vì WAF đã chạy ngầm trong Systemd, bạn có thể xem log theo thời gian thực (Realtime) bằng lệnh sau:
```bash
sudo journalctl -u mango-shield -f
```

Để dừng WAF:
```bash
sudo systemctl stop mango-shield
```

## ⚙️ Cấu hình

Bạn chỉ cần chỉnh sửa duy nhất file `config/config.yaml`.
Sau khi chỉnh sửa xong, hãy chạy:
```bash
sudo systemctl restart mango-shield
```
WAF sẽ tự động nạp cấu hình mới.

## 🛠 Yêu cầu hệ thống

Để XDP/eBPF hoạt động hoàn hảo, máy chủ cần:
- Hệ điều hành Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+).
- Cài đặt sẵn trình biên dịch C: `sudo apt install clang llvm libbpf-dev gcc make` (Ubuntu/Debian) hoặc `dnf install clang llvm libbpf-devel gcc make` (CentOS/AlmaLinux).

Chúc bạn an tâm tận hưởng hệ thống bảo mật L7 siêu việt này! 🥭🛡️
