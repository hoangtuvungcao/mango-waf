# Hướng Dẫn Cài Đặt & Cấu Hình Mango Shield Enterprise

Tài liệu này hướng dẫn chi tiết cách cài đặt, cấu hình, biên dịch, và thiết lập WAF cùng hệ thống bảo vệ eBPF/XDP chống DDoS.

---

## 1. Sử Dụng Bản Build Sẵn (Pre-built Binary)

Nếu bạn không muốn tự biên dịch, bạn có thể tải bản build sẵn (binary) về và chạy trực tiếp.

```bash
# 1. Tải bản binary mới nhất
wget https://github.com/hoangtuvungcao/mango-waf/releases/latest/download/mango-shield-linux-amd64.tar.gz

# 2. Giải nén
tar -xzvf mango-shield-linux-amd64.tar.gz

# 3. Cấp quyền thực thi
chmod +x mango-shield

# 4. Chạy WAF
sudo ./mango-shield
```

---

## 2. Hướng Dẫn Build Từ Mã Nguồn (Build Binary)

Nếu bạn muốn tự biên dịch (build) từ mã nguồn gốc:

### Yêu cầu hệ thống:
- Go 1.24.0+ 
- Clang/LLVM (để build eBPF)
- Linux Kernel 5.8+ (để hỗ trợ tính năng eBPF XDP)

```bash
# 1. Cài đặt các gói phụ thuộc (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential clang llvm gcc-multilib libbpf-dev linux-tools-common linux-tools-generic linux-headers-$(uname -r)

# 2. Đồng bộ các thư viện và module của Golang
go mod tidy
go mod download

# 3. Biên dịch eBPF/XDP (Rất quan trọng để kích hoạt chặn DDoS ở tầng card mạng)
go generate ./...

# 4. Biên dịch mã nguồn Go ra Binary (Tối ưu hóa dung lượng & tốc độ)
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o mango-shield main.go

# 5. Cấp quyền và chạy thử
chmod +x mango-shield
sudo ./mango-shield
```

---

## 3. Thiết Lập Hệ Thống Mạng Để Tối Ưu (Tùy Chọn Nhưng Khuyến Nghị)

Để chịu tải DDoS lớn, bạn cần nới lỏng giới hạn hệ điều hành:

```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.core.netdev_max_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -p
```

---

## 4. Kiểm Tra Tấn Công & Xem Log

Hệ thống sẽ tự động học hỏi và chuyển trạng thái chống DDoS.
- Dưới 1000 RPS: Chế độ kiểm tra JS/Captcha thông thường
- Trên 5000 RPS: Chế độ XDP / eBPF được tự động kích hoạt, chặn Drop thẳng gói tin tại Card mạng.

### Tại sao không có thông báo "Thống kê sau DDoS"?
WAF được thiết kế để kết luận một cuộc tấn công kết thúc khi có **10 giây liên tục** không còn request độc hại nào tới Server (RPS tụt xuống mức bình thường).
- Nếu bạn test DDoS và bấm `Ctrl+C` để tắt WAF **ngay lập tức** lúc đang bị DDoS hoặc vừa dừng Tool, hệ thống sẽ bị tắt ngang và **KHÔNG** kịp gửi thông báo Thống Kê.
- **Giải pháp:** Sau khi tắt tool tấn công, hãy **chờ 10-15 giây** để WAF xác nhận cuộc tấn công hoàn toàn kết thúc. Khi đó, WAF sẽ bắn log thông báo "✅ Tấn công đã kết thúc" kèm thống kê số lượng Requests đã chặn về Discord/Telegram của bạn.
*(Phiên bản mới nhất đã khắc phục: Ngay cả khi bạn ấn `Ctrl+C` tắt ngang Server, WAF cũng sẽ tự động xử lý và bắn thông báo thống kê lên Discord trước khi tắt).*

---

## 5. Chạy WAF Ở Chế Độ Nền (Background / Systemd)

Tạo file Service:
```bash
sudo nano /etc/systemd/system/mango-waf.service
```

Thêm nội dung:
```ini
[Unit]
Description=Mango Shield Enterprise WAF
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mango-waf
ExecStart=/opt/mango-waf/mango-shield
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Kích hoạt và chạy:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mango-waf
sudo systemctl start mango-waf
sudo systemctl status mango-waf
```
