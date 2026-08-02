# Hướng Dẫn Cài Đặt & Cấu Hình Mango Shield Enterprise v3.0

Tài liệu này hướng dẫn chi tiết cách cài đặt, cấu hình, biên dịch, và thiết lập WAF cùng hệ thống bảo vệ eBPF/XDP chống DDoS.

---

## 1. Sử Dụng Bản Build Sẵn (Pre-built Binary - Khuyên Dùng)

Đây là cách cài đặt nhanh nhất để chạy WAF mà không cần biên dịch hay cài đặt môi trường Go. Bản build sẵn này được đóng gói tối giản nhất để triển khai lên máy chủ Production.

###  Thành phần bên trong file nén (Release Archive):
Khi giải nén file `mango-shield-linux-amd64.tar.gz` (hoặc copy từ thư mục `bin/`), bạn sẽ nhận được các file sau:
- **`mango-shield`**: File thực thi (Binary) chính của WAF. Đã được biên dịch tĩnh, tốc độ siêu nhanh.
- **`config/config.yaml`**: File cấu hình lõi. Nơi bạn điền danh sách IP/Domain và các thông số giới hạn.
- **`xdp/mango_xdp.c`**: Mã nguồn hạt nhân C. WAF sẽ tự động đọc file này, biên dịch và nhúng xuống Card mạng để chặn DDoS ở tầng thấp nhất.
- **`scripts/optimize_tcp.sh`**: Kịch bản tối ưu hóa TCP/Kernel Linux (chống SYN Flood, mở rộng băng thông).
- **`mango-shield.service`**: File Systemd Service mẫu để cài WAF chạy ngầm tự động cùng hệ thống.
- **`README.md`**: Hướng dẫn cài đặt nhanh rút gọn.

---

###  Hướng Dẫn Cài Đặt Từng Bước

```bash
# 1. Tải bản binary mới nhất (hoặc copy từ thư mục bin/ sang)
wget https://github.com/hoangtuvungcao/mango-waf/releases/latest/download/mango-shield-linux-amd64.tar.gz

# 2. Giải nén vào thư mục chuẩn
sudo mkdir -p /opt/mango-waf
sudo tar -xzvf mango-shield-linux-amd64.tar.gz -C /opt/mango-waf/
cd /opt/mango-waf

# 3. Cấp quyền thực thi cho file chạy và kịch bản mạng
sudo chmod +x mango-shield
sudo chmod +x scripts/optimize_tcp.sh

# 4. Kiểm tra cấu hình (Lá cờ -test)
# Lệnh này kiểm tra xem config.yaml có bị sai cú pháp (như thiếu dấu space/tab) không.
sudo ./mango-shield -config config/production.yaml -test

# 5. Chạy WAF trực tiếp trên Terminal
sudo ./mango-shield -config config/production.yaml
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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o mango-shield main.go

# 5. Kiểm tra cấu hình trước khi chạy
chmod +x mango-shield
sudo ./mango-shield -config config/production.yaml -test

# 6. Chạy thử
sudo ./mango-shield -config config/production.yaml
```

---

## 3. Thiết Lập Hệ Thống Mạng Để Tối Ưu (Rất Khuyến Nghị)

Để chịu tải DDoS lớn, chống lại hàng triệu kết nối (SYN Flood, Connection Tracking exhaustion), hệ thống đã cung cấp sẵn script tối ưu hóa Kernel TCP. Script `optimize_tcp.sh` sẽ điều chỉnh các tham số mạng `sysctl` ở mức hardcore để WAF có thể xử lý hàng triệu RPS.

```bash
# 1. Cấp quyền thực thi cho script
chmod +x scripts/optimize_tcp.sh

# 2. Chạy script dưới quyền root
sudo ./scripts/optimize_tcp.sh
```

**Những gì script này thực hiện:**
- Tăng giới hạn File Descriptors (`fs.file-max` lên 2,097,152).
- Bật chống SYN Flood (SYN Cookies, giảm retries, tăng SYN backlog).
- Nâng cấp giới hạn theo dõi kết nối (`nf_conntrack_max`).
- Tối ưu hóa việc thu hồi socket nhanh chóng để tránh cạn kiệt ở trạng thái `TIME_WAIT`.
- Mở rộng giới hạn bộ đệm Socket TCP (Buffers).

---

## 4. Kiểm Tra Tấn Công & Xem Log

Hệ thống sẽ tự động học hỏi và chuyển trạng thái chống DDoS.
- Dưới 1000 RPS: Chế độ kiểm tra JS/Captcha thông thường
- Trên 5000 RPS: Chế độ XDP / eBPF được tự động kích hoạt, chặn Drop thẳng gói tin tại Card mạng.

### Tại sao không có thông báo "Thống kê sau DDoS"?
WAF được thiết kế để kết luận một cuộc tấn công kết thúc khi có **10 giây liên tục** không còn request độc hại nào tới Server (RPS tụt xuống mức bình thường).
- Nếu bạn test DDoS và bấm `Ctrl+C` để tắt WAF **ngay lập tức** lúc đang bị DDoS hoặc vừa dừng Tool, hệ thống sẽ bị tắt ngang và **KHÔNG** kịp gửi thông báo Thống Kê.
- **Giải pháp:** Sau khi tắt tool tấn công, hãy **chờ 10-15 giây** để WAF xác nhận cuộc tấn công hoàn toàn kết thúc. Khi đó, WAF sẽ bắn log thông báo " Tấn công đã kết thúc" kèm thống kê số lượng Requests đã chặn về Discord/Telegram của bạn.
*(Phiên bản mới nhất đã khắc phục: Ngay cả khi bạn ấn `Ctrl+C` tắt ngang Server, WAF cũng sẽ tự động xử lý và bắn thông báo thống kê lên Discord trước khi tắt).*

---

## 5. Chạy WAF Ở Chế Độ Nền (Background / Systemd)

Kích hoạt và chạy các tính năng mạnh nhất của Kernel cho eBPF:
```bash
sudo cp bin/mango-shield.service /etc/systemd/system/
```

Nếu bạn muốn tự tạo file Service thì tạo file `sudo nano /etc/systemd/system/mango-waf.service`:
```ini
[Unit]
Description=Mango Shield Enterprise WAF v3.0
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mango-waf
ExecStart=/opt/mango-waf/mango-shield -config /opt/mango-waf/config/production.yaml
Restart=always
RestartSec=5

# Tuning cực mạnh cho 200,000+ Kết Nối (OS Level)
LimitNOFILE=1048576
LimitNPROC=65535

# Cấp quyền tối đa cho eBPF/XDP
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_PERFMON CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_PERFMON CAP_NET_BIND_SERVICE

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
