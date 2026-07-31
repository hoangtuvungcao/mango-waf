# 🛠️ HƯỚNG DẪN CÀI ĐẶT & VẬN HÀNH MANGO WAF (ENTERPRISE BARE-METAL)

Tài liệu này hướng dẫn chi tiết từ A-Z cách thiết lập hệ thống môi trường, biên dịch mã nguồn thành Binary (File thực thi), cấu hình màng lọc XDP Kernel, thiết lập đồng bộ Mesh giữa các Node, và chạy test với cấu hình đầy đủ.

---

## 🚀 1. LẤY BẢN BUILD SẴN (PRE-BUILT BINARY)
Nếu bạn không muốn tự biên dịch, Mango Shield cung cấp sẵn các file Binary đã được tối ưu hóa cho Linux (AMD64 / ARM64).
*Cách lấy Binary:* Tải file `mango-waf-linux-amd64.tar.gz` mới nhất từ mục **Releases** trên GitHub, sau đó giải nén và cấp quyền thực thi:
```bash
tar -xzf mango-waf-linux-amd64.tar.gz
chmod +x mango-shield
./mango-shield -config=config.yaml
```

---

## 📦 2. CÀI ĐẶT MÔI TRƯỜNG & DEPENDENCIES (MODULE PACKAGES)
Để chạy và biên dịch eBPF/XDP cũng như mã nguồn Go từ đầu, bạn cần cài đặt đầy đủ các gói thư viện và công cụ mạng lõi của hệ điều hành Linux (áp dụng cho Ubuntu/Debian):

```bash
# 1. Cập nhật hệ thống
sudo apt-get update -y

# 2. Cài đặt các gói biên dịch C/C++, eBPF (XDP) và công cụ mạng
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic gcc make build-essential ethtool curl jq

# 3. Cài đặt Go (1.24.0) để biên dịch mã nguồn
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz

# 4. Cấu hình biến môi trường PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Kiểm tra phiên bản Go
go version
```

---

## 🛠️ 3. HƯỚNG DẪN BIÊN DỊCH (BUILD BINARY TỪ MÃ NGUỒN)
Sau khi cài đặt xong Go và các packages, tiến hành Build mã nguồn thành file Binary để chạy độc lập:

```bash
# 1. Clone source code
git clone https://github.com/hoangtuvungcao/mango-waf.git
cd mango-waf

# 2. Tải và đồng bộ các module thư viện của Go
go mod tidy

# 3. Biên dịch mã nguồn (Build) thành file Binary
go build -o mango-shield cmd/cli/main.go

# 4. Kiểm tra file đã build thành công
ls -la mango-shield
```

---

## 🛡️ 4. SETUP eBPF / XDP ĐỂ LỌC DDOS TẠI TẦNG KERNEL
Công nghệ XDP (eXpress Data Path) giúp DROP các gói tin rác trực tiếp ở Card mạng, không cần đẩy vào Kernel TCP/IP Stack, giúp bảo vệ CPU khỏi cạn kiệt.

**Bước 1:** Xác định tên Card mạng của bạn (VD: `eth0`, `ens3`, `eno1`) bằng lệnh:
```bash
ip -br a
```

**Bước 2:** Biên dịch và đính XDP vào Card mạng (Yêu cầu quyền root):
```bash
cd xdp
chmod +x setup_xdp.sh
sudo ./setup_xdp.sh
```
*Script sẽ tự động compile code C (`mango_xdp.c`) sang eBPF bytecode bằng `clang` và mount vào Kernel.*

**Bước 3 (Tùy chọn):** Gỡ bỏ XDP khỏi Card mạng nếu không dùng nữa (thay `eth0` bằng tên Card thật):
```bash
sudo ip link set dev eth0 xdp off
```

---

## 🌐 5. THIẾT LẬP CỤM ĐỒNG BỘ (P2P CLUSTER MESH)
Để các máy chủ (Node) tự động chia sẻ danh sách IP bị cấm (Banned IPs) với nhau theo thời gian thực (độ trễ <10ms), bạn phải cấu hình cụm Mesh.

Mở file cấu hình gốc (ví dụ: `config/production.yaml`) và chỉnh sửa block `cluster`:
```yaml
cluster:
  enabled: true
  node_name: "node-01"           # ĐẶT DUY NHẤT trên từng server (node-01, node-02, ...)
  bind_port: 7946
  advertise_ip: "103.77.246.167" # IP CÔNG CỘNG của VPS hiện tại (để các Node khác nhận diện)
  cname_target: ""               # Để trống
  join_peers:
    - "103.77.246.167:7946"      # Khai báo IP của Node 1
    - "103.77.246.107:7946"      # Khai báo IP của Node 2
  secret_key: "MANGO_MESH_SECRET_2026" # Key bảo mật: Bắt buộc giống nhau trên toàn bộ các Node
```

---

## ▶️ 6. RUN & TEST VỚI CẤU HÌNH ĐẦY ĐỦ (FULL CONFIG)
Cuối cùng, khởi chạy hệ thống bằng Binary vừa build cùng với file cấu hình tổng thể.

**Bước 1: Tối ưu hoá Kernel cho Network Load (Chống kẹt Socket)**
```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

**Bước 2: Cấp quyền và chạy Binary (Bare-metal)**
```bash
# Quay lại thư mục gốc dự án
cd /root/mango-waf

# Cấp quyền cho Binary có thể bind các port thấp (80, 443) mà không cần chạy 'sudo'
sudo setcap 'cap_net_bind_service=+ep' ./mango-shield

# Khởi chạy WAF với cấu hình production (trực tiếp ra stdout)
./mango-shield -config=config/production-nocf.yaml
```

**Bước 3: Test hệ thống toàn diện**
1. **Kiểm tra API Health Check nội bộ** (Mở 1 tab SSH khác):
```bash
curl -s http://localhost:9090/api/health | jq
```
2. **Kiểm tra chịu tải DDoS** (Sử dụng công cụ `hey` hoặc `ab` hoặc máy phụ):
```bash
# Gửi 10.000 requests, 1000 connections đồng thời
hey -n 10000 -c 1000 http://<IP_hoặc_Domain_của_bạn>/
```
3. **Theo dõi giám sát Terminal**:
- Hệ thống sẽ hiển thị log Block/Ban IP.
- Chức năng Mesh sẽ in ra log `[Mesh] Broadcasting ban for IP...` (Node này đẩy lệnh Banned sang Node kia).
- Theo dõi RPS tăng mạnh trên Log nhưng CPU load rất thấp.
