# 🛠️ HƯỚNG DẪN THIẾT LẬP VÀ VẬN HÀNH MANGO WAF v2.0 (ENTERPRISE SETUP GUIDE)

Tài liệu này hướng dẫn chi tiết từ A-Z cách triển khai, tối ưu hóa hệ điều hành và cấu hình cụm máy chủ chống DDoS cho **Mango WAF v2.0**.

---

## 📋 1. YÊU CẦU HỆ THỐNG (SYSTEM REQUIREMENTS)

- **Hệ điều hành**: Linux (Ubuntu 22.04 LTS / 24.04 LTS, Debian 12, Rocky Linux 9).
- **Phần cứng khuyến nghị (Per Node)**:
  - **CPU**: 4 - 8 Cores.
  - **RAM**: 4GB - 8GB.
  - **Network Interface**: 1 Gbps / 10 Gbps NIC.
- **Phần mềm bắt buộc**:
  - Docker & Docker Compose Plugin.
  - Go 1.24+ (nếu biên dịch thủ công).
  - `clang`, `llvm`, `libbpf-dev` (để biên dịch eBPF/XDP).

---

## ⚙️ 2. TỐI ƯU HÓA HỆ ĐIỀU HÀNH LINUX KERNEL (OS TUNING)

Để hệ thống chịu được lưu lượng tấn công lớn mà không bị nghẽn Socket hoặc chạm giới hạn File Descriptor của OS:

Khởi chạy script tự động tối ưu rlimit và sysctl:
```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

Hệ thống **Mango WAF** sẽ tự động gọi `syscall.Setrlimit(RLIMIT_NOFILE, 100000)` khi khởi chạy để mở tối đa **100.000 Socket đồng thời**.

---

## 🚀 3. QUY TRÌNH TRIỂN KHAI DOCKER (PRODUCTION DEPLOYMENT)

### Bước 1: Chuẩn bị file cấu hình
Hệ thống đi kèm 2 file cấu hình chuẩn Production:
- `config/production.yaml`: Cấu hình tổng thể cho mô hình có Cloudflare hoặc Proxy trung gian.
- `config/production-nocf.yaml`: Cấu hình tối ưu cao nhất cho mô hình Direct-IP (Chạy trực tiếp trên VPS).

### Bước 2: Chạy Docker Compose
```bash
cd /root/mango-waf
docker compose up -d --build
```

### Bước 3: Kiểm tra Container & Port Mapping
```bash
docker ps
```
Đảm bảo container `mango-shield` đang lắng nghe các cổng:
- `80/tcp`: HTTP Server & Redirect.
- `443/tcp`: HTTPS SSL/TLS.
- `443/udp`: **HTTP/3 (QUIC over UDP)**.
- `9090/tcp`: Dashboard UI & Monitoring API.
- `7946/tcp+udp`: Cluster Mesh P2P Synchronization.

---

## 🛡️ 4. KÍCH HOẠT MÀNG LỌC KERNEL eBPF/XDP (OPTIONAL FOR DIRECT IP)

Nếu máy chủ chịu đợt tấn công SYN/UDP Flood nặng, kích hoạt XDP để lọc gói tin trực tiếp từ Card mạng:

```bash
cd /root/mango-waf/xdp
chmod +x setup_xdp.sh
sudo ./setup_xdp.sh
```

Để gỡ bỏ XDP filter:
```bash
sudo ip link set dev <NIC_NAME> xdp off
```

---

## 🌐 5. CẤU HÌNH CỤM NHAU ĐỒNG BỘ P2P MESH (MULTI-NODE CLUSTER)

Trên từng VPS trong cụm, cập nhật phần `cluster` trong file `config/production.yaml`:

```yaml
cluster:
  enabled: true
  node_name: "node-01" # Đặt duy nhất cho từng VPS (VD: node-01, node-02)
  advertise_ip: "103.77.246.167" # IP công cộng của VPS hiện tại
  bind_port: 7946
  join_peers:
    - "103.77.246.167:7946"
    - "103.77.246.107:7946"
  secret_key: "MANGO_MESH_SECRET_2026"
```

Khi có IP bị khóa ở Node 1, Node 1 sẽ tự động phát gói tin UDP Gossip sang Node 2 để khóa ngay lập tức!

---

## 🔄 6. HOT-RELOAD CẤU HÌNH KHÔNG CẦN RESTART (ZERO DOWNTIME)

Bất kỳ lúc nào bạn thay đổi cấu hình qua Dashboard UI hoặc chỉnh trực tiếp file `production.yaml`, có thể gửi tín hiệu SIGHUP để nạp lại cấu hình vào RAM:

```bash
docker kill -s HUP mango-shield
```

Nhật ký sẽ báo:
`{"msg":"SIGHUP received — hot reload config"}`
`{"msg":"Config reloaded successfully"}`
