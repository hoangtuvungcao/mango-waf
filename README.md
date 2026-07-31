# 🥭 MANGO WAF v2.0 — Enterprise High-Performance Web Application Firewall & DDoS Shield

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![HTTP/3](https://img.shields.io/badge/HTTP%2F3-QUIC-7B1FA2?style=flat-square)](https://quic-go.net)
[![Kernel eBPF](https://img.shields.io/badge/Kernel-eBPF%2FXDP-FF6F00?style=flat-square)](https://ebpf.io)
[![Cluster Mesh](https://img.shields.io/badge/Mesh-P2P%20Sync-0288D1?style=flat-square)](https://github.com/hashicorp/memberlist)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

**Mango WAF v2.0** là hệ thống Tường lửa Ứng dụng Web (WAF) và Lá chắn chống tấn công DDoS cấp doanh nghiệp (Enterprise-grade) được phát triển 100% bằng ngôn ngữ **Go**, hỗ trợ giao thức tân tiến **HTTP/3 (QUIC)**, màng lọc kernel **eBPF/XDP**, đồng bộ P2P Mesh giữa các VPS và cơ chế **Hot-Reload cấu hình thời gian thực**.

---

## 🔥 THÀNH TỰU VÀ CẢI TIẾN NỔI BẬT (v2.0 ENTERPRISE)

- ⚡ **HTTP/3 (QUIC over UDP 443)**: Tích hợp hoàn chỉnh HTTP/3 song song với TCP HTTPS 443, tự động chèn header `Alt-Svc: h3=":443"; ma=86400` giúp tăng tốc độ tải trang lên **3x** và miễn nhiễm với TCP SYN Flood.
- 🛡️ **Kernel-Level eBPF/XDP Filtering**: Lọc và hủy (DROP) các gói tin DDoS cực mạnh ngay tại tầng Network Interface (NIC) trước khi đi vào bộ nhớ Socket Kernel.
- 🔄 **Real-Time Hot-Reloading**: Cập nhật cấu hình bảo mật, danh sách domain, mức WAF Paranoia, Rate Limit RPS/Burst và độ khó PoW trực tiếp trong bộ nhớ RAM mà không cần restart service.
- 🌐 **P2P Mesh Cluster Synchronization**: Các VPS tự động kết nối cụm bằng HashiCorp Memberlist, chia sẻ danh sách IP bị khóa (Ban IP) thời gian thực với độ trễ <10ms.
- 🚀 **Zero-Allocation Pipeline**: Tối ưu hóa bộ nhớ RAM ở mức cực hạn (`0 B/op, 0 allocs/op` ở luồng Inspect WAF Clean), chống sụt giảm CPU/RAM dưới thảm họa tấn công DDoS.
- 🧩 **JS Proof-of-Work & Captcha**: Thử thách PoW tự động thích ứng (<30ms cho trình duyệt thực) cùng giao diện Hold-to-Verify hiện đại chống Botnet dồn dập.

---

## 🏗️ THIẾT KẾ KIẾN TRÚC HỆ THỐNG

```mermaid
graph TD
    Client[Internet / Attackers / Legitimate Users] -->|UDP 443 HTTP/3 & TCP 443/80| XDP[Kernel eBPF/XDP Fast Drop]
    XDP -->|Passed Packets| WAF[Mango Shield Engine]
    
    subgraph Mango Shield Engine
        RateLimit[Token Bucket Rate Limiter]
        RulesEngine[OWASP CRS WAF Inspection]
        ChallengeMgr[JS PoW & Turnstile Captcha]
        IntelEngine[GeoIP & Datacenter ASN Filter]
    end
    
    WAF -->|Verified Pass| Proxy[Reverse Proxy & Connection Pool]
    Proxy -->|Clean Requests| Upstream[Backend Web Servers]
    
    WAF <-->|P2P Mesh State Sync| PeerNode[Cluster Mesh Peers]
```

---

## ⚡ KHỞI CHẠY NHANH BẰNG DOCKER COMPOSE

### 1. Tải Mã Nguồn & Cấu Hình
```bash
git clone https://github.com/hoangtuvungcao/mango-waf.git
cd mango-waf
```

### 2. Khởi Chạy Container
```bash
docker compose up -d --build
```

### 3. Kiểm Tra Trạng Thái
```bash
curl -s http://localhost:9090/api/health
```

---

## 📖 TÀI LIỆU HƯỚNG DẪN CHI TIẾT

Vui lòng xem tài liệu thiết lập nâng cao tại **[docs/SETUP.md](docs/SETUP.md)**:
- Cấu hình VPS 8 CPU / 8GB RAM tối ưu nhất.
- Hướng dẫn gán Kernel eBPF/XDP vào Card mạng.
- Thiết lập cụm Mesh Multi-Node (Cluster).
- Hướng dẫn sử dụng Dashboard UI & REST API.

---

## 📄 LICENSE

Dự án được phát hành theo giấy phép [MIT License](LICENSE).
