# API Reference - Mango Shield Dashboard REST API

The Mango Shield Admin Dashboard exposes RESTful API endpoints for monitoring, metrics collection, and cache management.

---

## Authentication

Admin operations (`/api/config`, `/api/cache/purge`) require authentication:
- **Session Authentication**: `POST /api/login` sets `mango_admin_session` cookie.
- **HTTP BasicAuth**: Using `dashboard.username` and `dashboard.password`.

---

## Endpoints

### 1. `POST /api/login`
Authenticates administrator credentials and returns session token.

**Request Payload**:
```json
{
  "username": "admin",
  "password": "admin123_change_in_production"
}
```

**Response `200 OK`**:
```json
{
  "status": "ok",
  "token": "mango-session-1785025478000",
  "user": "admin",
  "message": "Admin login successful"
}
```

---

### 2. `GET /api/stats`
Returns real-time traffic statistics.

**Response `200 OK`**:
```json
{
  "total_requests": 15420,
  "blocked_requests": 342,
  "passed_requests": 14989,
  "active_conns": 14,
  "current_rps": 230,
  "peak_rps": 1250,
  "active_bans": 12,
  "is_under_attack": false,
  "uptime_seconds": 86400,
  "xdp_enabled": true,
  "xdp_banned_ips": 12,
  "xdp_dropped_pkts": 450123
}
```

---

### 3. `GET /api/system-stats`
Returns OS system resource usage (CPU, RAM, Disk, Load, Network).

**Response `200 OK`**:
```json
{
  "cpu_percent": 2.4,
  "ram_total_mb": 7948,
  "ram_used_mb": 1594,
  "disk_total_gb": 98.3,
  "disk_used_gb": 22.1,
  "load_1m": 1.25,
  "tcp_connections": 16,
  "goroutines": 38,
  "num_cpu": 8
}
```

---

### 4. `GET /api/rps-history`
Returns request per second history data points (last 300 seconds).

**Response `200 OK`**:
```json
{
  "rps": [120, 145, 130, 210, 195, 180]
}
```

---

### 5. `POST /api/cache/purge`
Purges in-memory CDN cache items (Requires Admin Auth).

**Response `200 OK`**:
```json
{
  "status": "purged",
  "success": true
}
```

---

### 6. `GET /api/health`
Health check endpoint (Public access).

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "version": "2.0.0"
}
```
