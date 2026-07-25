# API Reference - Mango Shield Dashboard REST API

The Mango Shield Admin Dashboard exposes RESTful API endpoints for monitoring, metrics collection, and cache management.

---

## Authentication

All API endpoints (except `/api/health`) require HTTP Basic Authentication using credentials configured in `dashboard.username` and `dashboard.password`.

---

## Endpoints

### 1. `GET /api/stats`
Returns real-time traffic statistics.

**Response `200 OK`**:
```json
{
  "total_requests": 15420,
  "blocked_requests": 342,
  "challenged_requests": 89,
  "passed_requests": 14989,
  "active_connections": 14,
  "current_rps": 230,
  "peak_rps": 1250,
  "banned_ips": 12,
  "whitelisted_ips": 3,
  "is_under_attack": false,
  "uptime_seconds": 86400,
  "xdp_enabled": true,
  "xdp_banned": 12,
  "xdp_drops": 450123
}
```

---

### 2. `GET /api/rps/history`
Returns request per second history data points (last 60 seconds).

**Response `200 OK`**:
```json
{
  "rps": [120, 145, 130, 210, 195, 180]
}
```

---

### 3. `POST /api/cache/purge`
Purges in-memory CDN cache items.

**Query Parameters**:
- `key` (optional): Specific cache key to purge. If omitted, clears all cache items.

**Response `200 OK`**:
```json
{
  "status": "success",
  "message": "Cache purged successfully"
}
```

---

### 4. `GET /api/health`
Health check endpoint (no authentication required).

**Response `200 OK`**:
```json
{
  "status": "ok",
  "version": "2.0.0"
}
```
