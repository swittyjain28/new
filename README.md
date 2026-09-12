# GeoTraceIntel: Email Origin Traceability & Geolocation Map

> **Cybersecurity Threat Intelligence platform for email origin attribution, anonymization detection (TOR, VPN, Hosting), and interactive Leaflet.js relay path mapping.**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![Leaflet.js](https://img.shields.io/badge/Leaflet.js-1.9.4-199900?style=flat&logo=leaflet&logoColor=white)
![Security Hardened](https://img.shields.io/badge/Security-Hardened-blueviolet)

---

## 🎯 Features

- **Feature 3.2: Origin Traceability & Anonymization Intelligence**:
  - Reverse bottom-up relay chain parsing from sender to final receiver MTA.
  - RFC 1918 private IP detection (`10.x`, `192.168.x`, `172.16-31.x`, `127.0.0.1`).
  - Trusted corporate perimeter MTA filtering to isolate true entry IP.
  - Anonymization flags: **TOR Exit Nodes**, **Commercial VPNs/Proxies**, and **Cloud/Hosting ASNs** (AWS, DigitalOcean, Hetzner, etc.).
  - Attribution Confidence scoring (0% - 100%).

- **Feature 3.5: Geolocation Trace Map**:
  - Interactive **Leaflet.js** map powered by clean, high-resolution **Esri Dark Gray Canvas** tiles (no API keys or watermarks required).
  - Multi-hop relay path visualization with directional polylines.
  - Coordinated Threat Campaign cluster overlays.
  - Floating Quick-Hop Navigator bar.

- **Dual-Stage User Experience**:
  - **Stage 1 (Rough Info Overview)**: High-level intelligence cards, threat flags, and full **Ordered Relay Hops Matrix** with explicit **Latitude** and **Longitude** coordinates.
  - **Stage 2 (Click to See Map Location)**: Click "See Map Location" on any hop row to fly smoothly to that geographic coordinate and open the inspector popup.

- **Real-Time WebSocket Stream**:
  - Live bi-directional updates over `/ws` with zero page reloads on new trace submissions.

- **Enterprise Security Hardening**:
  - In-memory DoS protection with bounded FIFO/LRU eviction (`MAX_STORED_EMAILS = 100`).
  - Rate limiting (max 30 submissions per minute per client IP) returning `HTTP 429`.
  - ReDoS-immune precompiled regular expressions with input length guards.
  - Strict Pydantic input schemas (max string lengths & max 50 hops).
  - Strict `ipaddress.ip_address` validation guarding against SSRF.
  - Production HTTP security headers: `Content-Security-Policy (CSP)`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
  - Frontend XSS sanitization across all dynamic HTML templates.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- `pip install fastapi uvicorn pydantic`

### 2. Run the Server
```bash
python main.py
```
Or with uvicorn:
```bash
uvicorn main:app --reload --port 8000
```

### 3. Open Dashboard
Visit `http://127.0.0.1:8000/` in your browser.

---

## 🧪 Running Automated Tests

```bash
# Core Origin Traceability Tests
python -m unittest test_geo_intel.py

# Security Vulnerability & Hardening Tests
python -m unittest test_security.py
```

---

## 📡 REST & WebSocket API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web Dashboard UI |
| `GET` | `/emails` | List all processed email traces with origin coords & threat flags |
| `GET` | `/emails/{email_id}/trace` | Detailed hop-by-hop coordinates, origin trace, and campaign clusters |
| `POST` | `/emails/analyze` | Analyze raw relay chain (Rate-limited, max 30 req/min) |
| `WS` | `/ws` | Real-time WebSocket event stream (`email_trace` events) |

---

## 📂 Project Structure

```
email-geo-trace/
├── main.py              # FastAPI server, endpoints, rate limiter & WebSocket manager
├── geo_intel.py         # Origin resolution algorithm, IP geolocator & anonymization detector
├── config.py            # Known TOR nodes, hosting ASNs, VPN providers & trusted MTAs
├── test_geo_intel.py    # Unit tests for Feature 3.2 origin resolution
├── test_security.py     # Automated security verification test suite
├── .gitignore           # Git ignore rules
├── README.md            # Documentation
└── static/              # Frontend assets
    ├── index.html       # Single-page SOC intelligence dashboard
    ├── style.css        # Cyberpunk / SOC dark theme styles
    └── app.js           # Leaflet.js controller, dual-mode views & WebSocket client
```
