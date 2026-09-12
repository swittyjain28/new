# GeoTraceIntel: Email Origin Traceability & Geolocation Map

> **Cybersecurity Threat Intelligence platform for email origin attribution, anonymization detection (TOR, VPN, Hosting), and interactive Leaflet.js relay path mapping.**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![Leaflet.js](https://img.shields.io/badge/Leaflet.js-1.9.4-199900?style=flat&logo=leaflet&logoColor=white)
![Security Hardened](https://img.shields.io/badge/Security-Hardened-blueviolet)

---

## 🎯 Features & Specifications

### 🔍 Feature 3.2: Origin Traceability & Anonymization Intelligence
- **Function Signature**:
  ```python
  resolve_origin(relay_chain: list[str]) -> OriginTrace
  ```
  *(Also accepts structured `list[dict]` relay hop objects).*
- **Origin Resolution Logic**:
  - Reverse bottom-up relay chain parsing from origin sender to final receiving MTA.
  - RFC 1918 private IP detection (`10.x`, `192.168.x`, `172.16-31.x`, `127.0.0.1`).
  - Trusted corporate perimeter MTA filtering to isolate true entry IP.
  - Anonymization infrastructure detection: **TOR Exit Nodes**, **Commercial VPNs/Proxies**, and **Cloud/Hosting ASNs** (AWS, DigitalOcean, Hetzner, OVH, etc.).
  - Attribution Confidence scoring (`0.0` - `1.0`).

### 🗺️ Feature 3.5: Geolocation Trace Map
- Interactive **Leaflet.js** map powered by clean, high-resolution **Esri Dark Gray Canvas** tiles (100% free, zero API keys or watermarks required).
- Multi-hop relay path visualization with directional polylines.
- Coordinated Threat Campaign cluster overlays.
- Floating Quick-Hop Navigator bar.
- **Real-Time WebSocket Broadcast**:
  - Live bi-directional updates over `/ws` with zero page reloads.
  - All real-time events are broadcast using the explicit specification payload property:
    ```json
    {
      "msg_type": "email_trace",
      "email_id": "EML-89412",
      "subject": "URGENT: Executive Wire Transfer Authorization",
      "sender": "ceo-update@executive-mail.org",
      "origin_trace": { ... },
      "hops": [ ... ]
    }
    ```

### 📋 Dual-Stage User Experience
- **Stage 1 (Rough Info Overview - Loaded First)**: High-level intelligence cards, threat flags, and full **Ordered Relay Hops Matrix** with explicit **Latitude** and **Longitude** coordinates.
- **Stage 2 (Click to See Map Location)**: Click "See Map Location" on any hop row to fly smoothly to that geographic coordinate on the Leaflet map and open the inspector popup.

---

## 📐 Data Schemas

### `OriginTrace` Schema Specification
The explicit Pydantic model definition for origin intelligence resolution:

```python
class OriginTrace(BaseModel):
    ip: str = Field(..., description="Probable originating public IP address")
    country: str = Field("Unknown", description="Country name")
    city: str = Field("Unknown", description="City name")
    isp: str = Field("Unknown", description="Internet Service Provider")
    asn: str = Field("Unknown", description="Autonomous System Number")
    is_vpn: bool = Field(False, description="Flagged as commercial or private VPN")
    is_tor: bool = Field(False, description="Flagged as TOR exit node")
    is_hosting: bool = Field(False, description="Flagged as datacenter / hosting provider")
    confidence: float = Field(..., description="Origin attribution confidence score (0.0 - 1.0)")
    latitude: float = Field(0.0, description="Geographic latitude")
    longitude: float = Field(0.0, description="Geographic longitude")
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Install required dependencies including `geoip2`:
  ```bash
  pip install fastapi uvicorn pydantic geoip2
  ```

> [!NOTE]
> **MaxMind GeoLite2 Setup Note:** Place the offline database files (`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`) in the project root directory for local offline IP and ASN geolocation lookups. (The system includes built-in mock fallback heuristics if the `.mmdb` files are not present).

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
# Core Origin Traceability Tests (Feature 3.2)
python -m unittest test_geo_intel.py

# Security Vulnerability & Hardening Tests
python -m unittest test_security.py
```

---

## 📡 REST & WebSocket API Reference

| Method | Endpoint | Payload / Parameters | Description |
|---|---|---|---|
| `GET` | `/` | — | Single-page SOC web dashboard |
| `GET` | `/emails` | — | List all processed email traces with origin coords & threat flags |
| `GET` | `/emails/{email_id}/trace` | `email_id: str` | Detailed hop-by-hop coordinates, origin trace, and campaign clusters |
| `POST` | `/emails/analyze` | `EmailAnalyzeRequest` | Analyze raw relay chain (Rate-limited, max 30 req/min) |
| `WS` | `/ws` | — | Real-time WebSocket stream broadcasting `msg_type: "email_trace"` |

---

## 📂 Project Structure

```
email-geo-trace/
├── GeoLite2-City.mmdb   # MaxMind offline City database file (project root)
├── GeoLite2-ASN.mmdb    # MaxMind offline ASN database file (project root)
├── main.py              # FastAPI server, endpoints, rate limiter & WebSocket manager
├── geo_intel.py         # resolve_origin() implementation, IP geolocator & anonymization engine
├── config.py            # Known TOR nodes, hosting ASNs, VPN providers & precompiled trusted MTAs
├── test_geo_intel.py    # Unit tests for Feature 3.2 origin resolution
├── test_security.py     # Automated security verification test suite
├── .gitignore           # Git ignore rules
├── README.md            # Project documentation and specifications
└── static/              # Frontend assets
    ├── index.html       # Single-page SOC intelligence dashboard
    ├── style.css        # Cyberpunk / SOC dark theme styles
    └── app.js           # Leaflet.js controller, dual-mode views & WebSocket client
```
