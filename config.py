"""
Configuration for Origin Traceability & GeoLocation
Contains whitelist of trusted MTAs, RFC1918 private subnets,
and threat intelligence indicators (TOR exit nodes, hosting provider ASNs/ISPs, VPN signatures).
"""
import re

# Whitelist of trusted Mail Transfer Agents (MTAs) and internal domain patterns
TRUSTED_MTA_PATTERNS = [
    r"^([a-zA-Z0-9-]+\.)*internal\.company\.com$",
    r"^([a-zA-Z0-9-]+\.)*corp\.local$",
    r"^trusted-mta\.security\.net$",
    r"^mail-relay\.internal$",
    r"^10(\.[0-9]{1,3}){3}$",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])(\.[0-9]{1,3}){2}$",
    r"^192\.168(\.[0-9]{1,3}){2}$",
    r"^127\.0\.0\.1$",
    r"^::1$"
]

COMPILED_TRUSTED_MTAS = [
    re.compile(p, re.IGNORECASE) for p in TRUSTED_MTA_PATTERNS
]

# Backward compatibility alias
TRUSTED_MTAS = TRUSTED_MTA_PATTERNS

# Static list of known TOR exit node IPs (expandable / mockable for demo)
KNOWN_TOR_NODES = {
    "185.220.101.5",
    "185.220.101.7",
    "185.220.101.15",
    "198.96.155.3",
    "109.70.100.22",
    "162.247.74.200",
    "193.218.118.179",
    "195.176.3.24"
}

# Known Cloud/Hosting Provider ASNs and ISP strings
KNOWN_HOSTING_ISPS = [
    "Amazon.com, Inc.",
    "Amazon Data Services",
    "AWS",
    "DigitalOcean, LLC",
    "Hetzner Online GmbH",
    "Linode, LLC",
    "Akamai Connected Cloud",
    "OVH SAS",
    "Vultr Holdings LLC",
    "M247 Ltd",
    "Google Cloud Platform",
    "Microsoft Corporation",
    "Azure",
    "Leaseweb",
    "Contabo GmbH",
    "Choopa, LLC"
]

KNOWN_HOSTING_ASNS = {
    "AS16509", "AS14618", "AS14061", "AS24940", "AS63949",
    "AS16276", "AS20473", "AS34305", "AS15169", "AS8075", "AS51167"
}

# Known Commercial VPN Provider ISP indicators
KNOWN_VPN_PROVIDERS = [
    "NordVPN",
    "ExpressVPN",
    "Proton AG",
    "Surfshark Ltd",
    "Mullvad VPN",
    "CyberGhost",
    "Private Internet Access",
    "PIA",
    "Ipvanish"
]

# Fallback Geolocation Database for offline demo reliability
MOCK_GEO_DATABASE = {
    "185.220.101.5": {
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Tor Exit Node Network",
        "asn": "AS24940",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "is_tor": True,
        "is_vpn": False,
        "is_hosting": True
    },
    "198.96.155.3": {
        "country": "Switzerland",
        "city": "Zurich",
        "isp": "Privacy Host Net",
        "asn": "AS34305",
        "latitude": 47.3769,
        "longitude": 8.5417,
        "is_tor": True,
        "is_vpn": True,
        "is_hosting": True
    },
    "198.51.100.42": {
        "country": "United States",
        "city": "Chicago",
        "isp": "DigitalOcean LLC",
        "asn": "AS14061",
        "latitude": 41.8781,
        "longitude": -87.6298,
        "is_tor": False,
        "is_vpn": True,
        "is_hosting": True
    },
    "203.0.113.195": {
        "country": "Japan",
        "city": "Tokyo",
        "isp": "NTT Communications",
        "asn": "AS2914",
        "latitude": 35.6762,
        "longitude": 139.6503,
        "is_tor": False,
        "is_vpn": False,
        "is_hosting": False
    },
    "103.21.244.0": {
        "country": "India",
        "city": "Mumbai",
        "isp": "Reliance Jio Infocomm",
        "asn": "AS55836",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "is_tor": False,
        "is_vpn": False,
        "is_hosting": False
    },
    "157.240.22.35": {
        "country": "United States",
        "city": "Ashburn",
        "isp": "Meta Platforms",
        "asn": "AS32934",
        "latitude": 39.0438,
        "longitude": -77.4874,
        "is_tor": False,
        "is_vpn": False,
        "is_hosting": True
    }
}
