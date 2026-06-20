#!/usr/bin/env python3
"""
Generate http_demo.pcap — cleartext HTTP traffic for the Network Intelligence web/API-server view.

Three servers exercise the classification + endpoint log:
  - 10.0.0.50  JSON API (GET/POST /api/...)  -> API_SERVER
  - 10.0.0.60  plain HTML website            -> WEB_SERVER
  - 10.0.0.70  scanned host (mostly 404s)    -> WEB_SERVER + endpoint-enumeration banner

Run:     python3 gen_http_demo.py
Output:  http_demo.pcap  (in the same directory)
"""

import os
import random
import string
import sys

try:
    from scapy.all import wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
except ImportError:
    sys.exit("scapy not found — run:  pip install scapy")

CLIENT = "10.0.0.10"
SCANNER = "10.0.0.11"
CMAC = "52:54:00:bb:00:10"
SMAC = "52:54:00:aa:00:50"

pkts = []
_sport = 30000


def exchange(client, server, request, response):
    """Append a one-shot HTTP request + response on a fresh TCP stream (no handshake needed —
    tshark dissects and request/response-matches by 4-tuple)."""
    global _sport
    _sport += 1
    cmac = CMAC
    req = (
        Ether(src=cmac, dst=SMAC)
        / IP(src=client, dst=server)
        / TCP(sport=_sport, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=request)
    )
    resp = (
        Ether(src=SMAC, dst=cmac)
        / IP(src=server, dst=client)
        / TCP(sport=80, dport=_sport, flags="PA", seq=1, ack=1 + len(request))
        / Raw(load=response)
    )
    pkts.extend([req, resp])


def req(method, path, host):
    return (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: demo-client/1.0\r\nAccept: */*\r\n\r\n").encode()


def resp(status, reason, server, content_type, body=""):
    return (f"HTTP/1.1 {status} {reason}\r\nServer: {server}\r\n"
            f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}").encode()


# ── 10.0.0.50 — JSON API server ──────────────────────────────────────────────
API = "10.0.0.50"
API_SW = "nginx/1.18.0"
for _ in range(4):
    exchange(CLIENT, API, req("GET", "/api/users", "api.local"),
             resp(200, "OK", API_SW, "application/json", '{"users":[]}'))
exchange(CLIENT, API, req("GET", "/api/users/42", "api.local"),
         resp(200, "OK", API_SW, "application/json", '{"id":42}'))
exchange(CLIENT, API, req("POST", "/api/login", "api.local"),
         resp(200, "OK", API_SW, "application/json", '{"token":"x"}'))
exchange(CLIENT, API, req("POST", "/api/orders", "api.local"),
         resp(201, "Created", API_SW, "application/json", '{"id":1}'))
exchange(CLIENT, API, req("DELETE", "/api/orders/1", "api.local"),
         resp(204, "No Content", API_SW, "application/json"))
exchange(CLIENT, API, req("GET", "/api/secret", "api.local"),
         resp(403, "Forbidden", API_SW, "application/json", '{"error":"forbidden"}'))

# ── 10.0.0.60 — plain HTML website ───────────────────────────────────────────
WEB = "10.0.0.60"
WEB_SW = "Apache/2.4.41"
for path in ["/", "/about", "/contact", "/products", "/"]:
    exchange(CLIENT, WEB, req("GET", path, "www.local"),
             resp(200, "OK", WEB_SW, "text/html", "<html>hi</html>"))
exchange(CLIENT, WEB, req("GET", "/missing", "www.local"),
         resp(404, "Not Found", WEB_SW, "text/html", "<html>404</html>"))

# ── 10.0.0.70 — host under directory/endpoint enumeration ────────────────────
SCAN = "10.0.0.70"
SCAN_SW = "nginx"
random.seed(7)
for _ in range(25):
    p = "/" + "".join(random.choices(string.ascii_lowercase, k=8))
    exchange(SCANNER, SCAN, req("GET", p, "victim.local"),
             resp(404, "Not Found", SCAN_SW, "text/html", "<html>404</html>"))
for path in ["/", "/index.html"]:
    exchange(SCANNER, SCAN, req("GET", path, "victim.local"),
             resp(200, "OK", SCAN_SW, "text/html", "<html>ok</html>"))

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "http_demo.pcap")
wrpcap(out, pkts)
print(f"wrote {len(pkts)} packets ({len(pkts) // 2} HTTP exchanges) to {out}")
