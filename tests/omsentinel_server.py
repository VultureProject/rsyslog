#!/usr/bin/env python3
"""
Mock Microsoft Sentinel server for omsentinel tests.

Handles two real API endpoint paths on a single HTTPS port:

  Auth (OAuth2):
    POST /<tenant_id>/oauth2/v2.0/token
      - returns: {"access_token": "<uuid>", "token_type": "Bearer", "expires_in": N}

  Log ingestion:
    POST /dataCollectionRules/<dcr>/streams/<stream>?api-version=...
      - requires "Authorization: Bearer <valid-token>" header
      - returns: 204 No Content  (mirrors the real Azure Log Ingestion API)

Test inspection (no auth required):
    GET /test/data   → JSON array of all received POST bodies (strings)
    GET /test/stats  → {"issued": N, "ingested": N, "active_tokens": N}

Failure injection (CLI flags):
  --fail-auth-after N    return 401 on the (N+1)-th and subsequent auth POSTs
  --fail-ingest-every N  return --fail-with every N-th ingest POST
  --fail-ingest-after N  return --fail-with on every ingest POST after the N-th
  --fail-with CODE       HTTP status code to use for injected failures (default 500)
"""
import argparse
import gzip
import json
import os
import ssl
import time
import threading
import uuid

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Shared mutable state (protected by state["lock"])
# ---------------------------------------------------------------------------
state = {
    "lock":              None,   # threading.Lock, set in main()
    "tokens":            {},     # token_str -> expiry (time.time() + expires_in)
    "ingested":          [],     # list of raw POST body strings (one per request)
    "issued_count":      0,      # total token requests handled
    "ingest_count":      0,      # total ingest requests handled
    "compressed_count":  0,      # ingest requests with Content-Encoding: gzip
    "max_batch_messages": 0,     # largest message count seen in a single ingest POST
    # config (set from CLI, never mutated after startup)
    "accepted_dcr":      [],
    "accepted_streams":  [],
    "token_expire_secs": 3600,
    "fail_auth_after":   -1,
    "fail_ingest_every": -1,
    "fail_ingest_after": -1,
    "fail_with":         500,
}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class SentinelHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress per-request log noise; errors go to stderr automatically
        pass

    # --- helpers ------------------------------------------------------------

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    # --- dispatch -----------------------------------------------------------

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        # OAuth2 token endpoint:  /<tenant>/oauth2/v2.0/token
        if path.endswith("/oauth2/v2.0/token"):
            self._handle_token()
            return

        # Log ingestion endpoint: /dataCollectionRules/<dcr>/streams/<stream>
        if f"/dataCollectionRules/{state.get('dcr', '')}" in path and f"/streams/{state.get('stream', '')}" in path:
            self._handle_ingest()
            return

        self._send_json(404, {"error": "unknown endpoint", "path": self.path})

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/test/data":
            with state["lock"]:
                self._send_json(200, state["ingested"])
            return

        if path == "/test/stats":
            with state["lock"]:
                self._send_json(200, {
                    "issued":        state["issued_count"],
                    "ingested":      state["ingest_count"],
                    "active_tokens": len(state["tokens"]),
                    "compressed":    state["compressed_count"],
                    "max_batch_messages": state["max_batch_messages"],
                })
            return

        self._send_json(404, {"error": "unknown endpoint", "path": self.path})

    # --- auth ---------------------------------------------------------------

    def _handle_token(self):
        with state["lock"]:
            state["issued_count"] += 1
            n = state["issued_count"]

            if state["fail_auth_after"] != -1 and n > state["fail_auth_after"]:
                self._send_json(401, {"error": "simulated auth failure",
                                      "request_number": n})
                return

            token = str(uuid.uuid4())
            expiry = time.time() + state["token_expire_secs"]
            state["tokens"][token] = expiry

        self._send_json(200, {
            "access_token": token,
            "token_type":   "Bearer",
            "expires_in":   state["token_expire_secs"],
            "ext_expires_in": state["token_expire_secs"],
        })

    # --- ingest -------------------------------------------------------------

    def _handle_ingest(self):
        # Always consume the request body first so the connection stays clean
        # for subsequent keep-alive requests, regardless of whether we accept
        # or reject this particular request.
        raw_body = self._read_body()
        is_compressed = self.headers.get("Content-Encoding", "").lower() == "gzip"
        if is_compressed:
            raw_body = gzip.decompress(raw_body)
        body = raw_body.decode("utf-8")

        # Validate Bearer token
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send_json(401, {"error": "missing or malformed Authorization header"})
            return

        token = auth[len("Bearer "):]
        now   = time.time()

        with state["lock"]:
            expiry = state["tokens"].get(token)
            if expiry is None or expiry < now:
                self._send_json(401, {"error": "invalid or expired token"})
                return

            state["ingest_count"] += 1
            if is_compressed:
                state["compressed_count"] += 1
            msg_count = len(json.loads(body))
            if msg_count > state["max_batch_messages"]:
                state["max_batch_messages"] = msg_count
            n = state["ingest_count"]

            # Failure injection
            if state["fail_ingest_after"] != -1 and n > state["fail_ingest_after"]:
                self._send_empty(state["fail_with"])
                return

            if (state["fail_ingest_every"] != -1
                    and n > 1
                    and n % state["fail_ingest_every"] == 0):
                self._send_empty(state["fail_with"])
                return

            state["ingested"].append(body)

        # Azure Log Ingestion API returns 204 No Content on success
        self._send_empty(204)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Mock Microsoft Sentinel HTTP(S) server for omsentinel tests")

    parser.add_argument("-p", "--port",      type=int, default=0,
                        help="Listen port (0 = OS-assigned)")
    parser.add_argument("-i", "--interface", type=str, default="127.0.0.1",
                        help="Bind interface")
    parser.add_argument("--port-file",       type=str, default="",
                        help="Write the actual listen port to this file")

    # TLS
    parser.add_argument("--certfile",        type=str, default="",
                        help="TLS certificate (PEM).  Omit for plain HTTP.")
    parser.add_argument("--keyfile",         type=str, default="",
                        help="TLS private key (PEM).  Omit for plain HTTP.")

    # Token behaviour
    parser.add_argument("--token-expire-secs", type=int, default=3600,
                        help="Lifetime (seconds) of issued Bearer tokens")

    # DCR / Streams options
    parser.add_argument("--dcr",    type=str, default="",
                        help="Accepted DCR")
    parser.add_argument("--stream",    type=str, default="",
                        help="Accepted stream")

    # Failure injection
    parser.add_argument("--fail-auth-after",   type=int, default=-1,
                        help="Return 401 on auth requests after the N-th")
    parser.add_argument("--fail-ingest-every", type=int, default=-1,
                        help="Return --fail-with on every N-th ingest request")
    parser.add_argument("--fail-ingest-after", type=int, default=-1,
                        help="Return --fail-with on ingest requests after the N-th")
    parser.add_argument("--fail-with",         type=int, default=500,
                        help="HTTP status code for injected ingest failures")

    args = parser.parse_args()

    state["lock"]              = threading.Lock()
    state["token_expire_secs"] = args.token_expire_secs
    state["fail_auth_after"]   = args.fail_auth_after
    state["fail_ingest_every"] = args.fail_ingest_every
    state["fail_ingest_after"] = args.fail_ingest_after
    state["fail_with"]         = args.fail_with

    if args.dcr:
        state["dcr"] = args.dcr
    if args.stream:
        state["stream"] = args.stream

    server = HTTPServer((args.interface, args.port), SentinelHandler)

    using_tls = bool(args.certfile and args.keyfile)
    if using_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.certfile, args.keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    port = server.server_address[1]
    scheme = "https" if using_tls else "http"
    print(f"omsentinel mock server: {scheme}://{args.interface}:{port}  pid={os.getpid()}")
    print(f"args: {args}")

    if args.port_file:
        with open(args.port_file, "w") as f:
            f.write(str(port))

    server.serve_forever()


if __name__ == "__main__":
    main()
