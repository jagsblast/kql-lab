#!/usr/bin/env python3
"""
relay.py — Minimal HTTP relay: Logstash JSON events → Kustainer inline ingest
Pure Python 3 stdlib — no pip packages required.

Listens on :9001 for JSON POST requests (single event or JSON array).
Buffers events and flushes them to Kustainer via .ingest inline management commands.
"""
import json, sys, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import queue, time, os

KUSTAINER = os.environ.get("KUSTAINER_URL", "http://adx:8080")
DB        = os.environ.get("KUSTAINER_DB",  "NetDefaultDB")
TABLE     = os.environ.get("KUSTAINER_TABLE", "WindowsEvents")
MAPPING   = os.environ.get("KUSTAINER_MAPPING", "winlogbeat_mapping")
PORT      = int(os.environ.get("RELAY_PORT", "9001"))
BATCH_MAX    = int(os.environ.get("BATCH_MAX",    "500"))
NUM_WORKERS  = int(os.environ.get("NUM_WORKERS",  "4"))

event_queue: queue.Queue = queue.Queue()


def ingest_batch(events: list) -> None:
    """Send an entire batch in one multijson inline-ingest call."""
    ndjson = "\n".join(json.dumps(e) for e in events)
    csl = (
        f".ingest inline into table {TABLE} "
        f"with (format=multijson, ingestionMappingReference={MAPPING}) <|\n"
        f"{ndjson}"
    )
    body = json.dumps({"db": DB, "csl": csl}).encode()
    req = urllib.request.Request(
        f"{KUSTAINER}/v1/rest/mgmt",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60):
        pass


def worker() -> None:
    """Background thread: drain the queue and ingest events into Kustainer."""
    print(f"Worker started — target: {KUSTAINER} db={DB} table={TABLE}", flush=True)
    while True:
        batch = []
        try:
            batch.append(event_queue.get(timeout=5))
            while not event_queue.empty() and len(batch) < BATCH_MAX:
                batch.append(event_queue.get_nowait())
        except queue.Empty:
            pass

        if not batch:
            continue
        try:
            ingest_batch(batch)
            print(f"INFO: ingested {len(batch)} event(s)", flush=True)
        except Exception as exc:
            print(f"WARN: batch ingest failed, requeueing {len(batch)} events: {exc}", file=sys.stderr, flush=True)
            for event in batch:
                event_queue.put(event)
            time.sleep(5)  # back-off before retry


class RelayHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args) -> None:
        pass  # silence per-request access logs

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        try:
            payload = json.loads(body)
            events  = payload if isinstance(payload, list) else [payload]
            for e in events:
                event_queue.put(e)
            self.send_response(204)
            self.end_headers()
        except Exception as exc:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(exc).encode())


if __name__ == "__main__":
    for _ in range(NUM_WORKERS):
        Thread(target=worker, daemon=True).start()
    print(f"Started {NUM_WORKERS} worker threads, BATCH_MAX={BATCH_MAX}", flush=True)
    server = HTTPServer(("0.0.0.0", PORT), RelayHandler)
    print(f"Relay listening on :{PORT} — queue ready", flush=True)
    server.serve_forever()
