#!/usr/bin/env python3
"""Bench with optional gzip Accept-Encoding + persistent keep-alive."""
import gzip, json, sys, time, http.client
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3006"
MODE = sys.argv[2] if len(sys.argv) > 2 else "put"
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
PER = int(sys.argv[4]) if len(sys.argv) > 4 else 100
GZIP = len(sys.argv) > 5 and sys.argv[5] == "gzip"

U = urlparse(BASE)
HOST, PORT = U.hostname, U.port or 80

def worker(w):
    c = http.client.HTTPConnection(HOST, PORT, timeout=30)
    ok = fail = 0
    hdr = {"Connection": "keep-alive"}
    if GZIP:
        hdr["Accept-Encoding"] = "gzip"
    for i in range(PER):
        try:
            if MODE == "put":
                body = json.dumps({"v": 1, "tag": "bench", "note": "x" * 40})
                c.request("PUT", f"/api/collections/load/d{w}_{i}", body=body,
                          headers={**hdr, "Content-Type": "application/json"})
            elif MODE == "biglist":
                c.request("GET", "/api/collections/load?options=" +
                          '{"limit":500}', headers=hdr)
            else:
                c.request("GET", f"/api/collections/load/d{w}_{i}", headers=hdr)
            r = c.getresponse()
            data = r.read()
            if GZIP and r.getheader("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            if r.status == 200:
                ok += 1
            else:
                fail += 1
        except Exception:
            fail += 1
            try:
                c.close()
            except Exception:
                pass
            c = http.client.HTTPConnection(HOST, PORT, timeout=30)
    c.close()
    return ok, fail

t0 = time.time()
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    res = list(ex.map(worker, range(WORKERS)))
dt = time.time() - t0
ok = sum(o for o, _ in res)
fail = sum(f for _, f in res)
print(f"{MODE} gzip={GZIP} ok={ok} fail={fail} wall={dt:.1f}s rps={ok/dt:.0f}", flush=True)
