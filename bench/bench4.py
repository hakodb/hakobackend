#!/usr/bin/env python3
"""Query bench: seed varied docs, then filtered/ordered/biglist reads.
Usage: bench4.py BASE [workers] [per]
Seeds 2000 docs {age: i%70} once, then measures eq-filter, order, full-list."""
import json, sys, time, http.client
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3025"
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 8
PER = int(sys.argv[3]) if len(sys.argv) > 3 else 50

U = urlparse(BASE)
HOST, PORT = U.hostname, U.port or 80

def seed():
    c = http.client.HTTPConnection(HOST, PORT, timeout=60)
    for i in range(2000):
        body = json.dumps({"age": 18 + (i % 70), "tag": f"t{i % 32}"})
        c.request("PUT", f"/api/collections/people/p{i}", body=body,
                  headers={"Content-Type": "application/json", "Connection": "keep-alive"})
        r = c.getresponse()
        r.read()
        if r.status != 200:
            print("seed fail", r.status)
            break
    c.close()

QUERIES = {
    "eq-filter": {"filters": [{"field": "age", "op": "==", "value": 30}]},
    "eq+order": {"filters": [{"field": "age", "op": "==", "value": 30}],
                 "orderBy": [{"field": "age", "direction": "asc"}], "limit": 100},
    "order-only": {"orderBy": [{"field": "age", "direction": "desc"}], "limit": 100},
    "biglist": {"limit": 500},
}

def bench(name, q):
    path = "/api/collections/people?options=" + quote(json.dumps(q))
    def worker(_):
        c = http.client.HTTPConnection(HOST, PORT, timeout=30)
        ok = 0
        for _ in range(PER):
            try:
                c.request("GET", path, headers={"Connection": "keep-alive"})
                r = c.getresponse()
                r.read()
                if r.status == 200:
                    ok += 1
            except Exception:
                pass
        c.close()
        return ok
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        ok = sum(ex.map(worker, range(WORKERS)))
    dt = time.time() - t0
    total = WORKERS * PER
    print(f"{name:12s} ok={ok}/{total} wall={dt:.1f}s rps={ok/dt:.0f}", flush=True)

seed()
print("seeded 2000", flush=True)
for name, q in QUERIES.items():
    bench(name, q)
print("QUERY_BENCH_DONE", flush=True)
