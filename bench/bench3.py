#!/usr/bin/env python3
"""Multi-tenant sim: register N tenants, then concurrent per-tenant workers.
Usage: bench3.py BASE N_TENANTS N_WORKERS PER [mix]
  mix: put (default) | get | mix
Workers round-robin over tenants; reports aggregate + per-tenant + fairness.
"""
import json, sys, time, http.client, urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3021"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
PER = int(sys.argv[4]) if len(sys.argv) > 4 else 25
MODE = sys.argv[5] if len(sys.argv) > 5 else "mix"

U = urlparse(BASE)
HOST, PORT = U.hostname, U.port or 80

def api(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()[:200]
    except Exception as e:
        return -1, str(e)[:100]

print(f"provisioning {N} tenants...", flush=True)
tokens = []
for i in range(N):
    slug = f"t{i:03d}"
    s, b = api("POST", "/api/tenants/register",
               {"slug": slug, "id": f"owner{i}", "password": "password123"})
    if s != 201:
        print(f"register {slug}: {s} {b}")
        continue
    s, b = api("POST", f"/api/auth/login?tenant={slug}",
               {"login": f"owner{i}", "password": "password123"})
    # token comes via cookie; fetch with http.client to read Set-Cookie
    c = http.client.HTTPConnection(HOST, PORT, timeout=30)
    c.request("POST", f"/api/auth/login?tenant={slug}",
              body=json.dumps({"login": f"owner{i}", "password": "password123"}),
              headers={"Content-Type": "application/json"})
    r = c.getresponse()
    r.read()
    tok = None
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and "__Host-ub_at=" in v:
            tok = v.split("__Host-ub_at=")[1].split(";")[0]
    c.close()
    if tok:
        tokens.append((slug, tok))
    else:
        print(f"login {slug} failed")
print(f"ready tenants: {len(tokens)}/{N}", flush=True)

def worker(w):
    slug, tok = tokens[w % len(tokens)]
    c = http.client.HTTPConnection(HOST, PORT, timeout=30)
    ok = fail = 0
    mine = 0
    for i in range(PER):
        try:
            if MODE in ("put", "mix"):
                c.request("PUT", f"/api/collections/posts/d{w}_{i}",
                          body=json.dumps({"v": i, "by": slug}),
                          headers={"Content-Type": "application/json",
                                   "Authorization": f"Bearer {tok}",
                                   "X-Tenant": slug})
                r = c.getresponse()
                r.read()
                if r.status == 200:
                    ok += 1
                    mine += 1
                else:
                    fail += 1
            if MODE in ("get", "mix"):
                c.request("GET", f"/api/collections/posts/d{w}_{i}",
                          headers={"Authorization": f"Bearer {tok}", "X-Tenant": slug})
                r = c.getresponse()
                body = r.read().decode()
                good = (r.status == 200 and slug in body) or (MODE == "get" and r.status == 404)
                if good:
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
    return slug, ok, fail

t0 = time.time()
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    res = list(ex.map(worker, range(WORKERS)))
dt = time.time() - t0
tot_ok = sum(o for _, o, _ in res)
tot_fail = sum(f for _, _, f in res)
per_tenant = {}
for slug, o, f in res:
    a, b = per_tenant.get(slug, (0, 0))
    per_tenant[slug] = (a + o, b + f)
vals = sorted(v[0] for v in per_tenant.values())
print(f"tenants={len(tokens)} workers={WORKERS} ok={tot_ok} fail={tot_fail} "
      f"wall={dt:.1f}s rps={tot_ok/dt:.0f}", flush=True)
print(f"per-tenant ok min/med/max: {vals[0]}/{vals[len(vals)//2]}/{vals[-1]}", flush=True)
