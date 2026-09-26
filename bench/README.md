# Gateway bench scripts (HTTP-level)

These are the exact scripts behind every wall-RPS number in
PERFORMANCE_NOTE.md. Python 3 stdlib only. They measure the **gateway**
(HTTP + policy + driver + engine); driver-only numbers come from
`hakobackend --benchmark` (see `crates/hakobackend-server/src/bench.rs`),
engine-only numbers from hakodb's `benchmark` matrix.

## Scripts

- `bench2.py BASE MODE [workers] [per] [gzip]` — single-doc PUT/GET and
  500-doc lists. `MODE`: `put` (PUT rewrites `load/d{w}_{i}`,
  ~60-byte bodies), `get` (GET same ids), `biglist` (GET `load?limit=500`).
  Persistent keep-alive per worker; optional `gzip` Accept-Encoding probe.
  Defaults: 8 workers × 100 ops.
- `bench4.py BASE [workers] [per]` — seeds 2000 docs
  `{age: 18+(i%70), tag: t{i%32}}` into `people`, then measures
  `eq-filter` (age==30), `eq+order` (+order age asc, limit 100),
  `order-only` (order age desc, limit 100), `biglist` (limit 500).
  Defaults: 8 workers × 50 ops. Asserts HTTP 200 only — **not content**:
  pair slow shapes with a content check, or an index speedup can mask
  empty results (caught once the hard way; see PERFORMANCE_NOTE §8).
- `bench3.py BASE N_TENANTS N_WORKERS PER [mix]` — multi-tenant sim
  (open mode): registers N tenants, logs in, then `put`/`get`/`mix`
  with per-tenant JWTs. Reports aggregate rps + per-tenant min/med/max
  (fairness).

## Reproducing the comparison

```bash
# 1. bench instance (NEVER prod): fresh data, open limits, any driver
./hakobackend --driver hako --data /tmp/hqbench.ub --auth off \
  --host 127.0.0.1 --port 3025 \
  --limit-global 100000 --limit-global-burst 5000

# 2. single-doc + queries (8 workers, EL8 localhost reference)
python3 bench/bench2.py http://127.0.0.1:3025 put 8 200
python3 bench/bench2.py http://127.0.0.1:3025 get 8 200
python3 bench/bench4.py http://127.0.0.1:3025 8 50

# 3. wstats (same binary): UB_WSTATS=1 / --wstats / wstats = true,
# then GET /api/__wstats (404 when disabled)
```

## Reading the numbers honestly

- Wall-RPS moves ±20% run to run on a shared box (documented cases:
  biglist 717→933, order-only 224→368 with zero code change). Compare
  **bands across repeats**, never single runs. Parallel-profile rows in
  engine matrices are bimodal under load — prefer isolated-profile runs.
- RPS is throughput with 8 in flight; per-request latency ≈
  `workers / rps`, not `1 / rps`.
- Sequential loops (curl one-by-one) are dominated by TCP setup (~1ms),
  not handler time — use keep-alive multi-URL or the python scripts.
- `bench4` asserts status only: verify result **content** (count docs)
  before celebrating a query speedup.
- Durability is the deployment default in every number here (hako
  Interval, sqlite FULL unless `SQLITE_SYNCHRONOUS=normal`). hakobench
  stays the laboratory for durability sweeps.
