# Performance note (release, Linux localhost, keep-alive clients)

Method: release binary on AlmaLinux 8, python http.client threads,
`--limit-*` raised (limiters proven separately), median of runs.
Debug/Windows numbers are NOT representative — see §5.

## 1. Throughput by driver (8 workers unless noted)

| workload | sqlite FULL | sqlite NORMAL | hako | rethinkdb |
|---|---|---|---|---|
| PUT single-doc | ~610 | ~410* | ~2100 | ~216 |
| GET doc | ~2500 | — | ~2700 | ~1878 |
| batch (50 ops/call) | — | — | **25704 docs/s** | (emulated tx, sequential) |

\* NORMAL A/B median 414 vs FULL 183 on same warm file (opt-in
`SQLITE_SYNCHRONOUS=normal`; default stays `full`).

Read the PUT column as: sqlite = fsync-bound, hako = group-commit,
rethinkdb = 3 sequential RTTs over ONE shared TCP session (plus a
read-before-write). GET column ≈ per-request fixed cost (~370µs).

## 2. Stage breakdown, PUT on hako (throwaway `TIMING` spans, medians)

| stage (cumulative from middleware entry) | med |
|---|---|
| policy + pre-read (`db.get`) | ~1330µs contended (~18µs + ~70µs uncontended) |
| + preprocess + engine write (`db.set`) | ~1840µs |
| + bus emit | ~0µs (map lookup, no subscribers cost) |
| client-observed avg at 8-way concurrency | ~500µs |

Under concurrency ~80% of PUT latency is ENGINE QUEUEING (single
writer + `spawn_blocking` queue), not app work. App-side fixed cost
(policy, clones, serde, emit) ≈ 100–200µs. Halving the stack buys
~30%, not 10× — the 10× gap is structural (one HTTP request per doc;
batch amortizes it: 25.7K docs/s ÷ 50 ≈ same 2ms/call as single PUT).

## 3. Task/spawn topology (no spawn per request)

- axum multi-thread runtime: acceptor + per-connection tasks.
- Handler futures run inline on workers (no per-request spawn).
- HakoDB (sync API): `spawn_blocking` per op (shared blocking pool).
- `realtime::emit`: inline broadcast send (no spawn).
- Per subscription: 1 `run_source` task. Per (db, collection): 1 shared
  poller task (or 1 driver watch bridge / 1 rethinkdb feed task).
- Global singles: coalescer flusher (if enabled), TTL sweeper,
  graceful-shutdown watcher (TLS).
- Lanes converge idempotently; lagged receivers resync, never queue
  unboundedly (see HTTP_CONTRACT §7).

So: packet → worker task → (blocking pool for hako ops) → inline emit
→ response, all on the request's task except engine sync ops.

## 4. Multi-tenant scaling (hako, open mode, per-tenant JWTs)

- 10 tenants: 2054 rps, fairness 50/50/50, 0 fail
- 50 tenants × 50 workers: 2027 rps, fairness 40/40/40, 0 fail
- Tenant overhead vs single-tenant baseline ≈ **zero**
  (claim clone + prefix format + cache lookups).

## 5. What the numbers are NOT

- Debug/Windows localhost figures (PUT ~190, warm 197–398) measure
  debug codegen + Windows fsync, not capacity. Never optimize from them.
- KAJIAN's 80–150K rps = framework hello-world, not CRUD.
- HakoDB engine benches (`benches/write_path.rs`, criterion,
  per-durability, small/blob docs) measure the ENGINE, not the gateway;
  gateway adds ~400µs fixed cost per request on top.

## 6. Levers, measured (not theorized)

- gzip responses <1KB: skipped (was 13–33% overhead when clients
  compress; now identical on/off for small docs).
- jemalloc (Unix): ~0% here (glibc tcache already optimal for small
  allocs); kept for fragmentation hygiene, verified linked via `nm`.
- DPoP early-out, per-second timestamp cache, sentinel fast paths:
  small, correct, in the +14% aggregate (1841 → ~2100 PUT).
- Durability: HakoDB `Interval` default; sqlite `NORMAL` opt-in (~2.3×).
- Bulk path: `/api/batch` (single tx) and `--coalesce-writes`
  (hot-doc folding) — the only 10× levers for write volume.
- Next structural lever if single-PUT must rise: expose HakoDB
  `group_commit_max_ops`/durability per deployment; then faster fsync
  (disk). After that: it is physics.

## 7. Gateway wstats + hot-spot fixes (Linux EL8, hako/Always, 8 workers)

Per-stage gateway timing (1/16 sampled, throwaway `/api/__wstats`,
hakobench-style accumulators — branch deleted after measuring):

- PUT handler ~339us: `get_old` 115.1 (34%) > `eng_set` 209.7 (fsync)
  > `preproc` 5.1 > `authz` 3.5 ≈ `serdom` 3.6 > `emit` 1.1 > `allow` 0.7.
- GET handler ~94us: `eng_get` 78.1 (83%) > `allow_ser` 10.5.
- LIST handler ~13.1ms: `eng_list` 12384.6 (94%, 2000-doc scan+decode)
  > `serdom` 703.7 > `filter` 12.7.
- Same-box engine `--wstats`: single-write `wal` 717.8/745.9us (96%);
  engine-native Qry 21516 qps vs gateway 224–1082 rps (20–90x gap =
  scan + per-doc codec + DOM, all gateway/driver side).

Fixes shipped (all conformance-green):

1. Direct serialization: `Json(doc)` instead of `to_value()` + `Json`
   (one throwaway Value DOM removed; wire bytes identical).
2. `[performance] skip_read_before_write` (policy opt-in, default off):
   PUT skips the old-doc lookup when no `owner` rule governs the write
   (only `Owner` reads the existing doc). Tradeoff: PUT-overwrite resets
   `createdAt`; PATCH merge always reads. See SECURITY_RULES.md §6.
3. Hako `get()`: direct sync call, no `spawn_blocking` hop (single-doc
   reads are µs-scale, never fsync; dedicated engine thread rejected —
   reads would queue behind fsync writes, a pool keeps the same hop).
4. Hako `count()`: native `execute_aggregation` (O(1) unfiltered, O(index)
   eq-filtered) instead of fetch-all + len; cursor shapes keep legacy path
   (native aggregation ignores cursor bounds). Sum/avg still reduce in
   server (they reuse the count guard, so they speed up too).
5. Ordered query pushdown: engine planner (local hakodb tree) no longer
   pushes scan limits under unsatisfied ORDER BY (P6/P7 — was wrong TOP-N
   for direct callers); driver keeps full-fetch for ordered/cursor shapes
   until the published `hakodb` dep includes the fix, then narrow to
   cursor-only (see driver comment). Real speed for unindexed order+limit
   still needs an index on the sort field (`/api/indexes` — supported).
