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

Per-stage gateway timing (1/16 sampling, hakobench-style accumulators).
The throwaway branch is gone: since v0.1.1 the profiler is permanent and
gated — `UB_WSTATS=1`, exercise the paths, `GET /api/__wstats` (404 when
disabled; one atomic load per request when off). Baseline tables below.

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

## 9. Front path (0.1.4): collect, not parse

`UB_WSTATS=1` FRONT table splits what used to be one `parse` stage
(`TimedJson`: same content-type rule, same `Bytes` collection, same
`from_bytes` classification as axum's `Json` — parity test pins 415/400):

- `mw_auth` 5.0us, `mw_limit` 2.7us — middleware is noise. The hunt in
  front of the handler was justified and is over.
- `collect` **509us** vs `parse` **4us** (PUT bodies ~50B, keep-alive,
  loopback). Serde is innocent; the cost is body-byte arrival + task
  wakeup under load (hyper body channel across tokio tasks, 8 workers on
  4 CPUs). Not code fat — transport + runtime scheduling.
- Consequence for "RPS jauh dari engine": per-PUT server-side ≈ 570us
  front + ~300us handler. Volume answers stay what they were: `/api/batch`
  (25K docs/s amortizes collect over the batch) and index declarations
  for reads. A tokio worker-tuning experiment may shave the wakeup tail;
  not scheduled — batch covers the need.
- Deploy: prod `:3005` runs 0.1.4 (systemd, backup `hakobackend.0.1.0.bak`
  beside the binary; stop→replace→start, SELinux context preserved).

## 8. eng_list anatomy (closed) + TopN proof (0.8.25)

`eng_list` ~10ms on 2000 unindexed docs = full scan + per-doc
`HakoDoc::decode` + driver `to_doc` + in-memory sort. Proven by elimination
(index experiment) and now by construction (TopN):

`eng_list` ~10-12ms on 2000 unindexed docs = full scan + per-doc
`HakoDoc::decode` + driver `to_doc` + in-memory sort. Proven by elimination
on the bench box (driver 0.8.24, narrowed `list()`):

- Baseline (no index): eq-filter 1076, eq+order 1104, order-only 368, biglist ~910 rps.
- After `POST /api/indexes {collection: people, fields: [age]}` (simple):
  eq-filter **2395** (+2.2x), order-only **2096** (+5.7x), eq+order/biglist
  flat (controls: eq+order was already fast on its 28-doc set; biglist has
  no filter/order — pure serialize, unchanged).
- Indexed path decodes only returned docs (limit pushed via
  SecondaryIndexRange); unindexed path decodes all 2000. That delta IS the
  ~10ms. No code change needed for ordered/filtered queries: declare the
  index. (Unindexed order+limit stays a full scan by correctness — §7.5.)
- `get_old` split (wstats, same box): miss ~10us, hit ~77us (decode+to_doc).
  The earlier keep-alive 42us skip figure is WITHDRAWN (order effect: hint
  run went second on warm cache). Skip saves ≈77us on overwrite, ≈10us on
  create — the wstats numbers are the clean ones (sampled within-run).
- TopN (hakodb 0.8.25, driver cursor-only): order-only 296→**1175 rps**
  (+4x vs best pre-TopN 368: +3.2x), eq+order 820→1279 (TopN over the
  full scan, decode-100-only), blended `eng_list` 9961→**4033us** (−60%).
  Engine parity suite (`tests/topn_parity.rs`, 13 shapes) locks exactness;
  `topn_runs()` counter proves lane engagement.

## 10. Pointer/passthrough verdict + per-driver positions
- Remaining `json!(...)` literals are sub-µs noise (tiny responses).
  Remaining per-doc DOMs that matter: `to_doc` (Hako Value→JSON per field);
  tx-`get` embed is fixed (0.1.4 `OpOut::Raw`, single serialize + verbatim splice).
- Zero-copy passthrough (serve engine bytes as HTTP bytes) was investigated
  and REJECTED for the current wire shape: the flat doc merges `id` (stored
  separately in hako/sqlite/pg/mysql) into the JSON, so `id` injection forces
  a parse anyway. Hako's `query_raw` returns binary (not JSON); sqlite/pg
  return JSON text but id-less. Passthrough needs a breaking envelope change
  (`{id, data}` nested) — not worth it at current margins.
- tx-`get` RawValue embed shipped in 0.1.4 (`OpOut::Raw` + `render_results`;
  re-parse exists only for tests). Remaining embed cost: one serialize per doc.
- Per-driver pushdown: sqlite full SQL (WHERE/cursor/ORDER/LIMIT) — best
  positioned; postgres ORDER+OFFSET+LIMIT pushed; hako native
  (count/sum/avg + ordered limit, TTL-exact total−expired protocol in
  `TtlDb`, gated on `supports_native_aggregation`); **rethinkdb: eq-filter
  object + unordered skip/limit + native count** (live 2.4.3: eq-filter
  58→211 rps, eq+order 59→194, biglist 55→152; order-only unchanged by
  design — ReQL-vs-contract ordering parity on missing/mixed-type fields
  is unverified, so the driver re-sorts + truncates). mysql same shape as
  pg. Live wall (8 workers, EL8 localhost, docker pg16/mysql8 — since
  removed): pg PUT 1116 GET 2032 eq 736 eq+order 719 order-only 424
  biglist 507; mysql PUT 772 GET 1861 eq 446 eq+order 453 order-only 356
  biglist 374.
- Live-test catches (all fixed): pg subcollection path filter bound a
  jsonb param vs a TEXT column (`text = jsonb` 42883) — unquote the param
  (`($n #>> '{}')`); mysql `list_collections` `ESCAPE '\'` is a syntax
  error (→ `!` escape) AND information_schema returns VARBINARY (sqlx
  ColumnDecode → `CAST AS CHAR`); common order-by-id bug (sqlite/pg/mysql
  JSON path sorts NULLs): `id` column everywhere + contract fallback,
  pinned by shared conformance §5a.
- Our server is one consumer among public ones; every driver above is
  measurable with the same bench scripts + permanent wstats (§7).

## 11. Per-shape wstats + `__benchmark` (0.1.5 unreleased)

- LIST splits by shape (`classify`: order / filter / filter-order / cursor
  / paged / plain) into `shape-*` tables; the blended `list` table stays
  for baseline continuity. Shape is computed from options only (no I/O).
- wstats enablement, any one wins: `--wstats` flag, `wstats = true` in
  `hakobackend.toml`, `UB_WSTATS=1` env. Same for `--benchmark` /
  `benchmark = true` (runs then exits, no serving).
- `__benchmark` (new `bench.rs`, driver-level, TTL wrapper on): fixed
  N=2000 seed `{age, tag}` (bench4-compatible), sequential ops, shapes
  seed-put/put/post/patch/batch/get/walk/index/query-idx/count/offset-idx/
  cursor-idx + auto-clean verified by final count == 0 (any deviation
  aborts loudly). Cursor walks id-order (unique keys — tied sort fields
  lose rows by contract, so age-cursor totals would be meaningless).
  hakobench stays the reference for durability sweeps; this runs the
  deployment default and compares drivers shape-by-shape.
- First numbers (sqlite, Windows dev, sync journal — floor, not target):
  seed-put 74, put 149, post 283, patch 285, batch(100) 2884,
  get 1904, walk 17959 docs/s, query-idx 307, count 313, offset-idx 126,
  cursor-idx 11391 docs/s, cleanup verified.
- Pre-existing failure, ROOT-CAUSED + FIXED (uncommitted): `bus_instant_lane`
  was not flaky — `subscribe()` returned before `run_source` registered its
  bus receivers, so a synchronous emit-then-recv always dropped the echo
  (fire-and-forget bus, 1s timeout < 2s poll tick). Deterministic on
  current-thread runtimes. Fix: oneshot ready-handshake (subscribe returns
  after StreamMap built; 5s timeout degrades to old behavior, never hangs).
  Same race affected real clients (open page → immediate write missed its
   echo until the next tick). Suite now 37 green.

## 12. Cross-driver comparison (EL8 localhost, 8 workers, fresh data)

Wall gateway RPS (bench2/bench4 in `bench/`, 8 workers × 100/50, hako
Interval / sqlite FULL / docker pg16 + mysql8 defaults):

| driver | PUT | GET | eq | eq+order | order-only | biglist |
|---|---|---|---|---|---|---|
| hako 0.1.4+TopN | ~2150 | ~2900 | ~1100 | ~1100-1300 | 296→1175 / 2096 idx | ~900 |
| postgres 16 | 1116 | 2032 | 736 | 719 | 424 | 507 |
| mysql 8 | 772 | 1861 | 446 | 453 | 356 | 374 |
| rethinkdb 2.4.3 | 226→259 | ~2000 | 58→211 | 59→194 | 48 | 55→152 |
| sqlite | dev-box only (not comparable; run `__benchmark` on target) | | | | | |

`__benchmark` sequential, release, N=2000 (hako/Interval server):

| shape | hako rps | sqlite-dev rps |
|---|---|---|
| seed-put / put / post / patch | 12K / 19K / 20K / 19K | 74 / 149 / 283 / 285 |
| batch (1 tx @100) | 164323 docs/s | 2884 |
| get / walk / cursor-idx | 399K / 654K / 60K docs/s | 1904 / 17959 / 11391 |
| query-idx / count / offset-idx | 776 / 18190 / 1039 | 307 / 313 / 126 |

wstats handler baselines (hako): PUT ~290-340 (get_old 115→73 hit,
eng_set ~150-230 fsync variance), GET ~25-94 (eng_get 78→14),
LIST blended ~13.1ms→~3-4ms (TopN/indexed), FRONT total ~1200 blended
(mw_auth 5, mw_limit 2.7, collect ~350-570, parse 4). Per-shape tables
(`shape-order/filter/filter-order/cursor/paged/plain`) isolate further —
cursor eng highest by design (full fetch + post-filter).

Engine matrix Always/1000docs (same C++ harness): v0.7.6 → 0.8.24 →
TopN ≈ flat-or-better everywhere (WPS ~1360/8800, Qry ~21.5K,
Agg ~76K); Par/Tx rows are bimodal noise, compare isolated runs only.

## 13. Test-methodology issues (earned the hard way)

- Wall-RPS moves ±20% run to run: compare bands across repeats, never
  single runs. Parallel-profile rows are bimodal — rerun isolated.
- `bench4` asserts HTTP 200 only, never content: an index speedup once
  masked EMPTY results. Pair slow shapes with a doc-count check.
- Index builds are async: queries issued immediately read empty/partial
  indexes. Engine now falls back to full scan mid-build
  (`index_query_ready`); bench probes readiness too. Same hazard exists
  over plain HTTP right after `POST /api/indexes`.
- Sequential curl loops measure TCP setup (~1ms), not handlers — use
  keep-alive (the python scripts do) or multi-URL single curl.
- RPS is throughput with N in flight; per-request latency ≈ workers/rps.
- Sampling is 1/16 globally: per-shape wstats rows need volume (~64+
  requests/shape for a few samples); un-sampled shapes read 0.0, not 0.
- TTL wrapper shadows native aggregation in prod (correctness over
  speed); native fires via the exact total−expired protocol.
- Conformance had holes (order-by-id, subcollection pg, mysql
  list_collections) — every live run since has closed one; keep
  extending the shared suite, it is the arbiter.

## 14. Per-driver optimization guide

- **hako**: keep Interval (deployment default; Always only when every
  write must survive power loss — 96% of single-write cost is fsync).
  Declare indexes for every filtered/sorted field (single biggest lever,
  2-6x measured). Batch hot writes (164K docs/s). `skip_read_before_write`
  or `X-Hako-Skip-RBW` for owner-free PUT volume (~77us/hit).
  `query_workers` = CPU count; jemalloc measured ~0% (kept for hygiene).
  Next structural lever only: `group_commit_max_ops`/durability per
  deployment, then faster disks.
- **sqlite**: `SQLITE_SYNCHRONOUS=normal` opt-in (~2.3x, measured).
  WAL + busy_timeout already on; temp sorts in MEMORY, 64MB mmap,
  32MB WAL cap (new defaults). Declare indexes (expression DDL via the
  driver). Raise page cache only past ~2MB working sets.
- **postgres**: `shared_buffers` 25% RAM, `effective_cache_size` high,
  `work_mem` for big sorts, pool max ≥ workers + margin (default 10
  fits 8 bench workers). Prepared statements on by default. Declare
  indexes (B-tree on sort/filter exprs via driver DDL). Watch jsonb
  cross-type comparisons (500 vs contract-exclude on wild data).
- **mysql**: `innodb_buffer_pool_size` 50–70% RAM — **docker default
  128MB starves it; all mysql numbers above are pool-starved floors**.
  Same index/pool advice as postgres; utf8mb4 everywhere. Eq-null and
  Ne-non-scalar have narrow missing-field divergences (documented in
  driver) — normalize those fields if aggregated.
- **rethinkdb**: secondary indexes on every ordered/filtered field
  (unindexed `order_by` sorts in memory, hard-capped at 100K docs —
  over the cap it ERRORS, not slows). Shards for scale; no multi-doc
  atomicity (emulated tx is best-effort); consider soft durability for
  write volume. ReQL-vs-contract ordering on missing/mixed types is
  unverified — keep order pushdown off until a parity study says otherwise.
- **universal**: batch > single puts; indexes > code; measure with
  `__benchmark` (driver) then `bench/*.py` (gateway) then wstats
  (stages) — in that order, cheapest signal first.
