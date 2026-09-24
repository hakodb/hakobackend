# Tenant isolation study: prefix (today) vs per-database-per-tenant

Status: STUDY ONLY — no code changes. Decision required before any work.

## 1. Today: prefix namespacing (measured)

One database/cluster serves all tenants; isolation is a naming rule
(`{tenant}__{logical}`) + the `__*` HTTP deny + per-tenant policy docs.
Measured on live Linux (hako, release, localhost):

- 10 tenants × concurrent workers: 2054 rps, fairness 50/50/50, 0 fail
- 50 tenants × 50 workers: 2027 rps, fairness 40/40/40, 0 fail
- vs single-tenant baseline (~2100 rps): tenant overhead ≈ **zero**
  (claim clone + one format! + cache lookups per request).

The prefix also keeps cross-tenant features trivial: `collectionGroup`
and tenant listing are single-namespace scans; tenant provisioning is
one doc insert; backup is one file/DB dump.

## 2. Alternative: one database per tenant

Each tenant gets a physically separate database (file, schema/database,
or RethinkDB database). The gateway routes tenant → handle.

### What it would buy (the honest case FOR)

- **Write parallelism on embedded engines.** SQLite and HakoDB
  serialize writers per file/instance. Tenants on separate files stop
  sharing one writer lock: N hot tenants × M rps each instead of one
  shared ceiling. This is the strongest argument, and it is real.
- **Noisy-neighbor isolation** (IO, locks, checkpoints, compaction).
- **Per-tenant operations**: backup/restore/drop = file/DB ops;
  per-tenant durability knobs (HakoDB Interval vs Always per tenant);
  per-tenant encryption keys (hako `encrypted_cols`).
- **Compliance-shaped isolation** (data physically separable).

### What it costs (the honest case AGAINST)

- **Resource fan-out.** Per tenant: page cache (hako `page_cache_capacity`
  × N), file handles (sqlite: db+wal+shm × N; hako: segments × N),
  background maintenance per instance (compaction/checkpoint/tombstone
  tasks × N), broadcast channels, poller tasks. 50 tenants = 50× the
  background work whether they are hot or not.
- **Pool explosion (SQL).** Postgres/MySQL need a pool per database
  (or schema-search-path juggling per query — error-prone). Hundreds
  of tenants × pool-min-connections = fd/process exhaustion server-side.
- **Lifecycle manager.** Open-on-first-use + idle eviction + LRU close,
  crash-safe reopen, corrupt-single-tenant containment — a whole new
  subsystem in `AppState` (tenant → `Arc<dyn Database>` router).
- **Cross-tenant features die or get expensive.** `collectionGroup`
  across DBs = fan-out merge in the gateway; tenant listing = N opens;
  global aggregates = scatter/gather.
- **Provisioning cost.** Create DB + run schema/index bootstrap per
  tenant (vs one doc insert today); per-tenant migrations forever.
- **Cold tenants still cost.** An idle tenant's files/handles/cache
  footprint never reaches zero without eviction machinery.

### Per-driver fit

| driver | per-db mapping | cost |
|---|---|---|
| hako (embedded) | one `Hako` instance per tenant dir | highest: cache + maintenance × N |
| sqlite | one file per tenant | high: fds + WAL × N, pool per file |
| postgres/mysql | database (or schema) per tenant | pool explosion; migrations × N |
| rethinkdb | **native**: `db_create` per tenant, one pool | cheapest: designed for multidb |

RethinkDB is the only driver where per-db is nearly free — everywhere
else it trades a naming rule for an ops burden.

## 3. Recommendation

- **Keep prefix as the default** (measured zero overhead, simplest ops,
  all cross-tenant features intact).
- **If write-parallelism per tenant is ever needed**: hybrid, not
  migration — keep prefix for the many, add a tenant→database override
  for designated BIG tenants (registry field, e.g. `dedicated_db`).
  Small tenants share; loud tenants get files. No existing tenant moves.
- **Do not build this now.** Trigger conditions: sustained multi-tenant
  write load hitting the single-writer ceiling with batch/coalescing
  exhausted, or a compliance/customer demand for physical separation.
- If triggered, the work is: tenant router + lifecycle/eviction +
  per-tenant bootstrap/migration runner + collectionGroup fan-out +
  portal support. Estimate: one phase the size of Phase B, not a tweak.
