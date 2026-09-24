# Write-coalescing evaluation note (`--coalesce-writes`)

## What it is

Rapid `PATCH`es to the same document fold into one stored write per
100 ms window. Only ELIGIBLE bodies coalesce: top-level plain keys, no
`__type__` sentinels anywhere. Anything else (atomics, dot-paths)
bypasses to a direct write. `GET` overlays pending bodies, so
read-your-write holds inside the window. Batch/transaction never
coalesce (atomicity is not negotiable).

## Why folding is exact (for eligible bodies)

Eligible bodies are shallow key→value maps with no sentinels. Folding
them by `HashMap::extend` then applying once via `apply_update` equals
sequential application: disjoint keys commute, duplicate keys are
last-win in arrival order. Dot-path bodies are excluded on purpose: a
plain-object key and a dot-path key do NOT commute
(`{"a":{"x":1}}` then `{"a.b":2}` vs folded in the other order differ),
so they bypass. The `__type__` scan is string-based and conservative —
a plain string merely *containing* the substring also bypasses (safe
direction: a missed folding opportunity, never a wrong fold).

## Measured (sqlite, localhost, same PS client both sides)

| workload | off | on |
|---|---|---|
| 150 distinct-key PATCHes, one doc (client-observed ack time) | 5220 ms (~35 ms/ack, one sqlite write each) | 1415 ms (~9 ms/ack, memory acks + ~2 stored writes) ≈ **3.7×** |
| keys present afterwards | 150/150 | 150/150 (no loss) |
| 50 increments (`increment` sentinel, bypass path) | exact 50/50 | exact 50/50 (bypass is exact under load) |

The win scales with burst density: one hot doc patched at >10 Hz
folds ~everything; sparse traffic barely triggers a fold.

## Findings fixed during this evaluation

- **The documented retry did not exist.** `flush_due` removed the entry
  before writing, so the `get_mut` requeue path never hit and the first
  flush failure dropped an already-acked write (the `MAX_FLUSH_FAILS`
  budget was dead code). Now failures requeue up to 10× ~one window
  apart; bodies merged concurrently during a failure fold underneath
  (newer still wins); exhausted entries drop with a log line
  (test: `failed_flush_requeues_then_delivers`).
- Quiescent retry pacing resets `first_at` on requeue (no 50 ms hot spin
  against a dead driver).

## Known limits (by design, stay documented)

- **Ack-before-store.** A driver failure surfaces in logs, not in the
  response. A unique-index conflict inside a coalesced PATCH is
  discovered at flush: the client already got `success`.
- **Abrupt stop loses ≤1 window.** Reload flushes explicitly; SIGTERM /
  SIGKILL do not drain the flusher (graceful shutdown drains sockets only).
- **Log line per failed flush.** A dead driver + hot doc = one line per
  window per doc until the budget exhausts.

## Recommendation

Stay **opt-in** (default off). Enable for high-frequency PATCH streams
against few hot docs (counters-as-plain-writes, telemetry, presence);
leave off for low-rate traffic (nothing to fold) and for writes that
must not be lost-or-logged (unique fields, billing). Re-evaluate if a
driver ever reports flush latency above the window (folds would stack).
