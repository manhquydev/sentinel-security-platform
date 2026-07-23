# 0003 DefectDojo broker is Redis, not the upstream valkey pin

Date: 2026-07-23

## Status

Accepted

## Context

DefectDojo 3.1.200's own `docker-compose.yml` pins `valkey/valkey:9.1.0-alpine` as the
Celery broker. The data-lake standup (`docs/plans/active/defectdojo-data-lake-standup.md`)
started from that choice because upstream ships and tests it.

On this stack the Celery worker never processed a single task under valkey.

The failure is silent in every way an operator would normally check:

- worker logs `Connected to redis://valkey:6379/0` and `celery@… ready`;
- it registers every task, including `post_process_findings_batch`;
- `celery inspect ping` returns `pong`; `inspect active` returns empty;
- `inspect active_queues` reports it is consuming `celery`;
- no error, warning, or traceback appears in any container log;
- the UI and API stay fully responsive.

Meanwhile the queue only grew: measured depth **13 → 53** across a debugging window with
zero consumption, and `blocked_clients: 1` on the broker.

`MONITOR` on the broker showed what the control commands hid. Over a 14-second window the
worker issued **only** `PUBLISH …/worker.heartbeat` — no `BRPOP` at all. Capturing worker
startup showed its `BRPOP` calls target **only** `*.reply.celery.pidbox`, the control
(pidbox) channel. The task queue is never polled. That is precisely why `inspect` answers
normally while no work is done: control traffic and task traffic use different channels.

Eliminated as causes before reaching this conclusion, each by measurement:

| Hypothesis | Eliminated by |
|---|---|
| tasks never dispatched | queue depth grows on every import |
| worker dead | `inspect ping` → `pong` |
| stale `System_Settings` cache | `objects.get()` and `get(no_cache=True)` both `True`, in both uwsgi and worker |
| `solo` pool defect | `prefork` behaves identically |
| broken kombu binding / wrong queue name | `_kombu.binding.celery` present, `TYPE celery` = list, queued payloads carry the expected task name |
| worker consuming a different queue | `inspect active_queues` reports `celery` |

Control experiment: same DefectDojo image, same broker URL, same worker command, `redis
7.4-alpine` substituted for valkey. Result: `Task … received` → `Task … succeeded`, queue
drains to 0. **The broker was the only variable changed.**

## Decision

Run the Celery broker on `redis:7.4-alpine`, pinned by digest
`sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99`, with
`--appendonly yes`, a `redis-cli ping` healthcheck, and `depends_on: condition:
service_healthy` on every Celery-dependent service.

Upstream's valkey pin is deliberately **not** followed. The compose file records the
measurement inline so a future maintainer does not "restore parity" with upstream and
silently reintroduce the failure.

## Alternatives Considered

1. **Keep valkey and debug to the exact incompatible call.** Rejected for now: the
   product goal is a working data lake, and the substitution already restores correct
   behavior. The precise kombu/redis-py/valkey interaction remains unidentified — see
   Follow-Up.
2. **Keep valkey and run post-processing synchronously** (`force_sync`). Rejected: it
   moves deduplication, notifications, and grading onto the request path, changing import
   latency and failure semantics to work around a broker defect.
3. **Pin an older valkey.** Not attempted. Redis is the reference implementation Celery
   documents and tests against; choosing it removes the variable rather than guessing at
   a working version.

## Consequences

Positive:

- Celery genuinely executes tasks. Verified end-to-end: an identical finding imported
  twice is now flagged `duplicate=True`; under valkey it never was.
- This was never a deduplication-only problem. **Every** async path in DefectDojo runs
  through Celery — deduplication, notifications, product grading, JIRA sync. On valkey
  all of them silently did nothing while the system looked healthy.

Tradeoffs:

- The stack deviates from upstream's tested compose. The deviation is documented in
  `infra/defectdojo/docker-compose.yml` and `infra/defectdojo/README.md`, and is covered
  by a behavioural check in `scripts/dd-smoke.sh` that fails if the queue stops draining.
- Upstream may later fix or re-pin the broker; this decision should be revisited when the
  DefectDojo image is upgraded, not treated as permanent.

## Follow-Up

- The exact incompatibility (kombu transport vs redis-py 8.0.1 vs valkey 9.1.0) is
  unidentified. Worth reporting upstream: the pinned image disables all asynchronous
  processing with no error surfaced anywhere.
- Re-test the broker choice on any DefectDojo image upgrade. The smoke suite's
  queue-drain and duplicate-flag assertions are what will catch a regression.
