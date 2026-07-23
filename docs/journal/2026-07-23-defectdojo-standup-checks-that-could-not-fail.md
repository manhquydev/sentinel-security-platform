# 2026-07-23 — DefectDojo standup: two checks that could not fail

Work: Sentinel Week 1 Stream A, DefectDojo data-lake standup.
Outcome material: [execution plan](../plans/active/defectdojo-data-lake-standup.md),
[decision 0003](../decisions/0003-defectdojo-broker-is-redis-not-valkey.md),
[decision 0004](../decisions/0004-defectdojo-oss-has-no-role-based-authorization.md).

This entry is about method, not results. The results are in the files above.

## The same mistake, twice, in one day

**The restore drill.** It ran, printed `RESTORE DRILL PASSED`, and was believed. Then it
was run again against a randomly generated AES key — a key that should have made the
canary credential unreadable — and it passed again.

The cause: the canary was written with `Tool_Configuration.api_key = '<plaintext>'`.
DefectDojo encrypts credentials in the *form* layer, not in the model's `save()`. The
database held the literal string. Plaintext "decrypts" successfully under any key, so the
drill could not detect the one failure it existed to detect: a dump restored after key
rotation, whose rows are present, well-formed, and permanently unreadable.

**The smoke suite.** Twenty-two checks, all green, across two sessions. It asserted that
both deduplication dictionaries parsed as JSON and that every key resolved against
`/api/v2/test_types/`. All true. Meanwhile no deduplication was happening at all:
`System_Settings.enable_deduplication` defaults to `False` and no environment variable can
change it. The suite verified *configuration was loaded*, never *behaviour occurred*.

Both checks were written carefully. Both were worthless. The property neither had is the
only one that matters:

> A check that has never been observed to fail has not been shown to check anything.

Both now have negative controls. The drill is run against a wrong key and must report
`MISMATCH`. The smoke suite is run with deduplication disabled and must fail two checks
and exit 1. Those runs are part of the record, not a one-off.

## The plan's review had the same blind spot

The Week-1 plan went through two rounds of adversarial review. One round produced a
Critical finding specifically about deduplication: that setting
`DD_DEDUPLICATION_ALGORITHM_PER_PARSER` without `DD_HASHCODE_FIELDS_PER_SCANNER` leaves
non-endpoint defaults silently in place. Correct, precise, and useful.

Nobody asked whether deduplication was switched on. The reviewers examined how the feature
would behave in detail, and the acceptance criterion was written to match — "both dicts
set, keys resolve" — so the criterion passed honestly while the feature was inert.

Rigour applied inside an assumption cannot escape it. The question that broke it open was
not a better configuration review; it was importing the same finding twice and counting
duplicates.

## The broker: healthy-looking diagnostics hiding a dead path

After enabling the flag, deduplication still did nothing. What followed is worth recording
because every standard diagnostic said the system was fine:

- worker logged `Connected` and `ready`, registered every task;
- `celery inspect ping` → `pong`; `inspect active` → empty;
- `inspect active_queues` → reported consuming `celery`;
- no error, warning, or traceback in any log.

The only signal that disagreed was arithmetic: queue depth 13 → 53, never falling.

`MONITOR` on the broker settled it. Over fourteen seconds the worker issued only heartbeat
publishes — no `BRPOP`. At startup its `BRPOP` calls targeted only
`*.reply.celery.pidbox`: the control channel. Control commands and task delivery use
different channels, which is exactly why `inspect` answered normally while nothing ran.
Substituting Redis for valkey — one variable — restored `Task received` → `Task succeeded`.

Lesson: when a component's self-report and its measurable effect disagree, the effect is
the evidence. `inspect ping` proves a worker answers questions, not that it does work.

## Two wrong turns, for the record

**Misread output.** `CLIENT LIST` showed every connection coming from `172.19.0.7`, which
matched no application container. This was briefly read as a rogue container consuming the
queue. It was the broker's own `laddr` — a parsing error in the command used to inspect,
not a finding. Re-parsing by the correct field dissolved it.

**Blamed the wrong action.** `FLUSHALL` had been run on the broker during debugging, so the
consumer failure was assumed to be self-inflicted. Restarting the worker did not restore
consumption, and the backlog predated the flush. Plausible, sequential, and wrong.

Both were caught by measuring again instead of reasoning forward from the first
interpretation. Neither cost much; both would have if acted on.

## What carried over into the repository

- `dd-backup.sh` refuses to proceed if the canary is stored in plaintext, so the drill
  cannot silently degrade to a rubber stamp again.
- `dd-smoke.sh` imports a duplicate and requires it to be flagged — a behavioural check
  that fails when the mechanism is off, not merely when the config is malformed.
- `dd-bootstrap.sh` enables deduplication, because a setting with no environment variable
  will otherwise be forgotten in the next environment.
- The compose file carries the valkey measurement inline, so "restoring parity with
  upstream" cannot quietly reintroduce the defect.

## Still open

The exact valkey/Celery incompatibility is unidentified — the substitution works, the root
cause does not have a name yet. Worth reporting upstream: their pinned image disables all
asynchronous processing without surfacing a single error.
