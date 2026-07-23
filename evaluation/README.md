# Evaluation

Two measurements, answering different questions. Neither is a gate.

| Directory | Question | Runnable today |
|---|---|---|
| [`false-positive/`](false-positive/) | What does the egress guardrail do to legitimate security-testing content? | yes |
| [`agentdojo/`](agentdojo/) | How often does an indirect prompt injection succeed against an agent calling through the gateway? | yes, against scaffolding |

## Why these two and not one

The obvious Week-1 evaluation is an attack-success-rate baseline. It is also, right now,
close to meaningless on its own: Sentinel has no agent of its own, and the gateway
deliberately implements no injection detection
([decision 0006](../docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)).
Attack success means the model *did* something outside its task, and with no agent loop
there is nothing to hijack. Anything measured today describes the scaffolding built to
run the benchmark, and the `agentdojo/` README says so at the top.

The false-positive measurement is the opposite: it can be run today, against the content
this gateway actually carries, and it answers a question nobody has published an answer
to. Both research passes for this project reported the same gap — no study quantifies a
content guardrail's false-positive rate on a real security-testing workload. That gap is
sharpest here, because the legitimate traffic *is* injection payloads, traversal strings,
credentials inside vulnerable-by-design source, and long hex that is nearly always a file
hash.

## The corpus is not in git

`benchmark/targets/` and `scanners/out/` are ignored, so a fresh clone has almost none of
the corpus and the recorded numbers cannot be regenerated without provisioning it:

```bash
bash benchmark/scripts/setup-targets.sh     # clones WebGoat at the pinned tag (v2025.3)
```

The pin lives in `benchmark/targets/manifest.json`. Scanner reports under
`scanners/out/` are produced by running a scan; the sanitized ones are what the
measurement reads.

Corpus-dependent tests **skip** rather than pass when it is absent. That distinction
matters more than it looks: a false-positive count of zero over an empty corpus is also
zero, and would otherwise read as a clean result.

## What each number is, and is not

**False positives** are decided by structure, not opinion — contexts that cannot hold a
credential regardless of what they look like. A redaction inside WebGoat source is not
automatically wrong, because WebGoat teaches about hardcoded credentials and some of its
strings really are credentials. So the measurement judges only what it can judge, reports
the alteration rate without judgement, and treats payload preservation as a hard property.

The reported zero is only worth something because the machinery can produce a different
number. Reverting the guardrail's JWT pattern to the length-only form that shipped
earlier makes it report 36 false positives across real source, and a test asserts exactly
that. One of those 36 was caught by hand in review; the rest were not.

**Attack success rate** from `agentdojo/` is a static, undefended baseline against a
scaffold agent. Published work is unambiguous that static figures overstate robustness:
a filter measured at 0% statically was recovered to 64% on action-open tasks by adaptive
attack, and Sentinel's agents will be action-open by construction. Treat it as a
starting point for Week 7's before-and-after, never as evidence of robustness.

## Running them

```bash
python3 evaluation/false-positive/measure-false-positives.py \
  --output evaluation/false-positive/baseline-<date>.json
python3 -m pytest -q tests/test_guardrail_false_positives.py
```

See [`agentdojo/README.md`](agentdojo/README.md) for that harness, its cost, and the
bounded subset it runs.
