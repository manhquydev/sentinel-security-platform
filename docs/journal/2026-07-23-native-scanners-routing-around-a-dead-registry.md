# 2026-07-23 — Native scanners: routing around a dead registry

Work: Sentinel Week 1 Stream A, P3 — native scanners (Semgrep/Trivy/ZAP/Nuclei) → Juice Shop
harness → DefectDojo data lake, TDD.
Outcome material: [execution plan](../plans/active/defectdojo-data-lake-standup.md),
the phase file `plans/260721-2216-week1-sast-dast-data-lake-defectdojo/phase-03-native-scanners-juiceshop.md`,
[decision 0005](../decisions/0005-scanner-wrappers-accept-a-local-binary-fallback.md).

This entry is about method. The results are in the files above.

## The test that found the bug before any scanner ran

The security guarantee of P3 is "no secret/raw snippet is persisted in a finding". It was
built test-first: four planted-secret fixtures (ZAP XML, Nuclei JSONL, Semgrep JSON, Trivy
JSON) and a test that runs each through a no-op redactor and asserts the secret is gone and
the endpoint locator survives. Against the no-op stub every removal assertion failed — 10
red, exactly the point — and the locator assertions passed, proving the fixtures were real.
Then the redactor made all 20 green. A redaction check that has never been seen red proves
nothing; this one was.

The more useful discipline was importing a *sanitized fixture* into the live DefectDojo
before any real scan existed, to exercise the one integration nobody had tested. It failed
immediately: `HTTP 400 ["product_name parameter missing"]`. `reimport-scan` cannot resolve a
test by an engagement id alone the first time a `test_title` is seen; it needs
`product_name` + `engagement_name` + `auto_create_context`. Had that not been caught with a
throwaway fixture, every real scan later would have failed at the import step and the cause
would have looked like a scanner problem, not a request-shape problem. The self-test then
got cleaned up (delete test, HTTP 204) so it left no residue in the baseline.

## The registry was the adversary, not the code

Three of four scanner images would not pull. Docker Hub answered its auth challenge in 0.9s,
so this was not connectivity — it was blob throughput. ZAP (~1.6 GB) sat at zero progress for
forty minutes. Nuclei stalled on a layer. Semgrep reached the final layer and died on
`connection timed out`. Two retries, which resume cached layers, also failed.

Waiting was the wrong move, and the fix was not patience but a different channel:

- **Semgrep** installed from PyPI (`pip install`) where its Docker image had timed out.
- **Nuclei** downloaded as a single 43 MB binary from its GitHub release CDN in one request,
  where its Docker image had stalled.

Both worked on the first attempt. The wrappers already fail closed on an unpinned image, so
rather than weaken that, each grew an explicit opt-in local-binary override
(`SEMGREP_BIN`, `NUCLEI_BIN`) that skips only the image-pin guard and keeps every other one —
ruleset checksum, allowlist, redaction. That trade-off is [decision 0005](../decisions/0005-scanner-wrappers-accept-a-local-binary-fallback.md):
the `@sha256` guarantee holds on the Docker path; the fallback is disclosed as weaker and
cannot be entered by accident.

## What the three live runs actually proved

All three ran end-to-end against the live lake — scan → redact → import → reimport — and the
second import of each left the finding count unchanged, so deduplication is real, not
asserted:

- Trivy (secret scan on the Juice Shop image): 4 real secrets. The vuln-DB download timed out
  like everything else, so this was `--scanners secret,misconfig`, which needs no DB — SCA is
  a follow-up when the DB caches.
- Semgrep (SAST on OWASP Benchmark Java, local checksum-pinned ruleset): 221 findings.
- Nuclei (DAST on Juice Shop over the loopback harness): 21 findings. This is the one that
  exercised the parts fixtures cannot — the allowlist pinned the resolved IP in the real scan
  path, and redaction preserved the real `matched-at` endpoint locators the way endpoint-dedup
  needs.

## What is honestly not done

The Juice Shop image healthcheck cost a first attempt: it is a distroless image with no
`/bin/sh` and `node` off the exec PATH, so a `CMD-SHELL` healthcheck can never return —
the app was serving fine while the container sat `unhealthy`. Fixed with an exec-form check
against node's real path. Worth remembering: a red healthcheck on a distroless image is more
often the check's fault than the app's.

Trivy vuln-SCA and ZAP never ran live (registry). The redaction guarantee for all four tools
is fixture-proven; three of four are also live-proven. That gap is disclosed, not hidden.

## The review caught the redactor doing the opposite of its own design

The redactor's header comment argued for a whitelist — "a value we do not enumerate is the
one that leaks" — and then the code shipped a *blacklist*: it nulled the known secret fields
(request/response, extracted-results, extra.lines, Secrets.Match) and kept everything else.
The fixtures only tested the fields the blacklist already knew about, so 20/20 was green and
meaningless. A code review planted secrets in real, commonly-present fields the fixtures
omitted — ZAP `evidence`/`otherinfo`, Nuclei `curl-command`/`meta`, Semgrep
`extra.message`/`fix`/`dataflow_trace`, Trivy misconfig `CauseMetadata.Code` (on by default) —
and all four leaked. One was a direct miss against the plan's own acceptance text.

The lesson is about the test, not the redactor: a guarantee test that only exercises the
fields the implementation already handles cannot fail for the reason the guarantee exists.
The fix inverted every tool to a whitelist — emit only the locator/metadata fields DefectDojo
needs to parse and dedup, drop all else — and extended the fixtures to the leak vectors above.
One subtlety surfaced immediately: Semgrep's parser *requires* `extra.message`, so dropping it
returned HTTP 500. A required-but-secret-bearing field is kept as a key with a constant
`[REDACTED]` value, not passed through and not dropped. All three live scanners still parse;
the redaction suite is 29/29 against the expanded vectors.
