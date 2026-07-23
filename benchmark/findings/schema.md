# findings.jsonl schema

Two-layer design (locked in `docs/benchmark-pre-plan-decisions.md` §QD2): the SARIF
file each tool produces is the lossless source of truth; `findings.jsonl` is a
normalized, 1-record-per-line view for scoring/diffing, with `sarif_ref` pointing
back to the original file.

## Fields

| Field | Type | Notes |
|---|---|---|
| `finding_id` | str (sha1 hex) | `sha1(tool\|rule_id\|file\|start_line\|end_line\|cwe)`. Includes `end_line`+`cwe` so two findings on the same `start_line` with a different CWE or span never collide (see `schema.py:compute_finding_id`). |
| `run_id`, `timestamp` | str | Which benchmark run produced this record. |
| `tool`, `tool_version` | str | From the SARIF driver (`tool.driver.name`/`version`). |
| `variant` | str | `V0` / `V1` / `V2`. |
| `model` | str | LiteLLM alias or raw model string used for this run. |
| `rule_id`, `title` | str | `title` falls back to the SARIF message text if the rule has no `shortDescription`. |
| `cwe` | int or null | See "CWE extraction" below. |
| `owasp` | str or null | Not populated yet — no tool in this round emits an OWASP category directly. |
| `severity` | `critical\|high\|medium\|low\|info` | See "Severity normalization" below. |
| `file`, `start_line`, `end_line` | str/int | From the first `physicalLocation` in `result.locations`. |
| `message` | str | `result.message.text`. |
| `code_snippet` | str or null | Not populated yet (SARIF `region.snippet.text` exists for Metis; wire up when a converter consumer needs it). |
| `stage_status` | `candidate\|validated\|rejected` | **Caveat: always `validated` this round.** Neither engine gives us a real source for the other two values — see "stage_status caveat" below. |
| `confidence` | float or null | Only Metis exposes this (`result.properties.confidence`). |
| `target` | str | `webgoat` or `owasp-benchmark`, passed in by the caller. |
| `target_test_case` | str or null | Extracted from the file path via `BenchmarkTest\d+` regex; null for non-OWASP-Benchmark targets. |
| `sarif_ref` | str | Path/identifier of the source SARIF file. |

## CWE extraction (two real shapes, not guessed)
Confirmed from actual tool output during the Phase 1 spike:
- **Metis**: `result.properties.cwe` = `"CWE-89"` (string) on the result itself.
- **SAIST**: no per-result properties; CWE lives as a `"CWE:89"` tag on the
  **rule definition** (`tool.driver.rules[].properties.tags`), looked up via
  `result.ruleId`. SAIST's severity is similarly a `SEVERITY:WARNING`-style tag
  on the rule, not the result.

`sarif_to_jsonl.py` checks result-level `properties.cwe` first (Metis shape),
then falls back to the rule-tags lookup (SAIST shape).

## Severity normalization
Order of precedence: result `properties.severity` (Metis) → rule tag
`SEVERITY:x` (SAIST) → SARIF `level` (`error→high`, `warning→medium`,
`note→low`, `none→info`) → `info` if nothing else is present.

## stage_status caveat
The schema keeps `candidate`/`validated`/`rejected` for future engines with a
real 2-tier detect→validate split (SAIST was meant to be this, per plan.md
§Quyết định #2 original text). This round: **SAIST produced 0 real findings**
(DeepSeek rejects its `json_schema` response_format — see
`runs/spike-engine-endpoint.md`), and **Metis is single-pass** (no
candidate/rejected split exposed in its SARIF). So every record this round is
`stage_status = "validated"` by default parameter, not inferred from data.
Revisit if SAIST returns on a compatible provider (Gemini) with real
candidate/rejected results.

## Fixture provenance (Red Team Finding #10 — no fabricated-fixture tests)
- `tests/fixtures/sample_metis.sarif`: copied verbatim from a real Metis run
  (`runs/spike-metis-output.sarif`, 2026-07-21) — genuine CWE-89 finding.
- `tests/fixtures/sample_saist.sarif`: rule metadata (id, tags, real CWE
  location) copied verbatim from a real SAIST run
  (`runs/spike-saist-output.sarif`). The one *result* in this fixture is
  constructed (SAIST had 0 real results this round) but follows SAIST's real
  result schema shape exactly, so the converter has a genuine SAIST-style
  rule-tags CWE case to handle. This is documented inline in the fixture file
  and must be replaced with a real result once SAIST runs successfully again.

## Robustness (added after code review, 2026-07-21)
A malformed/unexpected-shape SARIF result (null `shortDescription`, plain-string
`message`, non-numeric `confidence`, missing `locations`) is logged and skipped,
not a converter-aborting crash — required for a ~2700-test-case FULL OWASP
Benchmark run where one bad result must not zero out the run (plan.md red-team
finding #11, completeness gate). Pass `skip_log=[]` to `convert_sarif_to_findings`
to collect skip reasons into that run's manifest instead of only the log stream.
Duplicate identical results (same tool re-reporting one location) share a
`finding_id` by design (it's a content hash) and are logged as a warning rather
than silently retained with no signal. The hash itself is computed over a
JSON-encoded tuple, not a `|`-joined string, so a literal `|` in a field (e.g. a
file URI) can't cause an unrelated collision.

## DefectDojo / OCSF mapping
`findings.jsonl` maps 1:1 onto DefectDojo's generic finding import model:
`title`→title, `severity`→severity, `cwe`→cwe, `file`+`start_line`→file_path/line,
`description`→(built from `message` + optional `code_snippet`),
`unique_id_from_tool`→`finding_id`. Against OCSF Vulnerability Finding: `cwe`→
`vulnerabilities[].cwe`, `severity`→`severity_id` (via standard OCSF severity
enum mapping), `confidence`→`confidence_score` where present.
