# AI-SAST findings → DefectDojo Generic Findings Import mapping

## Status and boundary

This is the Week-1 P2 contract for the future AI-SAST adapter. It is
**specification only**: it creates no Python adapter, fixture, test, request,
or DefectDojo import.

The upstream normalized `findings.jsonl` converter is implemented and its
schema is documented in
[`benchmark/findings/schema.md`](../benchmark/findings/schema.md). This mapping
is still **provisional for live import**: P5 must first reconcile it against at
least one real `findings.jsonl` emitted by the selected AI-SAST engine while
scanning the Lake target. Existing OWASP Benchmark output is not a substitute
because it is a scoring corpus, not the Lake target.

## Scope

- SAST only. The input has no endpoint or parameter model.
- Generic Findings Import only. ZAP and Nuclei use their native DefectDojo
  parsers in Week-1 P3; they are not converted through this mapping.
- The future adapter may import only findings for the defined Lake target. It
  must reject an OWASP Benchmark scoring-corpus record and must not reclassify
  it as Lake evidence.
- Cross-tool correlation is deferred. DefectDojo's per-parser deduplication is
  configured in P1; this adapter does not emulate it.

## Required source contract

Each accepted input is one validated `findings.jsonl` record with the immutable
identifier:

```text
finding_id = sha1(tool|rule_id|file|start_line|end_line|cwe)
```

`finding_id` is the SAST lineage key. It includes the end line and CWE so
distinct findings at the same start line do not collapse.

P5 must reject malformed records, duplicate JSON keys, unknown severity, an
empty identifier, an absolute or unsafe source path, a missing Lake-target
binding, or a `stage_status` other than `validated`. It must not invent values
for missing fields.

## Field map

| `findings.jsonl` field | Generic Findings Import field | Rule |
| --- | --- | --- |
| `finding_id` | `unique_id_from_tool` | Required; copied verbatim. This is the Generic parser's SAST lineage input. |
| `title` | `title` | Required after bounded validation. |
| `severity` | `severity` | Required; map only the normalized `critical`, `high`, `medium`, `low`, or `info` values to the importer's accepted spelling. |
| `cwe` | `cwe` | Integer only. Omit when null; never coerce arbitrary text to a CWE. |
| `file` | `file_path` | Required, repository-relative locator only. No host path, URI credentials, query values, or opaque tokens. |
| `start_line` | `line` | Required positive integer. |
| `end_line` | provenance validation | Required for `finding_id` verification but not serialized as a fabricated endpoint or parameter. Preserve it only in the bounded private import ledger if P5 needs it. |
| `message` | `description` | Required subject to the redaction rules below. |
| `sarif_ref` | reference/metadata locator | Locator only; do not embed SARIF, source, request, or code content in the finding body. P5 must verify the exact Generic Import representation against the installed DefectDojo version before live import. |
| `rule_id`, `tool`, `tool_version`, `variant`, `model`, `run_id`, `timestamp`, `confidence`, `owasp`, `target_test_case` | controller provenance only | Do not concatenate these into the user-visible finding body. Retain only a minimal, non-sensitive, bounded run ledger where necessary for audit. |
| `code_snippet` | dropped | Never serialise. |
| `target`, `stage_status` | admission checks | Required for policy admission; not finding-body content. |

## Redaction and provenance

Before creating an import payload, P5 must:

1. Drop `code_snippet` unconditionally.
2. Reject secret-like values in title, message, file path, `sarif_ref`, or any
   metadata/reference field rather than redact-and-continue ambiguously.
3. Preserve only the validated relative source locator and the `sarif_ref`
   pointer; never persist raw SARIF, source excerpts, prompts, responses,
   credentials, authorization headers, or scanner logs.
4. Keep prompt-egress redaction and egress audit separate. This mapping governs
   the finding write only; it does not authorize sending target-derived content
   to an LLM.

## Deduplication ownership

P1 owns DefectDojo configuration. Both
`DD_DEDUPLICATION_ALGORITHM_PER_PARSER` and
`DD_HASHCODE_FIELDS_PER_SCANNER` must retain their exact
`Generic Findings Import` entries. The Generic parser uses
`unique_id_from_tool_or_hash_code`; the adapter provides
`unique_id_from_tool = finding_id`.

P5 must prove a double import of the same reconciled source record does not
create a duplicate finding. It must not use this spec as justification to
modify native ZAP, Nuclei, Semgrep, or Trivy deduplication.

## Hard reconcile gate before P5

P5 remains blocked until all of the following are recorded:

1. The selected AI-SAST engine and the Lake target are explicit.
2. At least one real, sanitized `findings.jsonl` from that engine/target is
   available for contract reconciliation.
3. Every source field in the table is checked against that real record and the
   installed DefectDojo Generic Import contract.
4. The P5 adapter implements unit tests, secret-negative tests, and the
   duplicate live-import proof from the reconciled contract.
5. The separate prompt-egress redaction and audit boundary is approved and
   proven.

Until then, this document neither authorizes adapter code nor a live import.

## Cross-references

- P1: DefectDojo parser-specific deduplication configuration.
- P3: native scanner redaction for ZAP, Nuclei, Semgrep, and Trivy.
- P5: the only phase allowed to build the AI-SAST adapter, tests, and
  double-import validation.
