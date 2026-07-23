# Guardrail Hook Contract (D ↔ E Interface)

This document specifies the contract between Stream E (LiteLLM gateway) and Stream D (enforcement) for labelling and handling provenance of LLM request content. It is frozen as an interface contract and cannot change without coordinating both streams.

## Purpose

Sentinel's agents read content from deliberately vulnerable targets (OWASP Juice Shop, WebGoat). That content is attacker-controlled by construction, so indirect prompt injection is expected in every input. The gateway does not detect injection — this is an evidence-backed decision, not a gap.

Decision [0006](../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md) documents why injection detection fails at the gateway layer:

- **Adaptive attack** breaks 12 published defenses at >90% success rate ([Nasr et al.](https://arxiv.org/abs/2510.09023)).
- **Action-open tasks** (Sentinel's agents delegate the action itself to untrusted content) allow adaptive attack to recover 64% success even against filters measured at 0% statically ([AutoDojo](https://arxiv.org/abs/2606.15057)).
- **Domain-camouflaged payloads** evade production classifiers including Llama Guard 3 entirely, and Sentinel's legitimate traffic is made of security vocabulary and attack strings ([PARSE](https://arxiv.org/abs/2606.17467)).

Stream E ships labelling and transformation hygiene. Stream D implements capability gating and information-flow enforcement at the agent layer in Week 7, where control over the execution model exists.

## Schema and Authority

The authoritative schema is [provenance-label.schema.json](../../infra/litellm/guardrails/provenance-label.schema.json). Do not restate its fields below; read it for exact constraints.

## Declaration: How a Caller Sends Provenance

Every request to the gateway must carry the declaration at **`metadata.sentinel_provenance`**. Coverage must be exact: one entry per message in the `messages` array. An undeclared message fails the request closed.

`metadata` is the channel LiteLLM treats as proxy-side data and does not forward to the upstream provider. That is what this needs — the declaration instructs the gateway and is not something the model should see. A top-level custom key would instead rely on `drop_params` to avoid being forwarded upstream, which is too fragile to rest a security boundary on.

### Structure

```json
{
  "model": "sast-sol",
  "metadata": {
    "sentinel_provenance": {
      "schema_version": "1.0",
      "spans": [
        {
          "message_index": 0,
          "trust": "operator"
        },
        {
          "message_index": 1,
          "trust": "target-derived",
          "source": "nuclei-sanitized",
          "target": "juice-shop@sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a",
          "collected_at": "2026-07-23T10:15:30Z"
        }
      ]
    }
  },
  "messages": [
    {"role": "system", "content": "You are a security analysis assistant."},
    {"role": "user", "content": "<scanner output describing a finding>"}
  ]
}
```

- `message_index`: zero-based index into the `messages` array.
- `trust`: `"operator"` (authored by Sentinel) or `"target-derived"` (from a source Sentinel does not control).
- For `target-derived` spans: `source` and `target` are required. `collected_at` (RFC 3339 timestamp) is optional but recommended; it records when the content was obtained, not when the request was sent. Stale untrusted content presents different risk than fresh untrusted content.

## Gateway Guarantees

**Validation is fail-closed.** The gateway rejects any request where:
- `sentinel_provenance` is absent or malformed.
- Coverage is incomplete (any message lacks a declaration).
- A span declares `target-derived` without `source` and `target`.
- Indices are out-of-bounds or duplicated.
- `schema_version` is not `"1.0"`.

**Spotlighting is applied.** Every span declared `target-derived` is rewritten with visual markers (datamarking or delimiting) so the model can distinguish data from instructions. A system preamble is prepended explaining that marked content is target-derived. Spotlighting is hygiene, not a control; it is bypassable.

**An audit entry is produced** for each marked span, recording `source`, `target`, `collected_at` and character count. The gateway writes a summary of these — caller identity, count of spotlighted spans, and redaction counts per class — to the proxy log. Values are never logged, and the summary goes to the log rather than back to the caller, so the guardrail cannot be used as an oracle for what a caller managed to smuggle past it.

**Secrets are redacted on egress.** Credentials found in outbound content are replaced before the request leaves the host. Attack payloads and file hashes are deliberately *not* redacted: they are this system's legitimate cargo, and a redactor that mangles them would corrupt every downstream result invisibly. High-entropy content that is not classified as a credential is flagged in the audit trail without being altered.

## Gateway Non-Guarantees

**No injection detection.** The gateway does not attempt to detect, classify, or filter prompt injection. Read decision 0006 for the evidence basis.

**No prevention promise.** Labelling content as untrusted does not prevent an attack. It enables enforcement later. Spotlighting is not claimed to be a barrier.

## What Stream D Receives

Stream D receives the rewritten messages (with spotlighting applied), the audit entries, and the original provenance labels. These become the input to capability gating and information-flow enforcement in Week 7.

A mislabelled span (content marked trusted when it is untrusted) is worse than an unlabelled span, because enforcement will trust it. The discipline of the caller matters: callers must honestly declare whether each message is operator-authored or target-derived.

## Versioning

`schema_version` is an interface contract. Changing it requires coordination with both Stream E and Stream D; it is not a backward-compatible field. The current version is `1.0`.

To change the schema:
1. Propose the change with evidence (new field, new `trust` value, etc.).
2. Update the schema file.
3. Coordinate a simultaneous deployment window for both streams.
4. Update this document.

## Known Limitations

- **String content only (v1.0).** The contract handles text message content (`"content": "string"`). Multimodal payloads (images, audio) and tool-call content are rejected rather than silently passed.
- **No grammar enforcement.** A mislabelled span is a correctness bug in the caller, not detected by the gateway. The caller is responsible for honest labelling.
- **Spotlighting is bypassable.** Datamarking and delimiting are visible markers for the model; they carry no enforcement weight in the gateway. Enforcement happens at the agent layer.

## See Also

- [provenance.py](../../infra/litellm/guardrails/provenance.py) — reference implementation of validation and spotlighting.
- [Decision 0006](../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md) — full evidence and rationale.
- [Project architecture proposal §4](../project-sentinel-architecture-proposal.md) — stream ownership and interface contracts.
