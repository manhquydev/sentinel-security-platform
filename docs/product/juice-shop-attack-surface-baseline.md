# Juice Shop attack-surface baseline

This baseline is a versioned, anonymous-only locator inventory for the Juice Shop
runtime used by the Week-1 scanner harness. It is intentionally separate from the
DefectDojo lake: the exporter reads only the pinned manifest and the committed
locator observations.

## Target identity

- Image: `bkimminich/juice-shop@sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a`
- Application version: `20.1.1`
- Runtime: `juice-shop`, with the required host binding
  `127.0.0.1:13000` → container port `3000`
- OCI revision label: `df1b6bb`
- Separately resolved source commit: `df1b6bbd8bce6c4b6cf6b73625a0ddac946d2e92`
- Source repository: <https://github.com/juice-shop/juice-shop>
- Pinned source tree: <https://github.com/juice-shop/juice-shop/tree/df1b6bbd8bce6c4b6cf6b73625a0ddac946d2e92>

The OCI revision is declared image metadata, not a reproducible-build attestation.
The preflight checks the running container's image RepoDigest, configured OCI revision
label, required loopback port mapping and existing application-version endpoint. It does
not claim byte-equivalent source/image provenance.

## What is covered

The baseline records candidate public/read-only locators found in the pinned
OpenAPI/source references and sanitized Nuclei supporting locators. It also records
representative authentication, administrative and state-change boundaries as
`hypothesis` records when no route was executed; unexecuted or otherwise unsupported
classifications remain explicit hypotheses in the artifact. Parameter names and types
are retained; parameter values, cookies, credentials, requests and responses are not.
Trivy contributes only the digest-bound Juice Shop component identity; it is not a
vulnerability finding inventory.
Each observation carries a SHA-256 of its canonical immutable locator (or the image
digest for the component), so edited ad hoc references fail closed without storing raw
source or HTTP evidence.

The generated machine-readable artifact is
[attack-surface/baselines/juice-shop-df1b6bbd8bce.json](../../attack-surface/baselines/juice-shop-df1b6bbd8bce.json).
The exporter consumes the [pinned manifest](../../attack-surface/target-manifest.json)
and [locator observations](../../attack-surface/observations/juice-shop-df1b6bbd8bce.json).
From the repository root, with the pinned dependency in
`attack-surface/requirements.txt` available, rebuild it with:

```bash
python3 attack-surface/export-baseline.py build \
  --manifest attack-surface/target-manifest.json \
  --observations attack-surface/observations/juice-shop-df1b6bbd8bce.json \
  --output attack-surface/baselines/juice-shop-df1b6bbd8bce.json
```

The build is pure and deterministic. Runtime identity verification is a separate
read-only operation:

```bash
python3 attack-surface/export-baseline.py verify-runtime \
  --manifest attack-surface/target-manifest.json
```

## Boundaries and blind spots

- No authenticated crawler or state-changing request was run.
- No credentials, authorization headers, cookie jar, raw HTTP, source snippets or
  raw scanner output is stored.
- Semgrep/SAST rows are excluded because the existing Week-1 stream uses a Java-only
  ruleset and scans WebGoat/OWASP Benchmark rather than a Juice Shop source tree.
- Nuclei locators are supporting evidence only; they are not a complete route inventory.
- Trivy contributes component metadata bound to the pinned image digest, not vulnerability
  rows.
- The image/source provenance residual requires a future trusted attestation or
  reproducible-build decision.
