# Full Charter test suite (optional)

The slim grader venv is `requirements.txt` only: `pytest`, `cryptography`,
`requests`. That is the mentor/grader contract. `pytest.ini` `--ignore`s the
Charter files that import optional operator/RAG/attack-surface packages so a
fresh `.venv` can run the README ritual without `ModuleNotFoundError`.

This overlay is a deeper local check. It does **not** replace the slim grader
ritual in the root `README.md`. Do not treat a full-suite pass as the grader
proof, and do not add these extras to `requirements.txt`.

## Install extras

From the repository root, into the existing grader venv:

```bash
.venv/bin/pip install -r requirements-full.txt
```

`requirements-full.txt` includes `-r requirements.txt` plus `pydantic`,
`jsonschema`, `pyyaml`, `psycopg[binary]`, and `pgvector`. Those packages
unlock the ignored Charter files; they are not a substitute for
`rag/requirements.txt` (no onnx/fastembed).

## Run the full Charter suite

`-o addopts=""` clears the `pytest.ini` ignore list for this invocation only:

```bash
.venv/bin/python -m pytest -o addopts="" tests/test_charter_rag.py tests/test_charter_contracts.py tests/test_charter_proposal.py tests/test_charter_trivy.py tests/test_week1_artifact_normalizer.py tests/test_week3_aggregate_analysis.py tests/test_gateway_guardrails.py tests/test_attack_surface_baseline.py -q
```

Verified pass counts with those extras installed:

| File | Passed |
|---|---|
| `tests/test_gateway_guardrails.py` | 61 |
| `tests/test_week1_artifact_normalizer.py` | 16 |
| `tests/test_week3_aggregate_analysis.py` | 15 |
| `tests/test_charter_contracts.py` | 12 |
| `tests/test_charter_proposal.py` | 11 |
| `tests/test_attack_surface_baseline.py` | 11 |
| `tests/test_charter_rag.py` | 8 |
| `tests/test_charter_trivy.py` | 5 |

## Out of scope

`tests/test_workbench_phase3_boundary_scripts.py` is also ignored by
`pytest.ini`. It needs Docker and is a Workbench boundary check, not Charter.
Do not fold it into this suite.
