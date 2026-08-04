from __future__ import annotations

import pytest

from workbench.normalize import NormalizationViolation, normalize_codeql, normalize_semgrep, normalize_trivy


def test_new_engine_normalizers_emit_source_relative_canonical_union_keys_and_reconcile_counts():
    codeql = normalize_codeql(
        {
            "runs": [
                {
                    "invocations": [{"executionSuccessful": True}],
                    "results": [
                        {
                            "ruleId": "js/sql-injection",
                            "message": {"text": "SQL injection"},
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/db.ts"},
                                        "region": {"startLine": 12},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    semgrep = normalize_semgrep(
        {
            "results": [
                {
                    "check_id": "ts.sql-injection",
                    "path": "src/db.ts",
                    "start": {"line": 12},
                    "extra": {"message": "SQL injection", "severity": "ERROR"},
                }
            ],
            "errors": [],
            "paths": {"scanned": ["src/db.ts"]},
        }
    )
    trivy = normalize_trivy(
        {
            "Results": [
                {
                    "Target": "src/config.yml",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-TEST-1",
                            "Title": "Unsafe config",
                            "Severity": "HIGH",
                            "CauseMetadata": {"StartLine": 4},
                        }
                    ],
                }
            ]
        }
    )

    assert codeql[0].locator == "src/db.ts:12"
    assert semgrep[0].locator == "src/db.ts:12"
    assert trivy[0].locator == "src/config.yml:4"
    assert len({item.union_key for item in [*codeql, *semgrep, *trivy]}) == 3


def test_runner_adapter_converts_only_the_declared_container_source_mount_to_a_source_relative_locator():
    normalized = normalize_codeql(
        {
            "runs": [
                {
                    "invocations": [{"executionSuccessful": True}],
                    "results": [
                        {
                            "ruleId": "js/test",
                            "message": {"text": "test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file:///src/app.ts"},
                                        "region": {"startLine": 2},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        source_mount="/src",
    )

    assert normalized[0].locator == "app.ts:2"

    with pytest.raises(NormalizationViolation):
        normalize_codeql(
            {
                "runs": [
                    {
                        "invocations": [{"executionSuccessful": True}],
                        "results": [
                            {
                                "ruleId": "js/test",
                                "message": {"text": "test"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "file:///other/app.ts"},
                                            "region": {"startLine": 2},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            source_mount="/src",
        )


@pytest.mark.parametrize(
    ("normalizer", "report"),
    [
        (
            normalize_codeql,
            {
                "runs": [
                    {
                        "invocations": [{"executionSuccessful": False}],
                        "results": [],
                    }
                ]
            },
        ),
        (
            normalize_codeql,
            {
                "runs": [
                    {
                        "invocations": [{"executionSuccessful": True}],
                        "results": [
                            {
                                "ruleId": "bad",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "/host/secret.ts"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        ),
        (normalize_semgrep, {"results": [], "errors": ["parse error"], "paths": {"scanned": ["src/a.ts"]}}),
        (
            normalize_semgrep,
            {
                "results": [{"check_id": "bad", "path": "../outside.ts", "start": {"line": 1}, "extra": {}}],
                "errors": [],
                "paths": {"scanned": ["src/a.ts"]},
            },
        ),
        (normalize_trivy, {"Results": [{"Target": "../outside", "Vulnerabilities": []}]}),
        (normalize_trivy, {"Results": [{"Target": "src/a.ts", "Vulnerabilities": [{"Title": "missing id"}]}]}),
    ],
)
def test_normalizers_fail_closed_on_partial_or_non_relative_records(normalizer, report):
    with pytest.raises(NormalizationViolation):
        normalizer(report)


def test_semgrep_normalizer_refuses_a_report_that_skipped_any_source_file():
    with pytest.raises(NormalizationViolation, match="skipped"):
        normalize_semgrep(
            {
                "results": [],
                "errors": [],
                "paths": {
                    "scanned": ["src/a.ts"],
                    "skipped": [{"path": "src/generated.ts", "reason": "ignored"}],
                },
            }
        )
