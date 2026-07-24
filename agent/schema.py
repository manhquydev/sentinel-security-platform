"""The Attack Surface Map — the frozen interface contract the Recon agent emits (Week 4).

This schema is the artifact later phases consume (Week-5 fuzzing/exploit read it to choose
targets), so it is a versioned contract, not an ad-hoc dict. It fuses three real sources:
lake findings (DefectDojo), the Week-1 attack-surface taxonomy (auth_class / state_change), and
RAG-sourced vulnerability context (referenced by provenance id, not copied verbatim).

`extra="forbid"` everywhere is deliberate: an LLM that invents a field or renames one is a
regression, and the schema must reject it rather than silently accept a malformed map. Enum
values match the ACTUAL data vocabularies (the attack-surface baseline's auth classes, DefectDojo
severities) — not an invented superset — so a value outside them signals a hallucination.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"

# DefectDojo severities and the attack-surface baseline vocabularies, verbatim.
Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
ScannerKind = Literal["SAST", "DAST", "SCA"]
AuthClass = Literal["public", "authenticated", "administrative", "hypothesis"]
StateChange = Literal["read-only", "state-changing", "hypothesis"]

_forbid = ConfigDict(extra="forbid")


class Finding(BaseModel):
    model_config = _forbid
    finding_id: str = Field(..., description="Stable id of the lake finding")
    title: str
    severity: Severity
    scanner: ScannerKind
    cwe: Optional[int] = Field(None, description="CWE id, if the scanner reported one")
    rag_refs: list[str] = Field(default_factory=list,
                                description="Provenance ids of RAG context used (source:source_ref)")


class EndpointSurface(BaseModel):
    model_config = _forbid
    path: str
    method: Optional[str] = None
    auth_class: AuthClass
    state_change: StateChange
    findings: list[Finding] = Field(default_factory=list)
    notes: Optional[str] = Field(None, description="Agent analysis; LLM narrative synthesized "
                                 "over target-derived findings (target-influenced, not raw target "
                                 "response text) — scrubbed for secrets and target-raw markers "
                                 "before it is persisted (see agent/supervisor.py)")


class Provenance(BaseModel):
    model_config = _forbid
    attack_surface_baseline: str = Field(..., description="attack-surface baseline id analysed")
    lake_products: list[str] = Field(default_factory=list, description="DefectDojo products read")
    rag_source_refs: list[str] = Field(default_factory=list, description="RAG chunks retrieved")
    model: str = Field(..., description="LLM model alias that produced the analysis")


class AttackSurfaceMap(BaseModel):
    model_config = _forbid
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    target: str
    generated_at: str = Field(..., description="RFC 3339 timestamp of the analysis")
    agent_version: str
    endpoints: list[EndpointSurface]
    # Findings that cannot be honestly tied to a specific endpoint — app/file-level (a Trivy
    # secret, a Semgrep SAST hit) or a DAST finding whose endpoint reference DefectDojo's dedup
    # merged away. Kept here rather than fabricated onto an endpoint.
    app_level_findings: list[Finding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    cwe_summary: dict[str, int] = Field(default_factory=dict, description="CWE id (str) -> count")
    analysis: Optional[str] = Field(None, description="Agent's prioritized synthesis over the "
                                    "findings and retrieved context; LLM narrative over "
                                    "target-derived input (target-influenced), not a source of "
                                    "counts — scrubbed for secrets and target-raw markers before "
                                    "it is persisted (see agent/supervisor.py)")
    provenance: Provenance

    @field_validator("generated_at")
    @classmethod
    def _rfc3339(cls, v: str) -> str:
        """generated_at is a timestamp contract, so reject a value that is not RFC 3339 rather
        than accept an arbitrary string the model happened to emit."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"generated_at must be an RFC 3339 timestamp, got {v!r}") from e
        return v

    def all_findings(self) -> list[Finding]:
        """Every finding in the map — endpoint-attributed and app-level — for aggregation."""
        out = list(self.app_level_findings)
        for ep in self.endpoints:
            out.extend(ep.findings)
        return out

    @model_validator(mode="after")
    def _rag_refs_declared(self) -> "AttackSurfaceMap":
        """Every RAG reference a finding cites must be declared in provenance.rag_source_refs —
        a finding pointing at context the map never recorded retrieving is an inconsistency (or a
        fabricated citation), and the contract rejects it."""
        declared = set(self.provenance.rag_source_refs)
        for f in self.all_findings():
            undeclared = [r for r in f.rag_refs if r not in declared]
            if undeclared:
                raise ValueError(
                    f"finding {f.finding_id} cites RAG refs not in provenance: {undeclared}")
        return self

    def _derive(self) -> tuple[dict[str, int], dict[str, int]]:
        sev: dict[str, int] = {}
        cwe: dict[str, int] = {}
        for f in self.all_findings():
            sev[f.severity] = sev.get(f.severity, 0) + 1
            if f.cwe is not None:
                cwe[str(f.cwe)] = cwe.get(str(f.cwe), 0) + 1
        return sev, cwe

    def recompute_aggregates(self) -> "AttackSurfaceMap":
        """Derive severity_counts and cwe_summary from the findings, so the aggregates are
        computed by code (trustworthy) rather than by the LLM (mockable). Returns self."""
        self.severity_counts, self.cwe_summary = self._derive()
        return self

    def consistency_errors(self) -> list[str]:
        """Deterministic self-check: aggregates must match the findings. A mismatch means the
        map was assembled wrong (or an LLM fabricated a count). Empty list == consistent."""
        errs: list[str] = []
        sev, cwe = self._derive()
        if sev != {k: v for k, v in self.severity_counts.items() if v}:
            errs.append(f"severity_counts {self.severity_counts} != derived {sev}")
        if cwe != {k: v for k, v in self.cwe_summary.items() if v}:
            errs.append(f"cwe_summary {self.cwe_summary} != derived {cwe}")
        return errs


class ExploitProposal(BaseModel):
    """A Week-6 Exploit(sim) lead (decision D3, 0013's read-only bound). `endpoint`/`vuln_class`/
    `signal_kinds` are FACTS assembled by code from the fuzz report — never the model's word for
    it (mirrors `AttackSurfaceMap`'s "facts by code" discipline). `technique`/`justification`/
    `expected_impact` are the one narrative LLM call's output: a technique DESCRIPTION for a
    human to verify next, never a runnable payload/script/command — `agent/exploit.py` passes
    them through a BEST-EFFORT scrub of runnable state-changing/script/shell shapes (SQL DDL/DML,
    `xp_cmdshell`, shell chains, `<script>`/on-error/on-load/`javascript:`) before this model is
    ever constructed with LLM content, LAYERED ON the real safety guarantee: this agent never
    executes anything (structural containment, see `agent/exploit.py`'s module docstring), so the
    scrub is defense-in-depth, not the control. On the supervisor/graph path, `agent/supervisor.py`
    additionally redacts these fields (secrets + target-raw) before they reach the checkpoint, the
    same D5 rule every other persisted narrative field follows; the standalone CLI has only the
    scrub above. Non-state-changing read-probe leads (boolean SQLi, UNION-read, traversal/template
    markers) may legitimately appear as human-facing technique text — those are leads for a human
    to verify manually, never executed. `verdict` is fixed to a single HITL-gated literal — this
    agent proposes, it never gets to decide "go"."""
    model_config = _forbid
    endpoint: str
    vuln_class: str = Field(..., description="Code-derived from payload_class + signal_kinds, "
                            "e.g. 'sql-injection-suspected' — not an LLM assertion")
    signal_kinds: list[str] = Field(default_factory=list,
                                    description="Deterministic fuzz signal kinds behind this lead")
    technique: str = Field(..., description="A description of what a human should try next to "
                           "verify the lead — never a runnable payload")
    justification: str
    expected_impact: str
    verdict: Literal["suspected-needs-hitl"] = "suspected-needs-hitl"
