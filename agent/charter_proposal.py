"""Typed bridge from grounded charter findings to the fixed Phase-3 policy."""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from .charter_requests import RequestSpec, make_spec
from .charter_contracts import ReportFinding

@dataclass(frozen=True)
class RequestProposal:
    available: bool
    finding_ids: tuple[str,...]
    method: str = ""
    path: str = ""
    query: str = ""
    body: str = ""
    reason: str = ""
    def to_spec(self, run_id: str) -> RequestSpec:
        if not self.available: raise ValueError("proposal unavailable")
        headers={"Content-Type":"application/json"} if self.method=="POST" else {}
        return make_spec(run_id=run_id,method=self.method,path=self.path,query=self.query,body=self.body,headers=headers)

def propose(findings: Iterable[object], *, request_kind: str="get") -> RequestProposal:
    rows=list(findings); ids=[]
    for row in rows:
        # A ReportFinding is only constructed after the normalized scanner fact IDs,
        # allowed LLM enrichment shape, and retrieval provenance have all validated.
        # The old, nonexistent `grounded` attribute rejected every real report here.
        if not isinstance(row, ReportFinding):
            return RequestProposal(False, (), reason="unsupported evidence")
        ids.append(row.finding_id)
    if not ids:return RequestProposal(False,(),reason="no grounded findings")
    if request_kind=="get":
        return RequestProposal(available=True, finding_ids=tuple(ids), method="GET",
                               path="/rest/products/search", query="q=apple")
    if request_kind=="post":
        return RequestProposal(available=True, finding_ids=tuple(ids), method="POST",
                               path="/rest/basket", body="{}")
    return RequestProposal(False,tuple(ids),reason="unsupported fixed policy")


def propose_report_jsonl(path: str | Path, *, request_kind: str = "get") -> RequestProposal:
    """Load a persisted charter report through its strict type before proposing.

    A JSON object merely shaped like a report is not enough: the loader forbids extra
    fields and the proposal path receives only validated ``ReportFinding`` instances.
    """
    try:
        rows = [ReportFinding.model_validate(json.loads(line))
                for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:
        raise ValueError("invalid grounded report") from exc
    return propose(rows, request_kind=request_kind)
