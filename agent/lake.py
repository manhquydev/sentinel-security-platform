"""Read-only reader for the DefectDojo vulnerability lake.

The Recon agent consumes findings through this module and nothing else touches the lake with
write intent. Authentication uses the Week-1 least-privilege service account (non-admin; cannot
delete — decision 0004), minted the same way the import path mints it.

Two DefectDojo API facts this module is built around, both the hard way:
  - Filtering findings by scanner needs `test__test_type=<id>` (a numeric id resolved from
    /test_types/), NOT `test__test_type__name=`. The name filter is unregistered and silently
    IGNORED — it returns every finding of every scanner, the exact failure the lake's
    locator-scheme guard was bitten by. So the type name is resolved to an id first.
  - A Nuclei (DAST) finding locates itself through `endpoints: [<id>]` pointing at Endpoint
    objects that carry the request path; SAST/SCA findings (Semgrep, Trivy) locate through
    `file_path`. The reader normalises both into a single `locator`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import requests

DD_URL = os.environ.get("DD_URL", "http://localhost:8080")
TIMEOUT = 20


@dataclass
class LakeFinding:
    finding_id: str
    title: str
    severity: str          # DefectDojo: Critical/High/Medium/Low/Info
    scanner: str           # 'SAST' | 'DAST' | 'SCA'
    cwe: int | None
    endpoint_paths: list[str] = field(default_factory=list)  # DAST request paths, if any
    file_path: str | None = None                              # SAST/SCA locator, if any


# scan_type name -> the map's scanner kind
_SCANNER_KIND = {
    "Semgrep JSON Report": "SAST",
    "Nuclei Scan": "DAST",
    "Trivy Scan": "SCA",
}


class Lake:
    def __init__(self, url: str = DD_URL):
        self.url = url.rstrip("/")
        self._token: str | None = None
        self._type_ids: dict[str, int] = {}
        self._endpoint_paths: dict[int, str] = {}

    def _auth(self) -> str:
        if self._token:
            return self._token
        user = os.environ.get("DD_SERVICE_ACCOUNT_USER")
        pw = os.environ.get("DD_SERVICE_ACCOUNT_PASSWORD")
        if not user or not pw:
            raise RuntimeError("DD_SERVICE_ACCOUNT_USER/PASSWORD not set (source infra/.env)")
        r = requests.post(f"{self.url}/api/v2/api-token-auth/",
                          json={"username": user, "password": pw}, timeout=TIMEOUT)
        r.raise_for_status()
        self._token = r.json()["token"]
        return self._token

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = requests.get(f"{self.url}{path}", params=params,
                         headers={"Authorization": f"Token {self._auth()}"}, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _type_id(self, name: str) -> int:
        if name not in self._type_ids:
            data = self._get("/api/v2/test_types/", {"name": name})
            results = data.get("results", [])
            if not results:
                raise RuntimeError(f"test_type not found: {name!r}")
            self._type_ids[name] = results[0]["id"]
        return self._type_ids[name]

    def _load_endpoints(self) -> dict[int, str]:
        """Prefetch the canonical endpoint id -> path map ONCE. DefectDojo dedups/merges endpoints
        on import, so a finding's `endpoints` list can reference pre-merge ids that no longer GET
        (404). We resolve against the canonical list and skip ids that merged away, rather than
        crash or invent a path for a reference the instance cannot honour."""
        if not self._endpoint_paths:
            data = self._get("/api/v2/endpoints/", {"limit": 500})
            for e in data.get("results", []):
                p = (e.get("path") or "").lstrip("/")
                self._endpoint_paths[e["id"]] = "/" + p if p else "/"
        return self._endpoint_paths

    def findings(self, product: str, scan_type: str, limit: int = 200) -> list[LakeFinding]:
        """Active, non-duplicate findings for one product + scanner, normalised. Read-only."""
        data = self._get("/api/v2/findings/", {
            "test__engagement__product__name": product,
            "test__test_type": self._type_id(scan_type),
            "active": "true", "duplicate": "false", "limit": limit,
        })
        kind = _SCANNER_KIND.get(scan_type, "SAST")
        ep_map = self._load_endpoints() if kind == "DAST" else {}
        out: list[LakeFinding] = []
        for r in data.get("results", []):
            # Only keep endpoint paths that resolve against the canonical list; a merged-away id
            # yields no path rather than a fabricated one.
            paths = [ep_map[eid] for eid in (r.get("endpoints") or []) if eid in ep_map]
            cwe = r.get("cwe")
            out.append(LakeFinding(
                finding_id=str(r["id"]),
                title=r.get("title", ""),
                severity=r.get("severity", "Info"),
                scanner=kind,
                cwe=cwe if cwe else None,
                endpoint_paths=paths,
                file_path=r.get("file_path") or None,
            ))
        return out
