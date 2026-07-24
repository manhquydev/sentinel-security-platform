"""Source adapters: normalise each charter source to a common SourceDoc shape.

Three sources, one shape. OWASP guidance arrives as markdown (chunked on headings); a CVE and a
local finding are short structured records (passed whole). Downloaded corpora are cached under a
gitignored path so re-ingest is offline and deterministic, and nothing fetched is committed.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

import requests

CACHE = os.environ.get("RAG_CORPUS_CACHE", os.path.join(os.path.dirname(__file__), ".cache", "corpus"))
TIMEOUT = 20

# A focused OWASP Cheat Sheet set covering the web-app vulnerability classes the local targets
# actually exhibit (Juice Shop / WebGoat): injection, XSS, authn/z, CSRF, input validation.
OWASP_CHEATSHEETS = [
    "SQL_Injection_Prevention_Cheat_Sheet",
    "Cross_Site_Scripting_Prevention_Cheat_Sheet",
    "Authentication_Cheat_Sheet",
    "Authorization_Cheat_Sheet",
    "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet",
    "Input_Validation_Cheat_Sheet",
    "REST_Security_Cheat_Sheet",
    "Session_Management_Cheat_Sheet",
]
OWASP_RAW = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/{}.md"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class SourceDoc:
    source: str          # 'owasp' | 'nvd' | 'attack-surface'
    source_ref: str      # stable id: url / CVE id / finding path
    title: str
    text: str
    kind: str            # 'markdown' | 'record'


def _cache_path(*parts: str) -> str:
    p = os.path.join(CACHE, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def _slug(text: str) -> str:
    """Filesystem-safe cache slug: never lets a source name traverse out of the cache dir."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "x"


def _get_text(url: str, cache_file: str, refresh: bool = False) -> str | None:
    """Fetch a URL, caching the raw body. refresh=True re-fetches, ignoring the cache. Returns
    None on failure (caller skips, does not fake)."""
    if not refresh and os.path.exists(cache_file):
        with open(cache_file, encoding="utf-8") as f:
            return f.read()
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001 - report and skip, never fabricate corpus
        print(f"  skip {url}: {e}")
        return None
    with open(cache_file, "w", encoding="utf-8") as f:
        f.write(r.text)
    return r.text


def fetch_owasp(names: list[str] | None = None, refresh: bool = False) -> list[SourceDoc]:
    names = names or OWASP_CHEATSHEETS
    docs = []
    for name in names:
        text = _get_text(OWASP_RAW.format(name), _cache_path("owasp", f"{_slug(name)}.md"), refresh)
        if text:
            docs.append(SourceDoc("owasp", f"CheatSheetSeries/{name}",
                                  name.replace("_", " "), text, "markdown"))
    return docs


def fetch_nvd(keyword: str = "juice shop", limit: int = 20, refresh: bool = False) -> list[SourceDoc]:
    """A bounded NVD slice by keyword. Cached raw. One request stays within the anon rate limit."""
    cache = _cache_path("nvd", f"{_slug(keyword)}.json")
    if not refresh and os.path.exists(cache):
        with open(cache, encoding="utf-8") as f:
            raw = f.read()
    else:
        try:
            r = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": limit},
                             timeout=TIMEOUT)
            r.raise_for_status()
            raw = r.text
            with open(cache, "w", encoding="utf-8") as f:
                f.write(raw)
        except Exception as e:  # noqa: BLE001
            print(f"  skip NVD {keyword!r}: {e}")
            return []
    data = json.loads(raw)
    docs = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        descs = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
        metrics = cve.get("metrics", {})
        sev = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cd = metrics[key][0].get("cvssData", {})
                sev = f"CVSS {cd.get('baseScore', '?')} {cd.get('baseSeverity', '')}".strip()
                break
        text = f"{cid}. {sev}\n\n" + "\n".join(descs)
        docs.append(SourceDoc("nvd", cid, cid, text.strip(), "record"))
    return docs


def load_attack_surface(path: str) -> list[SourceDoc]:
    """The local 'past pentest' analog: each attack-surface endpoint as a short record."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    target = data.get("target", {}).get("name", "target")
    docs = []
    for ep in data.get("endpoints", []):
        ref = f"{ep.get('method')} {ep.get('path')}"
        text = (f"{ref} on {target}. auth_class={ep.get('auth_class')}, "
                f"state_change={ep.get('state_change')}. {ep.get('rationale', '')}")
        docs.append(SourceDoc("attack-surface", ref, ref, text.strip(), "record"))
    return docs
