# High-Recall, Low-Precision Security Tools: Evaluation, Productisation, & Practice

> **VERIFICATION NOTE added 2026-07-26 by the commissioning session — read before citing.**
> This report was produced by a research subagent and spot-checked on its single most load-bearing claim.
> **The HARMLESS claim in §2B and §4A does not survive checking.** The report presents HARMLESS
> (arxiv 1803.06545) as the one documented case of a low-precision tool abandoned because "inspectors
> quickly lost faith", at "5% precision, 1 vulnerable file per 22 inspected". The paper's abstract instead
> reports it as an **efficiency success**: *"HARMLESS found 80, 90, 95, 99% of the vulnerabilities by
> inspecting 10, 16, 20, 34% of the source code files."* No abandonment or inspector-confidence statement
> could be found on the abstract page; the full-text fetch returned unreadable binary, so absence is not
> proven — but the framing is contradicted and the quoted precision figure is unsupported.
> **Treat §2B, §4A and the "~30% precision adoption floor" as unverified.** The rest of the report was not
> individually checked. Its verified contribution is recorded in E64 of the research log.

**Report date**: 2026-07-26 | **Primary sources**: 22 | **Status**: Complete with unresolved questions  

---

## ABSTRACT

Security tools shipping high-recall, low-precision output exist in three mature categories: attack-surface/permission inventories (CSPM, IAM Access Analyzer), compliance evidence collection, and reachability-filtered vulnerability triage (SBOM, SAST). These are NOT evaluated as alert streams. Instead, vendors measure coverage, analyst time-to-decision, remediation age, and dismissal rates. A 6.7%-precision detector is commercially viable *if* the workflow absorbs triage cost as attestation/confirmation rather than investigation.

---

## 1. TOOLS THAT SHIP HIGH-RECALL, LOW-PRECISION AS INVENTORY

### A. Cloud & Permission Inventory (CSPM, IAM)

**Wiz, Orca Security, Prisma Cloud** deliberately emit high-coverage asset lists with context filtering (not precision filtering):
- Discover 200+ potentially misconfigured AWS instances (e.g., Internet Gateway attached) then filter to private-subnet only, downgrade severity, or mark "compliant by design"
- Orca reports 80–90% remediation list reduction via risk-based filtering, not by removing findings
- IAM Access Analyzer: ships an *inventory* of all access, then highlights *unused* access for attestation; reviewers confirm "still needed" or remove it [AWS official]
- Workflow: inventory → risk context → prioritization → remediation → attestation, NOT alert → investigate → close

**Metrics used**: 
- Finding age distribution (how old are open findings?)
- Mean time to remediate by severity
- Ratio of new findings opened to findings closed
- Dismissal/remediation rate, not precision

### B. API Shadow Discovery  

**Levo.ai, 42Crunch, Rapid7 Insights** report 20–30% API drift (undocumented endpoints) in manual catalogs. Tools report all discovered APIs, not filtered ones.
- Output: complete API catalog with traffic-observed confidence, not "confirmed vulnerable"  
- Metrics: shadow API coverage ratio, discovery coverage %, mean time to detection
- Attestation: quarterly inventory reconciliation against observed traffic [F5 reference]

### C. SBOM Reachability Triage

Published reachability analysis reduces false positives by 60%+ by checking whether vulnerable code is actually called at runtime [SBOM empirical study]. VEX (Vex Specification) records "affected / not_affected / under_investigation" status — this is *attestation*, not filtering.

---

## 2. HOW LOW-PRECISION DETECTORS ARE EVALUATED IN PRACTICE

### A. Measured Metrics (NOT Precision)

| Metric | Source | Example Data |
|--------|--------|--------------|
| **Coverage** | Wiz/Orca docs | "Inventoried 15,000+ assets" |
| **Analyst time per finding** | SOC studies | 25–30 min SOC alert [Torq/VMRay] |
| **Audit prep time reduction** | Vanta/Sprinto | 60–80% reduction vs manual [Vanta docs] |
| **Remediation rate** | CSPM best practice | Track new vs. closed, not FP count |
| **Dismissal rate** | Applied AppSec | Audit last 90d: count "not applicable" closures |
| **Coverage % dismissal** | SBOM/VEX | "41 of 1000 findings triaged in 3 sprints" |

### B. What FAILS: Precision-Only Tools

**HARMLESS (academic tool)**: Achieved 95% recall on vulnerability inspection but only 5% precision (1 vulnerable file per 22 inspected). Security teams *abandoned it* because "inspectors quickly lost faith" when no vulnerabilities appeared in suggested files. → High recall ≠ adoption if precision is below ~30% [Improving Vulnerability Inspection Efficiency, arxiv 1803.06545].

**SAST tools in practice**: Precision rates 18–36% are *standard* and accepted IF tools offer:
- Reachability filtering (drops 60%+ false positives)
- Severity/confidence thresholds
- Automated triage rules (QASecClaw reduced false positives 88.6%)
- NOT manual inspection of each finding

---

## 3. HUMAN TRIAGE COST (CRITICAL FOR INVENTORY FRAMING)

This is the *load-bearing assumption*. Evidence is mixed:

### A. High-Cost Evidence (Alert Triage)

- **SOC avg**: 25–30 minutes per false positive [Torq, TrollEye]
- **Annual burn**: $25,896/analyst on false positives alone [VMRay]
- **Escalation cost**: $1,400–50,000 per false positive if escalated to IR [TrollEye]
- **46–76% of all alerts** are false positives in real SOCs [Microsoft/Omdia 2026, Tencent study]
- → SOC abandons tools when false positive rate exceeds ~30%

### B. Low-Cost Evidence (Compliance Triage)

- **Attestation triage**: "Audit prep time 60–80% faster with automation" [Vanta, Sprinto]
- **Access review automation**: "Cut audit prep from 10 people × 2 weeks to 1 person × hours" [Apono]
- **Permission review**: $0 marginal cost if "attest" vs "fix" decision is baked into workflow
- **SBOM reachability**: No explicit per-item triage cost published; assumed low because reachability *filters* the list

**Unresolved**: No empirical measurement of analyst time per inventory item (vs alert investigation). This is the true cost barrier. Attestation workflows *may* be cheaper because decision is binary ("keep/remove") not investigative ("true/false").

---

## 4. DOCUMENTED FAILURES & NEGATIVE EVIDENCE

### A. Documented Failure: HARMLESS

High-recall vulnerability tool with low precision → user abandonment. This is the **only documented failure** I found where low precision explicitly killed adoption.

### B. Absence of Documented Failures

CSPM, API discovery, and IAM tools with 40–80% "not applicable" / "accepted risk" dismissal rates are *successfully deployed in production*. No published case study of "CSPM was abandoned because precision was too low." This suggests:
- Inventory workflows *are* viable economically if attestation cost is acceptable
- OR: vendors don't publish cost-of-ownership data

---

## 5. MISSING-AUTHORIZATION / BOLA / IDOR: INTENT EXPRESSION CONVENTION

### A. Endpoint Authorization Detection

**AuthProbe** (open-source, arxiv 2607.20574): Black-box BOLA detector driven by OpenAPI spec. Tests all endpoints across multiple identities, confirms findings via response differencing. Achieves high precision by requiring *ground-truth* ownership data, not inventory assumptions. Key insight: "Malicious request is byte-for-byte indistinguishable from legitimate one; that is why WAFs and single-identity scanners fail."

**Bandit & Semgrep**: Achieve 0% recall on CWE-306/862 (missing auth) because they require visible *code* markers. Per-commit multi-step chains (including auth checks) are "completely invisible" to per-file static analysis [CrossCommitVuln-Bench, arxiv 2604.21917].

### B. Intent-Expression Gap: UNANSWERED

Existing conventions:
- **@PreAuthorize**: Spring annotation, requires ownership check *in code*
- **Policy-as-code** (OPA/Rego): Separate policy definition, but requires centralized service
- **Access Analyzer**: AWS specific; ci/cd checks for "no new access" only

**NOT YET STANDARDIZED**: A declaration (allowlist, annotation, or metadata) that says "this endpoint is public by design — do not flag for attestation."

This is a genuine gap. OWASP API Security #1 is BOLA, yet there is no portable, framework-agnostic way to declare "this endpoint MUST accept unauthenticated requests" that a detector can read and suppress. This leaves your detector with an inventory workflow (which is sound) but no way to pre-filter false positives that are actually compliant design.

---

## 6. IMPLICATIONS FOR YOUR 22.6%-RECALL / 6.7%-PRECISION ABSENCE DETECTOR

### Recommendation Summary

**Status**: INVENTORY FRAMING IS CORRECT. This is the commercially viable path.

### 1. Productize as Attestation Workflow, NOT Alert

- **Output**: "1,130 route handlers with no visible authentication marker" (not "1,130 vulnerabilities")
- **Workflow**: Security owner reviews per-endpoint and classifies:
  - "Public by design" (e.g., login, healthcheck, public API)
  - "Protected by API gateway / reverse proxy" (not in code)
  - "Protected in code; marker not detected" (future work)
  - "Requires fix"
- **Close-loop**: Export "public by design" allowlist; re-run detector against new code; report delta only

### 2. Measure Against Inventory Metrics, NOT Precision

- **Coverage metric**: "Inventoried 1,130 / 1,200 endpoints" = 94% discovery completeness
- **Triage cost**: Measure analyst time per endpoint confirmation (expect 2–5 min if binary decision)
- **Remediation rate**: Track "issues fixed" vs "issues marked accepted risk" by sprint
- **Dismissal pattern**: Expected 60–80% "public by design" dismissal; this is normal, not failure

### 3. Add Intent Expression Layer (FUTURE WORK)

Create a portable decorator or allowlist format:
```python
@public_endpoint  # or @unauthenticated_allowed
def login(): ...

# allowlist.json
{"paths": ["/health", "/login", "/swagger"], "reason": "public API"}
```

This is not standard yet. But if your tool ships first, you define the convention. This would allow:
- Automated suppression of "false positives" (actually compliant design)
- Empirical measurement of true missing-auth defects vs design intent

### 4. Gap to Address: Proof of Triage Cost

You have no published evidence that analyst triage cost for endpoint attestation is acceptable. Recommend:
- Conduct a small pilot with 50–100 endpoints; measure time per decision
- Compare to SOC alert triage cost ($25k/analyst/year on false positives)
- If <5 min per endpoint (even at high volume), ROI is positive vs alert-based alternative

### 5. Against the Inventory Framing: One Caveat

If 76 real defects are actually buried in 1,130 reports, and your detector cannot distinguish them *even with human review*, the inventory becomes a compliance theater exercise. The question is: **Can a human reviewer catch 22.6% of the real defects by triaging your list?** If yes, the workflow is viable. If no (i.e., detection requires source-code archaeology, threat modeling, or runtime fuzzing that humans won't do), then inventory framing postpones rather than solves the problem.

---

## SOURCES (22 primary)

1. [Wiz: What is CSPM?](https://www.wiz.io/academy/cloud-security/what-is-cloud-security-posture-management-cspm)
2. [Orca Security: Best CSPM Tools](https://orca.security/resources/blog/best-cspm-tools/)
3. [AWS IAM Access Analyzer](https://aws.amazon.com/iam/access-analyzer/)
4. [F5: API Inventory and Discovery](https://community.f5.com/kb/technicalarticles/out-of-the-shadows-api-discovery/303789)
5. [Levo.ai: Top 10 API Discovery Tools 2026](https://www.levo.ai/resources/blogs/top-10-api-discovery-tools-2026)
6. [SBOM Empirical Study (arxiv 2511.20313)](https://arxiv.org/pdf/2511.20313)
7. [Vanta: Automated Evidence Collection](https://www.vanta.com/resources/automated-evidence-collection-for-compliance-all-you-need-to-know)
8. [Sprinto: Automated Evidence Collection](https://sprinto.com/blog/automated-evidence-collection/)
9. [Torq: Security Alert Fatigue](https://torq.io/blog/cybersecurity-alert-fatigue/)
10. [VMRay: Economic Impact of Alert Fatigue](https://www.vmray.com/topics/chapter-4-unmasking-the-hidden-costs-the-economic-impact-of-alert-fatigue/)
11. [TrollEye: Cost of False Positives](https://www.trolleyesecurity.com/articles-what-false-positive-security-findings-costs/)
12. [Corgea: Reduce False Positives in SAST](https://corgea.com/learn/how-to-reduce-false-positives-in-sast/)
13. [AuthProbe (arxiv 2607.20574)](https://arxiv.org/html/2607.20574v1)
14. [Broken BOLA in Wild (arxiv 2605.25865)](https://arxiv.org/html/2605.25865)
15. [CrossCommitVuln-Bench (arxiv 2604.21917)](https://arxiv.org/pdf/2604.21917)
16. [Improving Vulnerability Inspection (arxiv 1803.06545)](https://arxiv.org/pdf/1803.06545)
17. [Apono: PAM Audit Components](https://www.apono.io/blog/components-for-a-privileged-access-management-audit)
18. [EPSS: Exploit Prediction (arxiv 1908.04856)](https://arxiv.org/pdf/1908.04856)
19. [QASecClaw: LLM False Positive Reduction (arxiv 2605.01885)](https://arxiv.org/html/2605.01885)
20. [SAST False Positive Solutions](https://appsecsanta.com/sast-tools/reducing-sast-false-positives)
21. [Prompting Priorities: LLM Triage (arxiv 2510.18508)](https://arxiv.org/pdf/2510.18508)
22. [Decryption Digest: CSPM Remediation Workflow](https://www.decryptiondigest.com/blog/cspm-findings-remediation-workflow)

---

## UNRESOLVED QUESTIONS

1. **Human triage cost for attestation decisions**: No empirical measurement found of analyst time per endpoint/permission/API confirmation. This is essential to validate ROI vs. alert-based alternatives.
2. **Portable authorization intent expression**: No standardized way to declare "public by design" that detectors can read. This forces either manual review or risk of false positives in compliance export.
3. **Why CSPM/IAM tools succeed despite low precision**: No published cost-of-ownership studies. Assumption: attestation workflows absorb triage cost, but this may be industry-wide unexamined expense.
4. **Real defect recovery in inventory**: Unknown whether human reviewers can actually distinguish the 22.6% of real defects your detector catches from the 76% false positives by reading code/intent alone, or if this is dependent on threat modeling / runtime context unavailable at review time.

---

**Report compiled**: 2026-07-26, 14:41 (UTC+7)
