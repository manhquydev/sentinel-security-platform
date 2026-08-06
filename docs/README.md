# Documentation Map

Start with the smallest current map. Retrieve compatibility, historical, or
upstream-maintenance material only when the task explicitly needs it.

## Two products

**Charter** and **Workbench** are separate products. Do not use Workbench
artifacts as Charter acceptance evidence, or Charter Juice Shop runs as
Workbench comparative results. Root [`README.md`](../README.md) owns the
operator entry-point tables.

| Product | Authority | Live / local entrypoints |
|---|---|---|
| Charter | [Charter brief](product/sentinel-charter-brief.md), [as-built architecture](sentinel-six-week-as-built-architecture.md) | `scripts/sentinel-live-preflight.sh` → `scripts/sentinel-charter-up.sh` → `scripts/sentinel-demo.sh`; procedure in [live acceptance runbook](operations/sentinel-live-acceptance-runbook.md) |
| Workbench | [Workbench brief](product/sentinel-security-research-workbench.md) | `scripts/workbench-up.sh`, `scripts/workbench-scanner-preflight.sh`, `scripts/workbench-corpus-acquire.py`, `scripts/workbench-corpus-inventory.py`; [demo](operations/sentinel-workbench-demo.md), [scanner viability](operations/workbench-scanner-viability.md) |

Pinned scanner images: [`scanners/image-pins.env`](../scanners/image-pins.env).

## Sentinel

- [Kiến trúc Sentinel sáu tuần (as-built)](sentinel-six-week-as-built-architecture.md):
  luồng hiện có, ranh giới tin cậy và giới hạn bằng chứng live.
- [Charter brief](product/sentinel-charter-brief.md): published product contract
  (goals, scope, safety boundary). Full internship assignment texts stay
  local-only and are not linked from the public map.
- [Báo cáo tuần](reports/index.md): mentor-facing Week 1–3 reports in-repo
  (rendered by `website/` Starlight on Cloudflare).
- [Runbook nghiệm thu live](operations/sentinel-live-acceptance-runbook.md):
  điều kiện vận hành cho một lần chạy local mới, không chứa bí mật.
- [Sentinel Security Research Workbench](product/sentinel-security-research-workbench.md):
  product boundary and current evidence state for the separate local research
  workbench.
- [Workbench B3 preregistration](research/workbench-b3-preregistration.md):
  frozen experimental contract for any future comparative run.
- [Workbench scanner viability](operations/workbench-scanner-viability.md):
  fixture-only B0 admission and current scanner-readiness facts.

## Installed Core

- `WORKFLOW.md`: canonical request, planning, judgment, validation, and
  completion behavior.
- `product/`: consumer-owned product behavior derived from accepted intent.
- `plans/`: one evolving Git-native plan for work that needs durable memory.
- `decisions/`: lasting product and architecture choices.
- `journal/`: chronological record of how work went, including wrong turns. Method, not
  status — never a substitute for the files above.
- `templates/decision.md`: lasting-decision template.
- `templates/exec-plan.md`: durable execution-plan template.

These files are generic Harness structure. They do not select an application
stack, replace a consumer README or architecture, fabricate validation
commands, or require the optional SQLite control-plane lifecycle. The installed
`harness` binary only maintains this core structure.

## Consumer-Owned Truth

The consumer repository's own README, architecture, code, tests, CI, runtime
signals, and application behavior remain authoritative. Harness adds navigation
and working-memory structure around that truth; it does not install upstream
`repository-harness` product documents over it.

## Source-Repository Indexes

The following material is deliberately outside the default installation:

- [Application-legibility plan](https://github.com/hoangnb24/repository-harness/blob/main/docs/plans/active/application-legibility.md): current consumer-first evidence matrix and next gate.
- [Control-plane freeze decision](https://github.com/hoangnb24/repository-harness/blob/main/docs/decisions/0022-control-plane-freeze-and-compatibility-runway.md): current compatibility boundary for SQLite and protocol v1.
- [Optional-consumer ownership decision](https://github.com/hoangnb24/repository-harness/blob/main/docs/decisions/0023-optional-consumer-ownership.md): current ownership split between Harness, Symphony, and consumer applications.
- [Test suite map](https://github.com/hoangnb24/repository-harness/blob/main/tests/README.md): behavior protected by each current, compatibility, and historical test group.
- [CLI compatibility index](https://github.com/hoangnb24/repository-harness/blob/main/docs/compatibility/README.md): SQLite lifecycle, orchestration protocol, bootstrap, schemas, and CLI maintenance.
- [Historical index](https://github.com/hoangnb24/repository-harness/blob/main/docs/provenance/README.md): superseded decisions, story-era evidence, reviews, and migration provenance.
- [Upstream repository](https://github.com/hoangnb24/repository-harness): Rust implementation, installer, release, and maintenance truth.

Selecting the optional CLI profile installs the compatibility material required
to operate that surface. Historical and upstream-only material remains in the
source repository and Git history.
