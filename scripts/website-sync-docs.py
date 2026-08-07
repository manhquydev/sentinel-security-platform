#!/usr/bin/env python3
"""Sync docs/reports into Starlight + public raw/llms surfaces."""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
DOCS_DEST = SITE / "src" / "content" / "docs"
REPORTS_SRC = ROOT / "docs" / "reports"
PUBLIC = SITE / "public"
RAW_DEST = PUBLIC / "raw" / "reports"
SITE_URL = "https://vinsoc.manhquy.id.vn"

# slug without .md, human title, short description (VI)
REPORTS = [
    ("index", "Báo cáo tuần", "Mục lục báo cáo tuần Project Sentinel (VINSOC × VINUNI)"),
    ("week-01", "Tuần 1 — Quét bảo mật nền", "Báo cáo Tuần 1: quét SAST/DAST nền và che secret"),
    ("week-02", "Tuần 2 — Chuẩn hóa và kho tri thức", "Báo cáo Tuần 2: gộp cảnh báo và tra cứu offline"),
    ("week-03", "Tuần 3 — Agent phân tích bảo mật", "Báo cáo Tuần 3: agent phân tích bám bằng chứng (JSONL)"),
]

WEEKLY = [r for r in REPORTS if r[0] != "index"]


def die(msg: str) -> None:
    print(f"website-sync-docs: {msg}", file=sys.stderr)
    raise SystemExit(1)


def yaml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def body_without_h1(text: str) -> str:
    lines = text.splitlines()
    if lines and re.match(r"^#\s+", lines[0]):
        return "\n".join(lines[1:]).lstrip("\n")
    return text


def write_report_page(slug: str, title: str, description: str, source: Path) -> None:
    raw_body = source.read_text(encoding="utf-8")
    body = body_without_h1(raw_body)
    dest = DOCS_DEST / "reports" / f"{slug}.md"
    dest.parent.mkdir(parents=True, exist_ok=True)

    if slug == "index":
        banner = (
            "> **Nguồn cho agent / tải file:** "
            f"[llms.txt]({SITE_URL}/llms.txt) · "
            f"[Markdown mục lục](/reports/index/markdown/) · "
            f"[Raw mục lục](/raw/reports/index.md)\n\n"
        )
    else:
        banner = (
            "> **Xem nguồn:** "
            f"[Markdown](/reports/{slug}/markdown/) · "
            f"[Raw `.md`](/raw/reports/{slug}.md) · "
            f"[llms.txt]({SITE_URL}/llms.txt)\n\n"
        )

    dest.write_text(
        "\n".join(
            [
                "---",
                f"title: {yaml_quote(title)}",
                f"description: {yaml_quote(description)}",
                "---",
                "",
                banner.rstrip(),
                "",
                body.rstrip() + "\n",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {dest.relative_to(ROOT)}")


def write_markdown_view(slug: str, title: str, source: Path) -> None:
    """Starlight page that displays the full Markdown source for reading/copy."""
    raw = source.read_text(encoding="utf-8")
    # Use a long fence so embedded triple-backticks do not break the page.
    fence = "````"
    while fence in raw:
        fence += "`"

    dest = DOCS_DEST / "reports" / slug / "markdown.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    page_title = f"{title} — nguồn Markdown"
    html_link = "/reports/" if slug == "index" else f"/reports/{slug}/"
    raw_link = f"/raw/reports/{slug}.md"

    dest.write_text(
        "\n".join(
            [
                "---",
                f"title: {yaml_quote(page_title)}",
                f"description: {yaml_quote('Nguồn Markdown đầy đủ — đọc / sao chép')}",
                "---",
                "",
                f"Trang HTML: [{title}]({html_link}) · "
                f"[Tải raw]({raw_link}) · "
                f"[llms.txt]({SITE_URL}/llms.txt)",
                "",
                "Nội dung dưới đây là **toàn bộ file Markdown** trong monorepo "
                f"(`docs/reports/{slug}.md`), không qua bước render HTML.",
                "",
                fence + "markdown",
                raw.rstrip(),
                fence,
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {dest.relative_to(ROOT)}")


def write_raw_copies() -> None:
    if RAW_DEST.exists():
        shutil.rmtree(RAW_DEST)
    RAW_DEST.mkdir(parents=True, exist_ok=True)
    for slug, _title, _desc in REPORTS:
        src = REPORTS_SRC / f"{slug}.md"
        if not src.is_file():
            die(f"missing {src}")
        dest = RAW_DEST / f"{slug}.md"
        shutil.copyfile(src, dest)
        print(f"wrote {dest.relative_to(ROOT)}")


def write_llms_txt() -> None:
    """Write UTF-8 llms.txt. Worker enforces Content-Type charset=utf-8."""
    lines: list[str] = [
        "# Project Sentinel — Báo cáo tuần",
        "",
        "> Đồ án 6 tuần (VINSOC × VINUNI). TTS Nguyễn Mạnh Quý. "
        "Tiến độ hiện tại: tuần 1–3 / 6.",
        "",
        f"Site: {SITE_URL}",
        f"Repo: https://github.com/manhquydev/sentinel-security-platform",
        f"llms.txt: {SITE_URL}/llms.txt",
        "",
        "## Trang HTML (đọc trên web)",
        "",
    ]
    for slug, title, desc in REPORTS:
        url = f"{SITE_URL}/reports/" if slug == "index" else f"{SITE_URL}/reports/{slug}/"
        lines.append(f"- [{title}]({url}): {desc}")
    lines.extend(["", "## Nguồn Markdown (xem trên site)", ""])
    for slug, title, _desc in REPORTS:
        lines.append(f"- [{title} — Markdown]({SITE_URL}/reports/{slug}/markdown/)")
    lines.extend(["", "## Raw Markdown (tải / fetch)", ""])
    for slug, title, _desc in REPORTS:
        lines.append(f"- [{title} (raw)]({SITE_URL}/raw/reports/{slug}.md)")
    lines.extend(
        [
            "",
            "## Ghi chú",
            "",
            "- Chỉ publish báo cáo tuần trong allowlist.",
            "- Không có artifact quét thô (`.raw.*`) hay secret trên site.",
            "- File text được phục vụ với `charset=utf-8`.",
            "",
        ]
    )
    dest = PUBLIC / "llms.txt"
    dest.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"wrote {dest.relative_to(ROOT)}")


def write_landing() -> None:
    dest = DOCS_DEST / "index.mdx"
    dest.write_text(
        """---
title: Project Sentinel
description: Báo cáo tuần đồ án Project Sentinel — TTS Nguyễn Mạnh Quý (VINSOC × VINUNI).
template: splash
hero:
  title: Project Sentinel
  tagline: Báo cáo tuần 1–3 / 6 của đồ án bảo mật AI (VINSOC × VINUNI).
  actions:
    - text: Xem báo cáo tuần
      link: /reports/
      icon: right-arrow
      variant: primary
    - text: llms.txt
      link: /llms.txt
      icon: document
      variant: minimal
---

import { Card, CardGrid } from '@astrojs/starlight/components';

## Bắt đầu từ đây

<CardGrid>
  <Card title="Tuần 1" icon="seti:json">
    Quét bảo mật nền, che secret, Juice Shop — [tuần 1](/reports/week-01/).
  </Card>
  <Card title="Tuần 2" icon="seti:db">
    Chuẩn hóa 36 cảnh báo + kho tri thức offline — [tuần 2](/reports/week-02/).
  </Card>
  <Card title="Tuần 3" icon="seti:notebook">
    Agent phân tích bảo mật, báo cáo JSONL bám bằng chứng — [tuần 3](/reports/week-03/).
  </Card>
</CardGrid>

## Nguồn cho agent & tải file

- [`/llms.txt`](/llms.txt) — mục lục chuẩn llms.txt (HTML + Markdown + raw)
- [Xem Markdown](/reports/week-01/markdown/) · [Raw](/raw/reports/week-01.md) (mỗi tuần có cặp tương tự)
- [Mã nguồn monorepo](https://github.com/manhquydev/sentinel-security-platform)

## Ai thực hiện

**TTS Nguyễn Mạnh Quý** · **VINSOC** × **VINUNI**
""",
        encoding="utf-8",
    )
    print(f"wrote {dest.relative_to(ROOT)}")


def main() -> None:
    if not REPORTS_SRC.is_dir():
        die(f"missing {REPORTS_SRC}")
    if not SITE.is_dir():
        die("missing website/")

    # Clean generated docs content dirs (keep other manual pages none)
    for name in ("reports", "product", "architecture", "guides", "reference"):
        path = DOCS_DEST / name
        if path.exists():
            shutil.rmtree(path)
    DOCS_DEST.mkdir(parents=True, exist_ok=True)
    PUBLIC.mkdir(parents=True, exist_ok=True)

    for slug, title, description in REPORTS:
        src = REPORTS_SRC / f"{slug}.md"
        if not src.is_file():
            die(f"missing {src}")
        write_report_page(slug, title, description, src)
        write_markdown_view(slug, title, src)

    write_raw_copies()
    write_llms_txt()
    write_landing()
    print("website-sync-docs: ok")


if __name__ == "__main__":
    main()
