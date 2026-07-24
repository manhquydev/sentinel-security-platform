"""Section-aware chunking for security documents.

Markdown (OWASP guidance) is split on headings so a chunk stays within one topic and keeps its
heading path as provenance. Anything else falls back to a paragraph-packed splitter with a
character budget. Structured records (a CVE, a finding) are short and passed through whole by
the caller, not chunked here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_CHARS = 1200  # comfortably within BGE's window; keeps a chunk to one idea


@dataclass
class Chunk:
    section: str | None
    content: str


_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


def chunk_markdown(text: str, max_chars: int = MAX_CHARS) -> list[Chunk]:
    """Split on headings; pack body paragraphs up to max_chars, carrying the heading path."""
    chunks: list[Chunk] = []
    heading_stack: list[str] = []
    buf: list[str] = []
    in_fence = False  # inside a ``` / ~~~ code block, a leading '#' is a comment, not a heading

    def flush():
        body = "\n".join(buf).strip()
        buf.clear()
        if not body:
            return
        section = " > ".join(heading_stack) if heading_stack else None
        for piece in _pack(body, max_chars):
            chunks.append(Chunk(section=section, content=piece))

    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            buf.append(line)
            continue
        m = None if in_fence else _HEADING.match(line)
        if m:
            flush()
            level = len(m.group(1))
            heading_stack[level - 1:] = [m.group(2).strip()]
        else:
            buf.append(line)
    flush()
    return chunks


def _pack(body: str, max_chars: int) -> list[str]:
    """Pack paragraphs into pieces no larger than max_chars, without splitting a paragraph
    unless it alone exceeds the budget."""
    out: list[str] = []
    cur = ""
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para:
            continue
        if len(para) > max_chars:
            if cur:
                out.append(cur)
                cur = ""
            for i in range(0, len(para), max_chars):
                out.append(para[i:i + max_chars])
            continue
        if len(cur) + len(para) + 2 > max_chars:
            if cur:
                out.append(cur)
            cur = para
        else:
            cur = f"{cur}\n\n{para}" if cur else para
    if cur:
        out.append(cur)
    return out
