"""Read-only TypeScript dependency graph extraction from sealed snapshots."""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .sealed_store import SealedFixtureStore


_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")
_IMPORT_RE = re.compile(
    r"""\bimport\s+(?:type\s+)?(?:(?:[\w*$,\s{}]+?)\s+from\s+)?(?P<quote>['"])(?P<specifier>[^'"]+)(?P=quote)"""
)
_EXPORT_RE = re.compile(
    r"""\bexport\s+(?:type\s+)?(?:[\w*$,\s{}]+?)\s+from\s+(?P<quote>['"])(?P<specifier>[^'"]+)(?P=quote)"""
)
_DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*(?P<argument>[^)\n]+?)\s*\)""")
_ROUTE_RE = re.compile(
    r"""\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(\s*(?P<quote>['"])(?P<route>[^'"]+)(?P=quote)"""
)
_CALL_RE = re.compile(r"""\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\((?P<arguments>[^;\n]*)\)""")
_AUTH_RE = re.compile(
    r"""\b(?P<name>(?:require|verify|check)[A-Z][A-Za-z0-9_]*|[A-Za-z0-9_]*(?:auth|authenticate|authorization)[A-Za-z0-9_]*)\b""",
    re.IGNORECASE,
)
_PROCESS_ENV_RE = re.compile(
    r"""\bprocess\.env(?:\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)|\[\s*['"](?P<bracket>[A-Za-z_][A-Za-z0-9_]*)['"]\s*\])"""
)
_CONFIG_GET_RE = re.compile(
    r"""\b(?:config|env)\.get\s*\(\s*['"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['"]\s*\)"""
)


@dataclass(frozen=True, order=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    resolution: str


@dataclass(frozen=True)
class TypeScriptGraph:
    snapshot_id: str
    edges: tuple[GraphEdge, ...]

    @property
    def unknown_edges(self) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self.edges if edge.resolution == "unknown")


def extract_typescript_graph(store: SealedFixtureStore, snapshot_id: str) -> TypeScriptGraph:
    """Extract graph metadata from a verified sealed copy, never an input path."""
    snapshot = store.resolve(snapshot_id)
    files = sorted(
        path.relative_to(snapshot.root).as_posix()
        for path in snapshot.root.rglob("*")
        if path.is_file() and path.suffix in _SOURCE_SUFFIXES
    )
    edges: set[GraphEdge] = set()
    file_set = set(files)
    for relative in files:
        text = (snapshot.root / relative).read_text(encoding="utf-8")
        source = _strip_comments(text)
        edges.update(_import_edges(relative, source, file_set))
        edges.update(_route_auth_config_edges(relative, source))
    return TypeScriptGraph(snapshot.snapshot_id, tuple(sorted(edges)))


def _import_edges(source_path: str, source: str, files: set[str]) -> set[GraphEdge]:
    edges: set[GraphEdge] = set()
    for matcher in (_IMPORT_RE, _EXPORT_RE):
        for match in matcher.finditer(source):
            specifier = match.group("specifier")
            target = _resolve_specifier(source_path, specifier, files)
            edges.add(GraphEdge(source_path, target or specifier, "import", "resolved" if target else "unknown"))
    for match in _DYNAMIC_IMPORT_RE.finditer(source):
        argument = match.group("argument").strip()
        literal = re.fullmatch(r"""['"]([^'"]+)['"]""", argument)
        target = literal.group(1) if literal else "<dynamic>"
        edges.add(GraphEdge(source_path, target, "import", "unknown"))
    return edges


def _route_auth_config_edges(source_path: str, source: str) -> set[GraphEdge]:
    edges: set[GraphEdge] = set()
    for match in _ROUTE_RE.finditer(source):
        edges.add(GraphEdge(source_path, f"route:{match.group('route')}", "route", "resolved"))
    for match in _CALL_RE.finditer(source):
        for auth in _AUTH_RE.finditer(match.group("arguments")):
            name = auth.group("name")
            edges.add(GraphEdge(source_path, f"auth:{name}", "auth", "resolved"))
    for match in _PROCESS_ENV_RE.finditer(source):
        edges.add(GraphEdge(source_path, f"config:{match.group('name') or match.group('bracket')}", "config", "resolved"))
    for match in _CONFIG_GET_RE.finditer(source):
        edges.add(GraphEdge(source_path, f"config:{match.group('name')}", "config", "resolved"))
    return edges


def _resolve_specifier(source_path: str, specifier: str, files: set[str]) -> str | None:
    if not specifier.startswith("."):
        return None
    candidate = posixpath.normpath(str(PurePosixPath(source_path).parent / specifier))
    if candidate == ".." or candidate.startswith("../"):
        return None
    possibilities = [candidate, *(candidate + suffix for suffix in _SOURCE_SUFFIXES)]
    possibilities.extend(f"{candidate}/index{suffix}" for suffix in _SOURCE_SUFFIXES)
    return next((possible for possible in possibilities if possible in files), None)


def _strip_comments(source: str) -> str:
    """Remove comments without mistaking comment-like string content for a comment."""
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index < len(source) - 1 and not (source[index] == "*" and source[index + 1] == "/"):
                if source[index] in "\r\n":
                    output.append(source[index])
                index += 1
            index = min(index + 2, len(source))
            continue
        output.append(char)
        index += 1
    return "".join(output)
