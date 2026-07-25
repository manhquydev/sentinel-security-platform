"""Semantics-preserving mutation, to separate CAPABILITY from MEMORISATION.

Every generative-role result in this lab (E16b, E17, E18) rests on RealVuln, which is **public** and
whose repos carry `llm_generated_corpus: true`. A model may therefore be recalling these exact files
rather than reasoning about them, and nothing measured so far can tell those apart. That is the single
largest limit on decision 0027 and the reason it cannot be promised for a client's private code.

The standard mitigation is rephrasing: change every surface cue a memoriser would key on, while leaving
the semantics — and therefore the vulnerability — intact. If the model's detection rate survives, it was
reasoning. If it collapses, it was recall.

What is changed (surface identity):
  - every user-defined function, class, argument and local name -> generic `fn_N` / `Cls_N` / `v_N`
  - route/path string literals -> generic equivalents of the same shape
  - the filename shown in the prompt -> `module.py`

What is deliberately NOT changed (semantics, and therefore the ground truth):
  - control flow, call structure, decorators, imports, framework APIs
  - the ABSENCE of any authorization / ownership / rate-limit check — nothing is added or removed
  - comments (verified separately: only 3 of 60 arm-A files contain vulnerability-announcing comments,
    and only 1 of those was ever flagged, so they are not what the effect rides on)

Imports, builtins, keywords and dunder/framework hooks are never renamed, because renaming those would
change behaviour rather than identity.
"""

from __future__ import annotations

import ast
import builtins
import io
import keyword
import re
import tokenize

_BUILTINS = set(dir(builtins))
# Framework hooks and Django/Flask/FastAPI attribute names whose spelling is load-bearing.
_PROTECTED = {
    "self", "cls", "request", "response", "args", "kwargs", "Meta", "model", "fields", "queryset",
    "serializer_class", "permission_classes", "authentication_classes", "app", "db", "session",
    "objects", "id", "pk", "user", "username", "password", "email", "token", "get", "post", "put",
    "delete", "patch", "filter", "all", "first", "commit", "add", "query", "route", "methods",
}


def _renameable(src: str) -> set[str] | None:
    """User-defined names that can be renamed without changing behaviour, or None if unparseable."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    names: set[str] = set()
    imported: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            # Protect the BOUND name and every MODULE-PATH segment. A validation run caught
            # `from django.core.paginator import Paginator` becoming `django.core.v_21`, because
            # `paginator` was also a local name elsewhere in the file. That is not an anonymisation,
            # it is a broken import — and the AST node-count check could not see it, since an
            # ImportFrom is still an ImportFrom.
            mod = getattr(n, "module", None)
            if mod:
                imported.update(mod.split("."))
            for a in n.names:
                imported.update(a.name.split("."))
                if a.asname:
                    imported.add(a.asname)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(n.name)
            names.update(a.arg for a in n.args.args)
        elif isinstance(n, ast.ClassDef):
            names.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
    return {x for x in names
            if x not in imported and x not in _BUILTINS and x not in _PROTECTED
            and not keyword.iskeyword(x) and not x.startswith("__") and len(x) > 2}


# Route-ish literals: '/api/account/<id>', '/users/{user_id}' ... keep the SHAPE, drop the identity.
_ROUTE = re.compile(r"^(/[A-Za-z0-9_\-/<>{}:.]*)$")


def _generic_route(lit: str) -> str:
    parts = []
    for i, seg in enumerate(lit.strip("/").split("/")):
        if not seg:
            continue
        if seg.startswith(("<", "{")):
            parts.append(seg)                      # keep the parameter marker: it is semantics
        else:
            parts.append(f"seg{i}")
    return "/" + "/".join(parts)


def mutate(src: str) -> str | None:
    """Return the surface-anonymised source, or None if it cannot be parsed or re-tokenised."""
    names = _renameable(src)
    if names is None:
        return None

    mapping: dict[str, str] = {}
    for i, n in enumerate(sorted(names)):
        first = n[0]
        kind = "Cls" if first.isupper() else "fn" if "_" in n else "v"
        mapping[n] = f"{kind}_{i}"

    out: list[tokenize.TokenInfo] = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None

    for tok in toks:
        t = tok
        if tok.type == tokenize.NAME and tok.string in mapping:
            t = tok._replace(string=mapping[tok.string])
        elif tok.type == tokenize.STRING:
            raw = tok.string
            q = raw[0]
            body = raw.strip("\"'")
            if _ROUTE.match(body) and "/" in body:
                t = tok._replace(string=f"{q}{_generic_route(body)}{q}")
        out.append(t)

    try:
        mutated = tokenize.untokenize(out)
    except ValueError:
        return None
    # Fail closed: a mutation that no longer parses is not semantics-preserving.
    try:
        ast.parse(mutated)
    except SyntaxError:
        return None
    return mutated


def structure_preserved(original: str, mutated: str) -> bool:
    """Cheap structural equivalence check: same shape of code, different names.

    Compares counts of the node types that carry the semantics this experiment depends on. If a rename
    silently dropped a branch or a call, the vulnerability might have moved and the comparison would be
    meaningless.
    """
    try:
        a, b = ast.parse(original), ast.parse(mutated)
    except SyntaxError:
        return False
    # Imports must survive BYTE-IDENTICAL. Node counts alone cannot detect a corrupted module path,
    # which is exactly the defect this check was added to catch.
    def imports_of(tree):
        out = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                out.append(("import", tuple(sorted((x.name, x.asname) for x in n.names))))
            elif isinstance(n, ast.ImportFrom):
                out.append(("from", n.module, tuple(sorted((x.name, x.asname) for x in n.names))))
        return sorted(map(str, out))
    if imports_of(a) != imports_of(b):
        return False

    interesting = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While,
                   ast.Call, ast.Return, ast.Try, ast.Assign, ast.Compare)
    def profile(tree):
        c: dict[str, int] = {}
        for n in ast.walk(tree):
            if isinstance(n, interesting):
                c[type(n).__name__] = c.get(type(n).__name__, 0) + 1
        return c
    return profile(a) == profile(b)
