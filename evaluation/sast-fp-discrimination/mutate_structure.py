"""Structural mutation: reorder top-level definitions, on top of surface anonymisation.

E23 anonymised NAMES and left SHAPES untouched — the limit decision 0027 has carried ever since. This
changes the file's global structure by permuting top-level function and class definitions, which
defeats whole-file recall while leaving every definition's own body byte-identical.

SAFETY, because a reorder can change behaviour:
  - a file qualifies only if it has >=2 top-level definitions and NO non-definition statement sits
    between the first and the last. Module-level assignments, decorated registrations and side-effecting
    calls can all depend on definition order; interleaving means the order is load-bearing.
  - the result must still parse, keep the import set byte-identical, and keep the AST node-type profile.

WHAT THIS DOES NOT DO, stated in the module because it bounds every claim built on it: it does not
change **intra-function control flow**. A model recognising "this is that vulnerable handler" from the
shape of the function body would be unaffected. Only file-level structural recall is tested here.
"""

from __future__ import annotations

import ast
import random

from mutate_source import mutate as surface_mutate, structure_preserved


def _toplevel_defs(tree: ast.Module):
    return [i for i, n in enumerate(tree.body)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def reorderable(src: str) -> bool:
    """True only when permuting top-level definitions cannot change behaviour."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    defs = _toplevel_defs(tree)
    if len(defs) < 2:
        return False
    # Anything that is not a definition sitting between the first and last def makes order load-bearing.
    span = tree.body[defs[0]:defs[-1] + 1]
    return all(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for n in span)


def reorder_defs(src: str, seed: int = 17) -> str | None:
    """Permute the contiguous block of top-level definitions. Returns None if unsafe or unparseable."""
    if not reorderable(src):
        return None
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    defs = _toplevel_defs(tree)
    lo, hi = defs[0], defs[-1] + 1

    lines = src.splitlines(keepends=True)

    def seg(node):
        # end_lineno is 1-based inclusive; decorators sit above the def and belong to it.
        start = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno]) - 1
        return "".join(lines[start:node.end_lineno])

    blocks = [seg(n) for n in tree.body[lo:hi]]
    if len(blocks) < 2:
        return None
    rnd = random.Random(seed)
    order = list(range(len(blocks)))
    for _ in range(8):                       # ensure the permutation actually differs
        rnd.shuffle(order)
        if order != sorted(order):
            break
    else:
        return None

    first_line = min([d.lineno for d in getattr(tree.body[lo], "decorator_list", [])]
                     + [tree.body[lo].lineno]) - 1
    last_line = tree.body[hi - 1].end_lineno
    head = "".join(lines[:first_line])
    tail = "".join(lines[last_line:])
    body = "\n".join(b.rstrip("\n") for b in (blocks[i] for i in order))
    out = head + body + ("\n" if not body.endswith("\n") else "") + tail

    try:
        ast.parse(out)
    except SyntaxError:
        return None
    if not structure_preserved(src, out):    # imports byte-identical + node-type profile unchanged
        return None
    return out


def mutate_full(src: str, seed: int = 17) -> str | None:
    """Surface anonymisation THEN structural reorder. Both must succeed, or the file is excluded."""
    surface = surface_mutate(src)
    if not surface or not structure_preserved(src, surface):
        return None
    reordered = reorder_defs(surface, seed=seed)
    if not reordered:
        return None
    # Final gate against the ORIGINAL: names changed, structure permuted, semantics preserved.
    return reordered if structure_preserved(src, reordered) else None
