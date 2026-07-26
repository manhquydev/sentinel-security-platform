"""E16 — the first measurement of the LLM in a GENERATIVE role: propose, tools dispose.

Every AI role this lab has measured (judge, verifier, ranker) is a verdict/gate role the architecture
forbids the model to hold anyway. So "AI loses every comparison" was never tested where AI might
actually help: PROPOSING candidates that deterministic code then verifies.

The opening is decisions 0022-0024: pattern SAST scores ~0% on absence-of-control classes (CWE-307 no
auth-attempt limit, CWE-639 IDOR, CWE-200 info exposure, CWE-862/306 missing authz/authn), because an
absent control writes no token to match. The deterministic baseline there is approximately zero, so any
correct proposal is a net gain rather than a re-discovery.

TWO THINGS THIS DESIGN REFUSES TO FAKE
- **Negative-control files.** Files with ZERO ground-truth vulnerabilities are mixed in
  indistinguishably. Without them, "recall" is uninterpretable: a model that flags everything scores
  perfect recall. The flag rate on clean files is reported next to the recall, always.
- **Provenance.** Source code is content Sentinel does not control, so it is labelled `target-derived`,
  never `operator`. This lab has measured three times (0018, 0020, E11) that hardened models REFUSE to
  reason about target-derived material. If that happens here it is the RESULT, not an obstacle to route
  around by mislabelling the trust span to get an answer.

Scoring uses the committed deterministic matcher (`run_spike.match`: file + CWE + line +/-10,
claim-once). The model never sees ground truth and never marks its own work.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_generative.py
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402
from agent import trace  # noqa: E402

# The absence-of-control classes decisions 0022-0024 measured pattern SAST at ~0% on.
BLIND = {284, 285, 200, 306, 307, 639, 862, 863}
N_POSITIVE = int(os.environ.get("E16_POS", "24"))     # files holding >=1 absence-class vulnerability
N_NEGATIVE = int(os.environ.get("E16_NEG", "16"))     # files holding NO ground-truth vulnerability
MAX_BYTES = 14000                                      # per-file source cap, keeps prompts bounded

_RUBRIC = (
    "You are a security engineer reviewing one source file from a web application. Identify places "
    "where a REQUIRED SECURITY CONTROL IS ABSENT - for example an endpoint with no authorization "
    "check, an object looked up by a user-supplied id without an ownership check, an authentication "
    "endpoint with no rate limiting or lockout, or a response that discloses internal or other users' "
    "data. These are absences, not dangerous function calls, so there may be nothing wrong at all in "
    "this file. Do NOT invent findings to be helpful: reporting nothing is a valid and expected answer. "
    "The file may be truncated; review only what you are given and never ask a question back. "
    "Output ONLY finding lines and nothing else. For each real issue output one line EXACTLY: "
    "FINDING: line=<number> cwe=<number>. If there are none, output exactly: FINDING: none"
)

# A synthetic file with a blatant, textbook absence-of-control defect. A model that cannot flag THIS is
# not being blocked by difficulty or provenance — the harness is broken. Without this canary a prompt
# bug and a genuine negative are indistinguishable, and the first smoke run of E16 proved that: a
# mid-function truncation made the model ask a clarifying question, which scored as recall 0.000 and
# would have been published as "the generative role fails".
_CANARY_SRC = """1: from flask import Flask, request, jsonify
2: app = Flask(__name__)
3:
4: @app.route('/api/account/<account_id>')
5: def get_account(account_id):
6:     # no authentication, no ownership check on account_id
7:     row = db.query("SELECT * FROM accounts WHERE id = ?", account_id)
8:     return jsonify(row)
9:
10: @app.route('/api/login', methods=['POST'])
11: def login():
12:     # no rate limiting and no lockout on repeated failures
13:     u = request.form['user']; p = request.form['password']
14:     return jsonify({'ok': check_password(u, p)})
"""

_RX = re.compile(r"FINDING:\s*line\s*=\s*(\d+)\s+cwe\s*=\s*(?:CWE-)?(\d+)", re.I)

# FILE-LEVEL fallback rubric. Line-level structured output proved unobtainable: five model aliases
# through this gateway (sast-grok45, sast-sol, sast-gpt55, sast-terra, openai-gpt5-mini) all ignored an
# explicit JSON/format instruction AND an assistant prefill, answering with prose findings or a code
# patch instead — while correctly identifying the planted defects. Rather than mislabel provenance or
# tune the prompt against the evaluation files, the question is narrowed to one the models will
# actually answer in a parseable way, and the weaker granularity is reported as a limit.
_BINARY_RUBRIC = (
    "Review the given source file. Question: does it contain a place where a REQUIRED SECURITY CONTROL "
    "IS ABSENT - an endpoint with no authorization check, an object fetched by user-supplied id with no "
    "ownership check, an authentication endpoint with no rate limiting or lockout, no authentication at "
    "all, or a response disclosing internal or other users' data? Many files are perfectly fine; saying "
    "NO is expected and correct for them. Do not invent issues. "
    "Your reply must BEGIN with exactly one word: YES or NO. One line of justification may follow."
)
_YES = re.compile(r"^\W*(yes)\b", re.I)
_NO = re.compile(r"^\W*(no|none)\b", re.I)

# DETERMINISTIC DISPOSAL LAYER.
# The models will not emit structure (see above), but they answer in security prose, and that prose is
# strikingly different between the two arms: vulnerable files draw absence-of-control language, clean
# files draw code-quality chatter, refactors, or a question. So the model PROPOSES in its native form
# and this deterministic classifier DISPOSES — no model is consulted about its own output.
#
# Kept deliberately narrow: only ABSENCE-of-control vocabulary counts. Words like "sql injection" or
# "xss" are presence-class and must NOT count, or the classifier would credit the model for finding the
# very class pattern SAST already covers.
# Absence-class vocabulary, split into two kinds because a bare keyword match is not evidence.
#
# An audit of this classifier, run BEFORE any result was read, found two defects:
#   1. "Access control looks properly implemented here." matched -> flagged. A control being PRESENT
#      was scored as a finding.
#   2. `authoriz\b` could never match "Authorization", because the word continues past the boundary.
# Both are fixed by requiring absence LANGUAGE, not merely security vocabulary.

# Terms that are themselves a defect - no qualifier needed.
_INHERENT = re.compile(
    r"\b(idor|bola|broken (?:object level )?access control|privilege escalation|"
    r"brute.?force|information disclosure|excessive data exposure|"
    r"any(?:one| user| caller)? can (?:read|access|view|modify|delete))\b", re.I)

# "unauthenticated" used to sit in _INHERENT, which made "AES-CBC unauthenticated" — a CRYPTO
# property, i.e. presence-class — score as an absent control. It now needs absence language like
# any other concept.
# Presence-class vocabulary: the class pattern SAST already covers. A sentence about these must never
# count as an absent control merely because it also contains an auth word.
_PRESENCE_CLASS = re.compile(r"\b(aes|cbc|gcm|cipher|crypto|hash|md5|sha1|xss|sql ?injection|sqli|"
                             r"deserial|pickle|command injection|path traversal|hardcoded|"
                             r"ephemeral key|iv)\b", re.I)

# Security concepts that indicate a defect only when something is said to be MISSING.
# Vocabulary derived from the CWE DEFINITIONS of the eight classes under test, not from observed
# misses. E26 showed the model can describe a defect correctly in terms this list did not contain
# (a missing webhook signature verification — CWE-306 "Missing Authentication for Critical Function"),
# so every published sensitivity figure scored by the old list is a floor.
_CONCEPT = re.compile(
    # CWE-284/285/862/863 improper / missing authorization
    r"(access control|authoriz\w*|authz|permission|role check|entitlement|"
    # CWE-306/287 missing authentication for a critical function
    r"authentication|authn|auth\b|signature (?:verif|check|validat)\w*|hmac|signed request|"
    r"webhook (?:secret|signature)|api key check|bearer token check|"
    # CWE-639/IDOR authorization bypass through a user-controlled key
    r"ownership check|owner check|tenant (?:check|scope|isolation)|scope check|object level|"
    # CWE-307 improper restriction of excessive authentication attempts
    r"rate.?limit\w*|throttl\w*|lockout|attempt limit|captcha|"
    # CWE-200 exposure of sensitive information
    r"sensitive (?:data|field|information)|pii\b)", re.I)
_ABSENCE = re.compile(r"(lack\w*|missing|absent|no\s|not\s|without|none|fails? to|does ?n[o\u2019']t|"
                      r"unprotected|unchecked|unenforced|never|any(?:one| user)?\s+can)", re.I)
# Explicitly reassuring language: the control is present and correct.
# Reassurance vocabulary as a CATEGORY, not as a patch for one observed miss: prose asserting the
# control WORKS. E34 found "IDOR blocked" scored as a finding — the model had said the control was
# present. Terms added by category (blocked/prevented/mitigated/guarded/handled), the same way E27
# derived concept terms from CWE definitions rather than from whichever word tripped the run.
_PRESENT_OK = re.compile(r"(\bcorrect\w*|\bproperly\b|\bproper\s|is enforced|are enforced|defen[sc]e|"
                         r"\bblocked\b|\bprevented\b|\bmitigated\b|\bguarded\b|\bscoped\b|"
                         r"sole entry point|"
                         r"looks (?:fine|good|ok)|"
                         r"already (?:enforced|checked)|no issues?|seems (?:fine|ok)|appears (?:fine|ok))",
                         re.I)

_QUESTION_BACK = re.compile(r"(what (?:need|do you want)|state task|send goal|missing ask|"
                            r"which (?:file|task))", re.I)


# Inline code spans and fenced blocks are the model QUOTING source, not the model asserting anything.
# Two confirmed misclassifications came from exactly this: `add \`if not user.is_authenticated\`` and
# `flash("Not authorized", "error")` both supplied the absence word from code the model was suggesting
# or citing, not from its own prose. Absence language must come from what the model SAYS.
_CODE_SPAN = re.compile(r"```.*?```|`[^`]*`|\"[^\"]*\"|'[^']*'", re.S)


def _strip_code(t: str) -> str:
    return _CODE_SPAN.sub(" ", t or "")


def _sentences(t: str):
    return re.split(r"(?<=[.;:!?])\s+|\n+", t)


# Per-CWE vocabulary for CLASS ATTRIBUTION: did the model name the class ground truth actually records
# for this file, or did it flag the file for some unrelated problem? This distinction was decisive —
# it is what withdrew E17's mechanism claim (6 of 10 flags named the ground-truth class, 4 did not) —
# so it lives here with a test rather than as a one-off expression in a shell session.
_CLASS_VOCAB = {
    307: r"rate.?limit|throttl|lockout|brute.?forc",              # no limit on auth attempts
    # "any attorney edits any client", "any logged-in user can send any ..." — the original pattern
    # required the exact words "any user can" and missed every real phrasing of the same finding.
    639: (r"idor|bola|ownership|owner check|any (?:user|one) can|"
          r"any (?:\w+ ){0,3}(?:can|edits|reads|accesses) any"),
    200: r"disclos|leak|exposure|expose|enumerat|reveal",         # information exposure
    # "authz", "no admin gate" and "any <role> hits/edits/reads ..." are how the model actually writes a
    # missing authorization finding; the original vocabulary matched none of them. Widening was validated
    # before adoption: in-ground-truth firing rose 0.123 -> 0.200 while out-of-ground-truth stayed at
    # 0.004, so the gain is concentrated where the class really is.
    862: (r"authoriz|access control|no auth\b|missing auth|authz|no admin gate|"
          r"any (?:\w+ ){0,3}(?:hits|edits|reads|deletes|updates|accesses)"),       # missing authorization
    # CWE-306 "Missing Authentication for Critical Function". The first version of this pattern spelled
    # the concept out in full — "no authentication", "missing authentication" — and matched 0 of 440
    # real responses, because the model writes telegraphically: "no auth", "No admin gate", "Any login
    # marks sent". Every CWE-306 file was therefore uncreditable by construction, which reads as a
    # measured miss and is not one. The terms below come from the CWE's own definition of the condition
    # (the function is reachable with no authentication at all), not from whichever phrasing happened to
    # appear in a run.
    306: (r"unauthenticated|no authentication|missing authentication|without authentication|"
          r"not authenticated|no ?auth\b|no login|anonymous (?:access|user)|"
          r"requires? no (?:auth|login|credential)|unauth\w*|no re-?auth|no api key"),
    284: r"access control|authoriz",
    863: r"authoriz|access control",
    285: r"authoriz|access control",
}


def names_ground_truth_class(text: str, gt_cwes) -> bool:
    """True if the model's prose names a class the ground truth records for this file.

    A file-level flag alone does not show the model found THE vulnerability: a file containing a missing
    ownership check may equally be flagged for an unrelated deserialization bug. Only this stricter
    criterion supports a claim about detecting the class.
    """
    return any(re.search(_CLASS_VOCAB[c], text or "", re.I)
               for c in gt_cwes if c in _CLASS_VOCAB)


# Reassurance the model actually writes when it finds nothing. "No change." was scoring as an ABSENT
# CONTROL: the window "Stock Django auth views + hardened forms. No change." carries an auth concept and
# the absence word "No", so the flag rule fired on a file the model had just called fine. Found by reading
# every flagged response against its ground truth rather than by any guard.
_EXTRA_PRESENT_OK = re.compile(
    r"\bno (?:change|changes|issues?|problems?|action|findings?|concerns?)\b|"
    r"\blooks (?:fine|good|ok|correct)\b|\bnothing (?:wrong|to fix|found)\b", re.I)


def canary_passes(ask, n: int = 3, need: int = 1) -> tuple[bool, list[str]]:
    """Read the positive control `n` times; pass if it fires at least `need` times.

    A single reading was the original design, and it is wrong for this instrument. The canary was measured
    firing on 4 of 5 identical calls at `temperature=0` — the fifth came back as the model echoing the file
    into a code fence, which the classifier correctly reads as clean. So a one-shot control **blocks about
    a fifth of legitimate runs by chance**, which is what it did before this existed.

    `need=1` is deliberate and is not a weakening. The job of this control is to catch a DEAD harness — a
    truncated file, a broken credential, a model answering nothing — and a dead harness scores 0 out of n
    with certainty, however many times it is read. Against a live one, `need=1` fails spuriously with
    probability 0.008 rather than 0.2. Raising the threshold would trade that away for no additional power
    against the failure this is built to detect.

    The tally is returned rather than a bare verdict so a run that passes 1 of 3 leaves a visible record
    of a degraded instrument instead of looking identical to one that passed 3 of 3.
    """
    verdicts = [classify_prose(ask()) for _ in range(n)]
    return sum(v == "flagged" for v in verdicts) >= need, verdicts


def names_class_absence(text: str, cwe: int) -> bool:
    """True if the prose says the control for `cwe` is ABSENT — not merely that the topic came up.

    Bare vocabulary matching conflates two different things. "Rate limiting is applied per IP" and "no
    rate limiting on login" both contain the CWE-307 terms, and an audit found the class patterns firing
    on 3-8% of prose in which the model had concluded the file was fine. That is the regex talking, not
    the model. Requiring the class term and an absence marker to land in the same sentence window — with
    the reassurance test running first, as it does for the file-level verdict — drops firing on all-clear
    prose to zero for every class except CWE-200, whose vocabulary ("disclose", "leak", "expose") stays
    ambiguous enough that it cannot carry an attribution claim at all.
    """
    rx = _CLASS_VOCAB.get(cwe)
    if not rx:
        return False
    sents = _sentences(_strip_code(text or ""))
    for window in sents + [f"{a} {b}" for a, b in zip(sents, sents[1:])]:
        if _PRESENT_OK.search(window) or _EXTRA_PRESENT_OK.search(window):
            continue
        if re.search(rx, window, re.I) and (_ABSENCE.search(window) or _INHERENT.search(window)):
            return True
    return False


def classify_prose(text: str) -> str:
    """flagged | clean | non-answer | file-missing — deterministic rules over the model's own words."""
    if text == "\x00FILE-MISSING":
        return "file-missing"          # never shown to the model; not a negative detection
    t = (text or "").strip()
    if not t:
        return "non-answer"
    if _QUESTION_BACK.search(t[:200]):
        return "non-answer"
    sents = _sentences(_strip_code(t))
    # Terse model prose splits a single thought across sentences — "Authz hole. No property scope."
    # puts the concept in one and the absence word in the next, and a per-sentence scan scored it clean.
    # Adjacent pairs are therefore evaluated as well as single sentences.
    windows = sents + [f"{a} {b}" for a, b in zip(sents, sents[1:])]
    for sent in windows:
        if _EXTRA_PRESENT_OK.search(sent):
            continue
        # The reassurance test runs FIRST for every branch. A review found _INHERENT short-circuiting
        # ahead of it, so "correct IDOR defense" — prose saying the control IS present — scored as a
        # finding. That single error was the whole of E17's 1/40 clean-arm flag.
        if _PRESENT_OK.search(sent):
            continue
        if _INHERENT.search(sent):
            return "flagged"
        # A concept counts only with absence language, and never when the window is really about a
        # presence-class defect (crypto, injection, traversal) that merely mentions an auth word.
        if (_CONCEPT.search(sent) and _ABSENCE.search(sent)
                and not _PRESENCE_CLASS.search(sent)):
            return "flagged"
    return "clean"


def ask_binary(slug: str, relpath: str, model: str, literal_src: str | None = None) -> tuple[bool | None, str]:
    """File-level verdict. Returns (flagged, status); flagged is None when unparseable."""
    from agent import llm

    if literal_src is not None:
        src = literal_src
    else:
        try:
            src = open(os.path.join(rs.REPOS, slug, relpath), encoding="utf-8",
                       errors="replace").read()[:MAX_BYTES]
        except OSError as exc:
            return None, f"unreadable: {exc}"
    body = src if literal_src is not None else "\n".join(
        f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
    try:
        out = llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                        llm.Msg("user", f"file: {relpath}\n\n{body}",
                                llm.target_derived(source="corpus-file", target=slug))],
                       model=model, max_tokens=120, temperature=0.0)
    except Exception as exc:
        return None, f"error: {str(exc)[:80]}"
    t = out.strip()
    if _YES.match(t):
        return True, "answered"
    if _NO.match(t):
        return False, "answered"
    return None, "unparseable"


def _load_gt_index() -> dict:
    """Map (repo, file) -> ground-truth entries, plus the set of files known to hold no vulnerability."""
    index: dict = {}
    for slug in sorted(os.listdir(rs.REPOS)):
        for g in rs.load_gt(slug):
            index.setdefault((slug, g["file"]), []).append(g)
    return index


def _already_used() -> set:
    """Files consumed by a previous run, so a replication can be run on a DISJOINT sample.

    Re-testing the same files would extend an exploratory result rather than replicate it
    independently, and would silently reuse whatever idiosyncrasies that sample had.
    """
    prev = os.environ.get("E16_EXCLUDE_ARTEFACT", "")
    if not prev or not os.path.exists(prev):
        return set()
    try:
        return {(r["repo"], r["file"]) for r in json.load(open(prev, encoding="utf-8"))["rows"]}
    except Exception:
        return set()


def pick_files(seed: int = 5) -> tuple[list[tuple], list[tuple]]:
    """Sample positive files (hold an absence-class vuln) and negative controls (hold nothing)."""
    index = _load_gt_index()
    positives, vulnerable_files = [], set()
    for (slug, f), entries in index.items():
        if any(e["is_vulnerable"] for e in entries):
            vulnerable_files.add((slug, f))
        if any(e["is_vulnerable"] and (e["primary"] in BLIND) for e in entries):
            positives.append((slug, f))

    # Negative controls: real source files from the SAME repos that ground truth never marks vulnerable.
    negatives = []
    for slug in sorted({s for s, _ in positives}):
        repo = os.path.join(rs.REPOS, slug)
        for root, _dirs, files in os.walk(repo):
            if any(p in root for p in (".git", "node_modules", "venv", "__pycache__")):
                continue
            for fn in files:
                if not fn.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(root, fn), repo)
                if (slug, rel) in vulnerable_files:
                    continue
                # Skip trivial files; a 3-line __init__.py is not a meaningful negative control.
                try:
                    if os.path.getsize(os.path.join(root, fn)) < 800:
                        continue
                except OSError:
                    continue
                negatives.append((slug, rel))

    used = _already_used()
    if used:
        positives = [x for x in positives if x not in used]
        negatives = [x for x in negatives if x not in used]
    rnd = random.Random(seed)
    rnd.shuffle(positives)
    rnd.shuffle(negatives)
    return positives[:N_POSITIVE], negatives[:N_NEGATIVE]


def ask(slug: str, relpath: str, model: str, literal_src: str | None = None
        ) -> tuple[list[tuple[int, int]], str]:
    """Ask the model for absence-class candidates in one file. Returns (proposals, status).

    `literal_src` lets the canary travel the EXACT same path as a real file — same prompt, same
    provenance label, same parser — so a passing canary really does prove the harness works.
    """
    from agent import llm

    if literal_src is not None:
        src = literal_src
    else:
        path = os.path.join(rs.REPOS, slug, relpath)
        try:
            src = open(path, encoding="utf-8", errors="replace").read()[:MAX_BYTES]
        except OSError as exc:
            return [], f"unreadable: {exc}"

    # Truncate on a LINE boundary and say so. Cutting mid-statement made the model ask a clarifying
    # question instead of answering, which the harness scored as a non-answer.
    if literal_src is not None:
        numbered = src                      # already line-numbered
    else:
        numbered = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
    try:
        out = llm.chat(
            [llm.Msg("system", _RUBRIC, llm.operator()),
             # Source code is content Sentinel does not control. Labelling it operator to dodge a
             # refusal would corrupt the very contract this project enforces.
             llm.Msg("user", f"file: {relpath}\n\n{numbered}",
                     llm.target_derived(source="corpus-file", target=slug))],
            model=model, max_tokens=400, temperature=0.0)
    except Exception as exc:                       # fail closed: never silently drop a failed call
        return [], f"error: {str(exc)[:80]}"

    props = [(int(m.group(1)), int(m.group(2))) for m in _RX.finditer(out)]
    if props:
        return props, "answered"
    if re.search(r"FINDING:\s*none", out, re.I):
        return [], "answered-none"
    return [], "unparseable"


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print(f"FAIL: corpus not fetched — run {os.path.join(_HERE, 'fetch.sh')}")
        return 2
    if not os.environ.get("LITELLM_MASTER_KEY"):
        print("FAIL: no gateway credential — a zero from a dead model is not a measurement.")
        return 2
    model = os.environ.get("RECON_MODEL", "sast-grok45")

    from agent import llm

    def query(slug: str, relpath: str, literal: str | None = None) -> str:
        if literal is not None:
            body = literal
        else:
            try:
                src = open(os.path.join(rs.REPOS, slug, relpath), encoding="utf-8",
                           errors="replace").read()[:MAX_BYTES]
            except OSError:
                # A file that cannot be read was never shown to the model, so this is NOT a model
                # behaviour and must not be folded into "non-answer" alongside genuine refusals. It
                # inflates the denominator and therefore deflates measured sensitivity. Found in E21:
                # one arm-A entry (`flag.txt`) is listed in ground truth but absent from the corpus.
                return "\x00FILE-MISSING"
            body = "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(src.splitlines()))
        try:
            return llm.chat([llm.Msg("system", _BINARY_RUBRIC, llm.operator()),
                             llm.Msg("user", f"file: {relpath}\n\n{body}",
                                     llm.target_derived(source="corpus-file", target=slug))],
                            model=model, max_tokens=160, temperature=0.0)
        except Exception:
            return ""

    # POSITIVE CONTROL: the classifier and the prompt must together surface a blatant planted defect.
    _ok, _tally = canary_passes(lambda: query("__canary__", "canary.py", literal=_CANARY_SRC))
    print(f"positive control (planted missing-authz + missing-rate-limit): {_tally}")
    canary = "flagged" if _ok else "clean"
    if canary != "flagged":
        print("FAIL: the harness cannot surface a blatant absence-class defect. Any negative result "
              "here would measure the harness, not the hypothesis.")
        return 2

    pos, neg = pick_files()
    print(f"sample: {len(pos)} files with an absence-class vulnerability, {len(neg)} clean controls, "
          f"model={model}\n")

    counts = {"positive": {}, "negative": {}}
    rows = []
    for arm, files in (("positive", pos), ("negative", neg)):
        for slug, relpath in files:
            raw = query(slug, relpath)
            # Score the text that is PERSISTED, not the raw response (protocol section 14). Scoring the
            # raw prose while storing a redacted copy makes the published number impossible for anyone —
            # including us — to re-derive from the committed evidence. This runner kept doing it after the
            # rule was written, and the reproducibility guard caught it on the next fresh pair of runs.
            # Redaction only ever removes characters, so this can suppress a flag and never invent one:
            # the resulting rates are a floor.
            kept = raw if raw == "\x00FILE-MISSING" else trace.redact_persisted(raw[:4000])
            verdict = classify_prose(kept)
            counts[arm][verdict] = counts[arm].get(verdict, 0) + 1
            # Keep the prose. A classifier this new WILL be revised, and re-querying 40 files to
            # re-score would be wasteful and non-reproducible (protocol section 9: never discard what
            # re-analysis needs).
            rows.append({"arm": arm, "repo": slug, "file": relpath, "verdict": verdict,
                         "response": kept})

    def rate(arm):
        c = counts[arm]
        engaged = c.get("flagged", 0) + c.get("clean", 0)
        return c.get("flagged", 0), engaged, (c.get("flagged", 0) / engaged if engaged else None)

    fp_, fe, fr = rate("positive")
    np_, ne, nr = rate("negative")
    print(f"VULNERABLE files: {counts['positive']}")
    print(f"CLEAN controls  : {counts['negative']}")
    print(f"\nflag rate on vulnerable files = {fp_}/{fe}" + (f" = {fr:.2f}" if fr is not None else ""))
    print(f"flag rate on clean controls   = {np_}/{ne}" + (f" = {nr:.2f}" if nr is not None else ""))
    if fr is not None and nr is not None:
        print(f"SEPARATION = {fr - nr:+.2f}  (0 would mean the model flags indiscriminately and the "
              "'detection' is guessing)")
    print("\nGranularity limit: this is FILE-level detection. Line-level structured output could not be "
          "obtained from any of five model aliases, so per-line precision is unmeasured.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": model,
           "granularity": "file-level (line-level unobtainable: see conformance finding)",
           "counts": counts,
           "flag_rate_vulnerable": round(fr, 4) if fr is not None else None,
           "flag_rate_clean": round(nr, 4) if nr is not None else None,
           "separation": round(fr - nr, 4) if (fr is not None and nr is not None) else None,
           "contamination_bound": "RealVuln is public and MIXED provenance: the benchmark records "
                                  "authorship per repo and 26 of 66 are human_authored (704 real "
                                  "vulns), 40 are llm_generated. E59 measured detection HIGHER on the "
                                  "human half (0.519 vs 0.316 union, p=0.062), i.e. no evidence for the "
                                  "feared direction, though confounded by file size. A "
                                  "positive result mixes capability with memorisation and cannot "
                                  "transfer to private code",
           "rows": rows}
    # A re-run must not overwrite the artefact it is meant to be compared against.
    _name = os.environ.get("GENERATIVE_OUT", "generative-260726.json")
    with open(os.path.join(_HERE, _name), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
