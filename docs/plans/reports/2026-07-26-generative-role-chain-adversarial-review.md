# Adversarial review — the E17–E21 generative-role chain (Stage 8, independent)

Date: 2026-07-26
Reviewer role: independent adversarial reviewer. Did not build these instruments.
Target: decision `0027-the-llm-belongs-in-the-generative-role-on-absence-of-control-classes.md`
Method: reproduce every headline first, then attack. No file in the repo was modified except this report.

---

## 0. Reproduction — all five headlines reproduce exactly

Recomputed from the committed artefacts with an independent Fisher/McNemar implementation
(`math.comb`, no SciPy in `rag/.venv`).

| claim | published | I got | verdict |
|---|---|---|---|
| E17 arm A vs clean | 10/60 vs 1/40, p = 0.024 | p = **0.0237** | reproduces |
| E18 arm A vs arm B | 10/60 vs 3/80, p = 0.010 | p = **0.0103** | reproduces |
| E18 arm B vs clean | 3/80 vs 1/40, p = 0.59 | p = **0.5926** | reproduces |
| E19 McNemar paired | 3 lost / 3 gained, p = 0.656 | p = **0.6562** | reproduces |
| E20 A′ vs C | 7/28 vs 3/42, p = 0.042 | p = **0.0418** | reproduces |
| E20 fragility (+1 flag) | p = 0.081 | p = **0.0807** | reproduces |
| E21 sensitivity | 0.167 → 0.183 | 10/60 → 11/60 = **0.1833** | reproduces |

`tests/sast-measurement-test.sh` runs green: **PASS=12 FAIL=0**.
Arm A′ = 7/28 is hardcoded in `run_role_control.py:104`; I independently re-derived it by applying the
`ROLE` regex to E17's stored rows and got **28 files, 7 flagged**. The hardcode is faithful.

The arithmetic is clean. Everything below is about what the numbers are *of*.

---

## CONFIRMED DEFECTS

### C1. The instrument is not deterministic. Measured 30% verdict disagreement on identical inputs at temperature 0. — **CHANGES CONCLUSIONS (E19, E20)**

Nine files sit in both E18's arm B and E20's arm C, and one file in both E17's clean arm and arm C.
Ten files were therefore measured **twice**, with the same prompt, the same frozen classifier, the same
model alias and `temperature=0.0`. Three disagreed:

| file | E18 verdict | E20 verdict |
|---|---|---|
| `realvuln-extremely-vulnerable-flask-app/routes/registration_codes.py` | **flagged** | clean |
| `vc-codex-high-seeded-v2-education-lms-django/lms/views.py` | clean | **non-answer** |
| `vc-codex-high-seeded-v2-legal-case-django/cases/views.py` | **non-answer** | clean |

**3/10 = 30% test–retest disagreement** (binomial 95% CI 7–65%). E21 independently corroborates this from
the other direction: 10 of 19 readable non-answers changed verdict on a single retry — **53%**. The log
reads E21 as "non-answers resolve"; it is more accurately *the instrument is not reproducible*.

Every experiment in the chain assumes determinism, and two of them **depend** on it:

- **E19 reuses E17's original-arm verdicts rather than re-measuring them.** Its preregistration says so
  explicitly: "The original verdicts are already measured (E17, frozen instrument, temperature 0)."
  With a ~30% per-file flip rate, the observed **3 lost / 3 gained** is exactly what pure retest noise
  produces on 53 files with a 0.189 base rate — *independently of whether mutation did anything*.
  E19 therefore cannot distinguish "mutation had no effect" from "the instrument cannot resolve any
  effect". The missing control is the obvious one: re-run the 53 **originals** a second time to establish
  the noise floor, then compare mutated against that. It does not exist.
- **E20 reuses arm A′ from E17 rather than re-running it**, on the same stated justification
  ("deterministic instrument, temperature 0"). At p = 0.042 with a self-reported one-flag flip to 0.081,
  a 30% noise floor is not a footnote.

Grok is served from a batched MoE deployment; `temperature=0` does not buy determinism there. The
assumption is stated in three preregistrations and was never tested, even though the repo already
contained the data to test it.

### C2. `classify_prose` misclassifies real model prose at a measured rate, and the errors concentrate in the flags — **CHANGES E18's arm-B number, not E17's direction**

I re-scored all 222 stored rows and hand-adjudicated every `flagged` row plus every `clean` row
containing security-plus-absence language. Instrumenting the classifier to report its triggering
sentence makes the failures explicit.

**Confirmed false positives** (classifier said `flagged`, the prose says no such thing):

| arm | file | trigger sentence | why it is wrong |
|---|---|---|---|
| E17 arm A | `Insecure_Frameworks/bad_mvc.py` | `AES-CBC unauthenticated + ephemeral KEY.` | "unauthenticated" here is the **cryptographic** term (no MAC). `_INHERENT` treats it as missing authentication. |
| E17 **clean control** | `employees/services.py` | `visible_employees_for as sole entry point — correct IDOR defense` | The model said the control is **present and correct**. This is the *entire* 1/40 clean-arm flag. |
| E18 arm B | `routes/registration_codes.py` | `flash("Not authorized", "error")` | **Quoted source code**, not a finding. `Not ` + `authoriz` is enough. |
| E18 arm B | `app/models/utils.py` | `Fixed IV+CBC leaks patterns, no auth.` | Crypto again — "no auth" = no MAC. |

Two architectural causes:

1. **`_INHERENT` short-circuits before `_PRESENT_OK` is ever consulted** (`run_generative.py:181-184`).
   A sentence containing `idor` or `unauthenticated` is flagged even when it is explicitly reassuring.
   The classifier's own header comment says the pre-registration audit fixed exactly this failure
   ("Access control looks properly implemented here." matched → flagged) — the fix was applied only to
   the `_CONCEPT` branch, and the `_INHERENT` branch still has it.
2. **`_PRESENT_OK` matches `correctly` but not `correct`**, so "correct IDOR defense" is not recognised as
   reassurance even if it reached that check.

**Confirmed false negatives** (real absence-of-control findings scored `clean`), both in arm A:

| file | prose the classifier scored `clean` |
|---|---|
| `.../routers/users.py` | "**Authz hole** `get_user`: managers fetch any user by id. **No property scope.**" |
| `.../routers/messages.py` | "**Access holes:** … no role scope for manager/worker/admin … `create_message`: **no recipient/parent/role checks.**" |

`_CONCEPT` covers `authoriz\w*` — which does **not** match the abbreviation `Authz` — and has no term for
`role`, `permission`, `scope`, `tenant`, or `guard`. The model literally wrote "Authz hole" and was
scored clean.

**Measured rate on real prose:** 4 confirmed errors in 71 engaged E17 verdicts = **5.6%**. But they are
not uniformly distributed: **2 of E17's 11 flags (18%)** and **2 of E18's 3 arm-B flags (67%)** are
classifier artefacts. Flags are the load-bearing events; the error rate that matters is the one on flags.

An 18-probe adversarial set built from realistic security-review phrasings (crypto "unauthenticated",
quoted source, `Authz`, `no role check`, `no permission guard`, "Tenant isolation is not applied")
misclassifies **14/18**. That number is not an estimate of field performance — the probes were chosen to
be hard — but it maps the failure surface, and four of the eighteen phrasings were then found verbatim
in the artefacts.

**Correcting the four confirmed E17/E18 errors moves both results in the claim's favour:**

| comparison | published | hand-corrected |
|---|---|---|
| E17 A vs clean | 10/60 vs 1/40, p = 0.0237 | 11/60 vs **0/40**, p = **0.0024** |
| E17, worst case for the claim | — | 9/60 vs 1/40, p = **0.0385** |
| E18 A vs B | 10/60 vs 3/80, p = 0.0103 | 11/60 vs **1/80**, p = **0.0004** |
| E18 B vs clean | 3/80 vs 1/40, p = 0.59 | 1/80 vs 0/40, p = **0.67** |

So the classifier is demonstrably unreliable and **E17/E18's directions survive anyway** — under every
adjudication I could construct, including the one most hostile to the claim. What does not survive is
the published *specificity* number: **"1 of 40 clean files drew a false absence-class claim"** (decision
0027, evidence table) is wrong. The correct statement is **0 of 40**, and the one flag was the
classifier's error, not the model's.

Two flags (`backend/app/routers/auth.py` in E17, `app/security.py` in E18) **cannot be adjudicated at
all** — the trigger sentence lies beyond the 600-character truncation applied at persist time. See I3.

### C3. E20's arm-composition verification was applied to one arm only, and the arms are asymmetric in exactly the dimension the author identified as decisive — **CHANGES E20's stated fragility (favourably)**

The log records a pre-result check on arm C and draws a specific conclusion from it:

> the 42 files are 28 `views.py`, 10 `routes/*`, 3 `api/*`, 1 `handlers.py` — and **zero `urls.py`**.
> That matters because Django's `urls.py` is routing *configuration*, not handler logic, and would rarely
> contain an authorization check whether or not one was required.

The identical check was never run on arm A′. I ran it:

| arm | `views.py` | `routes/*` | `api/*` | `handlers.py` | **`urls.py` (config)** | other |
|---|---|---|---|---|---|---|
| A′ (n=28) | 14 | 5 | 1 | 0 | **8 (29%)** | 0 |
| C (n=42) | 28 | 7 | 3 | 1 | **0** | 3 |

Arm A′ is **29% routing-configuration files**; arm C is 0%. All eight are non-flags (5 non-answer,
3 clean), so by the author's own reasoning they are dead weight in the numerator's denominator.
Removing them, so both arms mean the same thing by "handler":

- **A′ = 7/20 = 0.350** vs arm C 3/42 = 0.071, **p = 0.0094** (published 0.0418)
- the self-reported fragility largely dissolves: one extra arm-C flag gives **p = 0.0202**, not 0.081.

This is a confirmed defect in the verification, and correcting it **strengthens** E20. It should be
corrected regardless — an asymmetric composition check that happens to bias against the hypothesis is
still an uncontrolled asymmetry.

### C4. The gateway redacts the **request**, so the model was shown mangled source. Undisclosed, and it affects all five experiments. — **RIGOR / limits**

`infra/litellm/guardrails/sentinel_guardrail.py:103-113`, `async_pre_call_hook`, calls
`egress_redaction.redact_request(data)` before the request leaves the host.
`egress_redaction._ASSIGNMENT` (lines 107-115) rewrites any `token|secret|password|api_key|
authorization|cookie` followed by `=` or `:` and its value.

In Python web source those are **ordinary identifiers**, not credentials. The consequence is visible in
the model's own stored replies, which comment on damage to the file it was given:

- `"Auth router dump. Redaction broke syntax (L31, L86, L119, L200–204, L225)."`
- `"Broken redactions. Restore: …"`
- `"Lines 213/223 mangled by redaction."`
- `"Redaction broke 4 lines. Rest fine."`

Measured on the actual corpus files (applying `egress_redaction.redact` directly):

| arm | files with ≥1 redaction | mean redactions/file |
|---|---|---|
| E17 arm A | 37% | 1.15 |
| E17 clean | 32% | 0.82 |
| E18 arm B | 38% | 0.61 |
| E20 arm C | 31% | 0.48 |

Arm A takes the most damage — it is the auth/session-heavy arm — and arm A also has the highest
non-answer rate (33% vs 22.5% clean). The plausible causal chain is: redaction breaks syntax → the model
switches into "repair the file" mode → non-answer or code-quality prose instead of a security verdict.

This **biases against** the hypothesis, so it does not threaten E17/E18/E20's direction. But three
things follow that the log does not say: (a) measured sensitivity of ~19% is a floor, not an estimate of
the model's actual capability; (b) the non-answer rate is partly an artefact of the harness, which
weakens E21's framing of it as model behaviour; (c) E19's mutation operates on *already-mangled* text,
so "surface anonymisation" was layered on top of an uncontrolled surface perturbation.

Nothing in `docs/ai-sast-research-log.md` or decision 0027 mentions inbound redaction.

### C5. The positive control (canary) can pass without the model doing anything — **RIGOR**

`_CANARY_SRC` announces its own planted defects in source comments:
`# no authentication, no ownership check on account_id` and `# no rate limiting and no lockout`.
`classify_prose` is run over the model's reply, and:

```
classify_prose(_CANARY_SRC verbatim)                  -> flagged
classify_prose("Here is the file you sent:\n" + src)  -> flagged
```

A model that merely echoes the file back passes the gate. The canary's stated purpose is to prove "the
harness can surface a blatant absence-class defect"; as written it also passes for a model that has done
no analysis at all. Moving the planted defects out of the comments into pure structure would fix this.

---

## PLAUSIBLE CONCERNS

### P1. E20's positive result is contingent on the `ROLE` regex, which is framework-biased

`ROLE` (`run_role_control.py:37-38`) matches `views.py`, `routes/`, `/api/`, `urls.py`,
`handlers.py`, `controllers/`, `resources.py`, `endpoints.py`. It does **not** match `routers/` — the
standard FastAPI convention — nor the corpus's `*_operations.py` endpoint modules. In arm A that
excludes 18 files that are unambiguously request handlers:

| arm-A subset | n | flagged | rate | median bytes |
|---|---|---|---|---|
| `ROLE`-matched (= arm A′) | 28 | 7 | **0.250** | 3572 |
| excluded `routers/*` | 12 | 1 | 0.083 | 5820 |
| excluded `*_operations.py` | 6 | 0 | 0.000 | 6435 |

**The arm-A handler files that E20's regex excluded flag at 1/18 = 0.056 — statistically
indistinguishable from arm C's 3/42 = 0.071 (p = 0.77).** If those files had been in arm A′ and arm C
had been widened correspondingly, E20 might well have returned null.

The regex is applied consistently to *both* arms, so the published comparison is internally valid — but
it establishes the effect only for Django/Flask-shaped handlers, not for handlers generally, and that
scope limit is not stated. I cannot recompute the widened comparison because the additional arm-C files
were never measured; this needs a re-run, not a re-analysis. Note the partial confound with C6: the
excluded files are also the *large* ones, and large files flag less.

### P2. "Full surface anonymisation" (E19) changes a median of 17% of identifier tokens

Measured over all 53 pairs by re-running `mutate_source.mutate`:

- character similarity original vs mutated: **median 0.806**, mean 0.768
- fraction of identifier tokens changed: **median 0.171**, mean 0.242
- 19/53 files retain ≥1 comment; 5/53 retain ≥1 docstring (both deliberate, per the module docstring)
- 3 files (`urls.py`) change ≤1% of tokens — effectively unmutated

The log's phrasing — "**full** anonymisation", "replacing every identifier, route literal and the
filename should have destroyed most detections" — overstates the intervention. `_PROTECTED`
(`mutate_source.py:38-43`) deliberately preserves `user`, `username`, `password`, `token`, `session`,
`query`, `route`, `methods`, `objects`; decorators and framework calls are preserved by design; and
attribute names are never renamed, so `current_user.id`, `note.user_id`, `is_admin` survive intact.

**I tested whether this dilutes the null and it does not.** Restricting to pairs with a substantive
mutation leaves the paired table unchanged:

| restriction | n | orig | mut | lost | gained | McNemar p |
|---|---|---|---|---|---|---|
| all pairs | 53 | 10 | 10 | 3 | 3 | 0.6562 |
| >1% tokens changed | 50 | 10 | 10 | 3 | 3 | 0.6562 |
| ≥10% tokens changed | 41 | 10 | 10 | 3 | 3 | 0.6562 |

All ten original flags fall in pairs with ≥10% mutation; the near-unmutated `urls.py` files were never
flagged in either condition. **This attack fails** — the concern is with the wording, not the result.
The result's real weakness is C1 (noise floor), not dilution.

Also note one of E19's three "lost by mutation" files is `bad_mvc.py` — which C2 shows was never a real
detection.

### P3. Multiple comparisons — survives Holm, fails Bonferroni, and the family definition is load-bearing

Three confirmatory positive tests across the chain:

| test | raw p | Holm-adjusted | Bonferroni |
|---|---|---|---|
| E18 A vs B | 0.0103 | **0.0309** | 0.0309 |
| E17 A vs clean | 0.0237 | **0.0474** | 0.0711 |
| E20 A′ vs C | 0.0418 | **0.0418** | 0.1254 |

All three survive Holm, but E17 lands at 0.047 — knife-edge. Under Bonferroni, E17 and E20 both fail.
If E16b (p = 0.065) were counted in the family, Holm pushes E17 to 0.071 and the chain's primary result
fails. The repo's defence is legitimate and pre-recorded: E16b is preregistered as **exploratory**, its
files are **disjoint** from E17's (`_already_used()` / `E16_EXCLUDE_ARTEFACT` enforces this in code), and
each experiment declares exactly one primary. I verified the disjointness mechanism exists and is real.
This is a defensible family definition — but it is a *choice*, it is doing real work, and it should be
stated in 0027 rather than left implicit.

Note also that the corrected E17/E18 numbers from C2 (p = 0.0024 / 0.0004) would clear Bonferroni
comfortably.

### P4. Repo clustering — **I attacked this and it holds**

49 distinct repos across E17's 100 files (median 2 files/repo, max 5). Arm A draws from 41 repos, the
clean arm from 26, with 18 shared. The 11 flags are spread across 9 distinct repos — no single repo
dominates.

Cluster bootstrap resampling **repos** (not files), 20,000 draws:

| method | 95% CI on the arm difference | P(diff ≤ 0) |
|---|---|---|
| naive file-level bootstrap | [+0.042, +0.250] | 0.0039 |
| **repo-clustered bootstrap** | **[+0.026, +0.275]** | **0.0075** |

Clustering widens the interval, as expected, and the interval still excludes zero. **Non-independence
does not overturn E17.** This was the attack most likely to succeed and it failed cleanly.

### P5. Arm size imbalance is real, and it runs *against* the finding

Arm A files are systematically larger than the clean controls (median 4473 vs 2920 bytes, 1.5×;
median 113 vs 70 lines). The hypothesis in the review brief was that longer files give the model more to
react to. The data says the opposite:

| stratum (pooled median 4250 bytes) | arm A | clean | Fisher p |
|---|---|---|---|
| small | 8/27 = 0.296 | 1/23 = 0.043 | **0.0223** |
| large | 2/32 = 0.062 | 0/17 = 0.000 | 0.4218 |

Within arm A, **small files flag at 0.296 and large files at 0.062**. Because arm A is the larger arm,
the size imbalance *attenuates* the measured effect. Size-stratified, the effect survives in the small
stratum and is unresolvable in the large one (too few clean-arm flags to test).

Two consequences worth stating: (a) the size confound cannot manufacture E17's result; (b) **the entire
measured effect lives in files under ~4KB**, which is a real generalisation limit — combined with the
14KB truncation cap, this is closer to "the model detects absent controls in short files" than the
unqualified claim. Arm C being the *largest* arm (median 5672) while flagging lowest is consistent with
this and partially confounds P1.

---

## SM1–SM12: which can pass vacuously

The suite is genuinely better than most — several assertions carry explicit negative controls, and SM4's
comment records a previous review catching a tautological version of itself. Four weaknesses:

| test | vacuity |
|---|---|
| **SM9** | asserts `flag_rate < 0.10` where `flag_rate = flagged/n` and `n` **includes non-answers**. A model that stops answering drives the rate to 0 and SM9 passes. It cannot distinguish "mess does not trigger flags" from "the model said nothing". |
| **SM10** | asserts `mcnemar_p >= 0.05` — i.e. asserts a **null**. It passes most easily when the experiment has *least* power; 0 discordant pairs gives p = 1.0 and a green light. It guards `drop < 0.10` too, which is the real content, but the p-value clause rewards weakness. |
| **SM11** | reads `arm_a_prime` from the artefact, which `run_role_control.py:104` **hardcodes as `7, 28`**. `a["rate"]` is 0.250 by construction. The test can never detect a change in, or a defect in the composition of, arm A′ — which is exactly what C3 found. |
| **SM8** | `named("Register 409 leaks email existence", {200}) and not named(..., {307})` passes for *any* two disjoint vocabularies. It proves the regexes differ, not that attribution is correct. |

**The larger gap is what has no test at all.** `classify_prose` is the single point of failure for all
five experiments, and **no SM assertion exercises it**. SM8 guards `names_ground_truth_class` only. Every
defect in C2 would have been caught by a dozen-line table test pinning classifier behaviour on
reassurance prose, quoted source, crypto "unauthenticated", and `Authz`/`role`/`permission` phrasings.

---

## Informational

- **I1. Provenance and refusal handling are sound.** `llm.chat` sends source as `target_derived`, never
  `operator`, and the runner fails closed on a missing gateway credential rather than publishing a zero
  from a dead model. This is the part of the harness I could not break.
- **I2. `E16_EXCLUDE_ARTEFACT` disjointness is real**, not just claimed in prose — `_already_used()`
  filters both arms before sampling. E17 genuinely is an independent replication.
- **I3. Stored responses are truncated at 600 chars *and* passed through `trace.redact_persisted`, but the
  classifier scored the full raw text.** Re-scoring the artefacts reproduces only 218/222 verdicts; 4 rows
  cannot be reproduced from what was persisted, and 2 of those are flags that therefore cannot be
  audited. The protocol's own rule (§9, "never discard what re-analysis needs") is not met. Persist the
  full redacted response, or at minimum the triggering sentence.
- **I4. `main()` in `run_generative.py` retries the canary zero times**; `run_role_control.py` retries up
  to 3 on transport failure. The stricter behaviour is the later one — worth backporting so a network
  blip cannot abort a run and look like a harness failure.
- **I5. E17's artefact reports `flag_rate_vulnerable = 0.25`** (engaged-only denominator) while the log
  and decision 0027 headline `0.167` (ITT). Both are defensible and ITT is the conservative, preregistered
  one — but the artefact and the publication disagree on the same field name, which is a trap for the
  next reader. Engaged-only gives 10/40 vs 1/31, p = 0.0112.

---

## Ranked verdict against decision 0027

**Changes the conclusion:**

1. **C1 (30% retest instability)** — invalidates the reasoning behind E19's headline and undermines E20's
   arm-A′ reuse. 0027 was *narrowed* on the strength of E19 (commit `877946c`). That narrowing is not
   currently supported.
2. **C3 + P1 (E20 arm composition)** — E20's status should not be "STANDS (marginal)". The composition
   correction strengthens it; the handler-definition sensitivity weakens it; the retest noise makes a
   p = 0.042 unreproducible in principle. The honest status is **inconclusive pending a re-run** with both
   arms re-measured under a single, preregistered handler definition.
3. **C2's specificity correction** — decision 0027's evidence table states "1 of 40 clean files drew a
   false absence-class claim". That flag is a classifier artefact. The line should read **0 of 40**.

**Improves rigor without changing the conclusion:**

4. C2's error rate (needs a classifier test and a vocabulary fix), C4 (inbound redaction must be
   disclosed as an instrument limit), C5 (canary), P2 (wording), P3 (state the family definition),
   P5 (state the small-file limit), SM9/SM10/SM11 vacuity, I3.

**Attacks that failed — the chain earned these:**

- Repo clustering does not overturn E17 (P4). The repo-clustered CI still excludes zero.
- File-size confounding cannot manufacture E17; it works against it (P5).
- E19's null is not an artefact of weak mutation (P2) — restricting to heavily mutated pairs is identical.
- Hand-adjudicating every load-bearing flag against the raw prose **strengthens** E17 and E18 rather than
  dissolving them (C2). Under the adjudication most hostile to the claim, E17 is still p = 0.0385.

### Does 0027 survive?

**Its central claim survives. Two of its supporting claims do not, at the strength stated.**

The core finding — *the model flags files containing absence-of-control vulnerabilities at a materially
higher rate than clean controls, on a class where the deterministic engines score a structural zero* —
held against every attack I could construct: repo clustering, size stratification, multiplicity, and
full hand-adjudication of the prose behind every flag. Under hand-correction it gets **stronger**
(p = 0.0024), and the specificity is better than published (0/40, not 1/40). E18's class-specificity
holds and also strengthens (p = 0.0004).

What does not survive: **E19's "surface memorisation excluded"** should be downgraded to *inconclusive*
until the retest noise floor is measured, because its paired design reuses verdicts from an instrument
now shown to flip 30% of the time — and 3-lost/3-gained is exactly what that noise predicts. **E20's
"STANDS (marginal)"** should be downgraded to *inconclusive pending re-run*, on the combination of an
asymmetric arm composition, a framework-biased handler definition under which the excluded arm-A
handlers are indistinguishable from arm C, and the same noise floor sitting under a p = 0.042.

The chain's own norms are what made this review possible: the stored prose, the preregistrations, the
disjointness enforced in code, and the pre-result arm-composition check on arm C. Three of the five
confirmed defects were found *because* those artefacts exist. The one that mattered most — C1 — was
found by cross-referencing two experiments the lab had already run, using data already committed.

### Recommended actions, in order

1. Re-run the 53 E19 originals unchanged to measure the retest noise floor. Report E19's paired
   difference against it. Until then mark E19 inconclusive in the ledger and restore 0027's original
   contamination bound.
2. Re-run E20 with both arms measured in the same session under one preregistered handler definition
   that includes `routers/` and `*_operations.py`, and with `urls.py` excluded from both arms. Mark E20
   inconclusive until then.
3. Add SM12 as a table test over `classify_prose`, pinning: reassurance prose is `clean`
   (including `_INHERENT` sentences), crypto "unauthenticated"/"no auth" is `clean`, and
   `Authz`/`no role check`/`no permission guard`/`no ownership scope` are `flagged`.
4. Fix `classify_prose`: consult `_PRESENT_OK` before `_INHERENT` fires; add `correct` to `_PRESENT_OK`;
   add `authz|role|permission|scope|tenant|guard` to `_CONCEPT`; exclude sentences that are verbatim
   quoted source. Then re-score the stored prose — no new LLM calls needed — and republish.
5. Correct 0027's specificity row to 0/40 and add C4 (inbound gateway redaction) and P5 (effect confined
   to files under ~4KB) to its stated bounds.
6. Persist the full redacted response, not `[:600]`, so every verdict remains auditable.
7. Fix SM9's denominator (report flagged/engaged alongside ITT), drop SM10's `p >= 0.05` clause in favour
   of the interval, and make SM11 recompute arm A′ from the E17 artefact rather than trusting a hardcode.
