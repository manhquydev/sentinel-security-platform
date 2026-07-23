# Checks that passed because they checked nothing

Date: 2026-07-23

One session, one recurring failure. It appeared in shipped code, in review tooling, in the
tests written to catch it, and in the verification of those tests. Every instance looked
like success at the moment it mattered.

## The shape

A check reports a pass without having examined the thing it names. Not a wrong answer — no
answer, presented as a right one. Green is the default outcome of a check that never ran,
so nothing about the output distinguishes "verified" from "never looked".

## Where it turned up

**A guardrail bypassed on the route it existed for.** Enforcement read `data["messages"]`
and returned the request untouched when that key was absent, on the reasoning that such
calls carry nothing to redact. The Responses API puts content in `input`; the scanner this
gateway was built for calls the Responses API exclusively. An undeclared prompt carrying
credential-shaped strings returned HTTP 200, produced no audit line, and was persisted to
the trace store in plaintext. The comment explaining the early return was confident and
wrong, and no test exercised a call shape.

**Two suites asserting nothing.** `grep -q` suppressed the output its own pipeline
consumed, so the check after the pipe always saw an empty stream and always passed. A port
pattern matched `"PORT:PORT"` — digits and a colon — while a real all-interfaces binding
carries dots, so `"0.0.0.0:4000"` never matched and the "no port published on all
interfaces" line had never once been capable of failing.

**An ordering assertion that compared a set.** Built on `ast.walk`, which is breadth-first
and therefore does not yield source order. A deliberate reordering of two calls passed it.
Sorting by position turned it into the assertion its name claimed.

**A cross-check that was an identity.** Two totals were reported as corroborating each
other. Both derived from the same list, so they agreed by construction and could not have
disagreed. It was written into a commit message as evidence.

**A false-positive count over an absent corpus.** The measurement corpus is gitignored. On
a fresh clone the harness measured nothing and reported zero structural false positives — a
clean result, indistinguishable from a real one.

**A destructive migration verified against the wrong file.** A wrapper was invoked without
its required output argument, exited early, and the verification read a stale artifact left
by an earlier run. The conclusion drawn was that a correct fix had failed.

**A test that was never written.** A script located an anchor string, replaced it, and
printed a success message. The anchor did not match the file. Nothing was written; the
suite that subsequently "passed" was the original one; and the mutation test run against
the absent assertion found, correctly, that it did not fail.

## What separates the ones that were caught

Every instance was found the same way: something was deliberately broken and the check was
watched. Nothing was found by reading. Reading is what produced most of them.

Two refinements the session forced, both from the last item above:

- **Confirm the mutation applied before believing its result.** A mutation that silently
  fails to apply produces a green suite and the conclusion that the assertion is weak. Both
  the mutation and the restoration need to be observed, not assumed.
- **Make edit tooling refuse rather than report.** A script that cannot find its anchor
  should fail loudly. Printing a success message after changing nothing is the same defect
  as the checks it was being used to add.

## The one that generalises

An adversarial review found the guardrail bypass in minutes by sending a request instead of
reading the code. The bypass had survived a plan, an implementation, a code review, four
mutation-tested suites, and two rounds of self-correction — all of which examined the chat
path, because that was the path the code was written for.

A check inherits the assumptions of whoever wrote it. Mutation testing catches an assertion
that cannot fail; it does not catch an assertion aimed at the wrong thing. That needs
someone adversarial who does not share the assumption, and it needs them to run the system
rather than read it.

## Cost

Four of the session's own verification steps returned wrong answers because of how they
were run, not because of what they examined. Each cost a false report before being caught.
The rate is the finding: when verification is this fragile, an unverified claim should be
treated as unknown rather than probably-fine.

## Related

- [0006 The gateway labels provenance; it does not detect injection](../decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md)
- [0007 A Product is one application](../decisions/0007-a-product-is-one-application-and-benchmarks-leave-the-lake.md) — whose original evidence was itself disproven and corrected in place
- [LiteLLM gateway and observability](../plans/active/2026-07-23-no-issue-litellm-gateway-and-observability.md)
