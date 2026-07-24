# A configured interface is not a working one

Date: 2026-07-24

Building Weeks 3 and 4 on top of the existing gateway, twice I nearly built on an interface that
was present, wired, named — and dead. Both times the tell was the same, and both times a single
live probe before writing any code turned a wrong architecture into the right one. Decisions 0011
and 0012 record *what* the interfaces do; this records the *method*, because the decisions cannot.

## The embedding endpoint that was a chat model

Week 3 needed embeddings. The stack already had a LiteLLM `embed` alias, `EMBED_MODEL`,
`EMBED_API_KEY`, `EMBED_API_BASE` — all set. The obvious move was to route RAG embeddings through
it. A comment in the config even warned it might be "unusable," but a warning comment is easy to
read past when the variables are all populated and the alias is right there in `model_list`.

One curl to `/v1/embeddings` ended it: `EMBED_MODEL` was `…/gemini-3.5-flash-low` — a **chat**
model, which has no embedding output — and the gateway's provenance guardrail refused the request
outright because it carried no `messages` array. Two independent reasons the path could never
work, neither visible from the config. Had I trusted the presence of the vars, Week 3 would have
been built around an endpoint that returns no vectors, discovered only when the first similarity
query came back empty. Instead the RAG plane got its own local embedder (fastembed, decision 0011).

## The chat gateway that refused to speak unlabelled

Week 4's agent needed chat completions. The gateway was up and healthy, the `sast-*` aliases were
listed, `curl /v1/chat/completions` looked like a plain OpenAI call. It returned **500 —
"request carries no sentinel_provenance declaration"**. The gateway is fail-closed on the Week-1
provenance contract: every message must be labelled operator or target-derived, or the request
dies. That is not a bug to work around — it is the injection boundary, and it meant the agent's
model client had to *speak the contract* (label every finding, chunk, and target response as
untrusted) rather than wrap a naive call. Reading the frozen contract
(`guardrail-hook-contract.md`) before writing the client turned a boundary I would have fought
into the boundary I built on.

## The tell, and the rule

Each time, the symptom was identical: **I could name the interface but had not exercised it.** The
`embed` alias, the chat endpoint — both were legible, both looked callable, both were listed in
config I had read. Legibility is not liveness. A populated environment variable proves someone
intended a wiring, not that the wiring carries current.

The rule this leaves: before building a layer on an existing interface, send it one real request
and read the real response. It costs one curl and it is the difference between designing around
what the system does and designing around what its config claims. The same discipline that made
Week-1's "checks that checked nothing" a recurring lesson applies to interfaces: an interface you
have only read is an interface you have only assumed.
