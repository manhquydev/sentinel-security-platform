"""LiteLLM CustomGuardrail wiring for the Sentinel gateway.

This is the thin adapter between LiteLLM's hook interface and the two pure modules that
hold the actual behaviour: egress secret redaction and provenance labelling/spotlighting.
It contains no policy of its own, deliberately - everything testable lives in the pure
modules so the suite runs without the proxy installed.

Order is a safety property, not a preference. Redaction runs FIRST, then spotlighting.
Datamarking replaces whitespace runs with a marker character, and the redactor recognises
an assignment by its `key`, separator and surrounding whitespace - so spotlighting first
turns `token = secret` into `token▁=▁secret`, which the assignment pattern no longer
matches, and the credential reaches the upstream untouched. That was measured, not
reasoned about: an earlier version of this file ran them the other way round on the
argument that marking should precede rewriting, and it leaked. Both halves still run
before the request leaves the host.

Because the order matters this much, both halves live in one guardrail with a fixed
internal sequence rather than two guardrails whose relative order would depend on how
the config happens to be written.

Where the declaration lives: `metadata.sentinel_provenance`. LiteLLM treats `metadata` as
proxy-side data and does not forward it to the upstream provider, which is what this
needs - the declaration is an instruction to the gateway, not a field the model should
see. A top-level custom key would instead depend on `drop_params` to avoid being
forwarded, which is a fragile thing to rest a security boundary on.

See docs/product/guardrail-hook-contract.md for the contract this implements, and
decision 0006 for why there is no injection detector here.
"""

from __future__ import annotations

from typing import Any, Optional, Union

import logging
import sys

try:
    from litellm.caching.caching import DualCache
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.proxy._types import UserAPIKeyAuth
except ImportError:  # pragma: no cover - exercised by the running proxy, not this suite
    # The proxy is deliberately absent from the test environment (see module docstring
    # and the test suite's own header). The class below still needs a base to subclass
    # and names to reference at import time; a running gateway always has the real
    # litellm package, so this fallback is never live outside a test collection run.
    DualCache = Any  # type: ignore[assignment,misc]
    UserAPIKeyAuth = Any  # type: ignore[assignment,misc]

    class CustomGuardrail:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            pass

import egress_redaction
import provenance

METADATA_KEY = "sentinel_provenance"

# The audit trail gets its own logger rather than riding on litellm's.
#
# The first version of this file emitted through `verbose_proxy_logger.info`, and nothing
# was ever written: that logger's effective level is WARNING unless the proxy is started
# in debug mode, so the audit trail documented in the hook contract did not exist in
# practice. An audit record is a security artifact, not a debug line — whether it is
# written must not depend on how verbosely someone happened to start the proxy.
#
# propagate=False keeps these lines out of litellm's own handlers, so redaction counts
# cannot be silenced or duplicated by a change to the proxy's logging configuration.
audit_logger = logging.getLogger("sentinel.guardrail.audit")
if not audit_logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s sentinel-audit %(message)s"))
    audit_logger.addHandler(_handler)
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False


class SentinelGuardrail(CustomGuardrail):
    """Redact secrets on egress, then label and spotlight target-derived content.

    Redaction is unconditional: it needs nothing from the caller and protects this host
    from what it sends to a router that publishes no retention terms.

    Provenance enforcement is `require_provenance`, and it defaults to True so that a
    caller who forgets to declare is refused rather than silently trusted. There is no
    exemption, and none is reachable: LiteLLM refuses to let a caller switch off a
    `default_on` guardrail from the request body - its own guardrail code states the
    restriction exists to prevent callers from disabling guardrails. An earlier version
    of this docstring described a `sentinel-legacy-client` entry as a named, config-level
    exemption for a vendored scanner assumed unable to send a declaration. That entry
    never worked; it only read as though it did, which is worse than not having it, and
    its premise was wrong besides - the caller it was written for has since been taught
    to declare provenance like everything else. A caller that genuinely cannot declare
    must be taught to, not exempted.
    """

    def __init__(self, require_provenance: bool = True, spotlight_mode: str = "auto", **kwargs):
        self.require_provenance = require_provenance
        self.spotlight_mode = spotlight_mode
        self.optional_params = kwargs
        super().__init__(**kwargs)

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Optional[Any] = None,
    ) -> Optional[Union[Exception, str, dict]]:
        # Redaction first, over every text-bearing location the request has - see the
        # module docstring for the ordering, and redact_request for why keying on
        # `messages` alone was a bypass rather than a limitation.
        data, redactions, covered = egress_redaction.redact_request(data)

        messages = data.get("messages")
        declaration = (data.get("metadata") or {}).get(METADATA_KEY)
        marked: list[dict] = []

        if isinstance(messages, list) and messages:
            if self.require_provenance or declaration is not None:
                # Raising is what makes the guardrail fail closed: LiteLLM surfaces the
                # exception to the caller and the upstream request is never issued.
                data["messages"], marked = provenance.apply(
                    messages, declaration, self.spotlight_mode
                )
        elif self.require_provenance:
            # Anything that is not the chat shape is refused rather than forwarded.
            #
            # Schema 1.0 of the provenance contract addresses messages by index, so it
            # cannot describe a Responses-API `input` or a bare `prompt`. The previous
            # behaviour was to return the request untouched, which meant the guardrail
            # was inert on exactly the route this gateway's primary client uses. An
            # unrecognised shape must be a loud failure, not a quiet pass: refusing
            # costs a caller an error, while passing costs an unlabelled prompt sent to
            # a third party and then persisted to the trace store.
            raise provenance.ProvenanceError(
                "request carries no 'messages' array, so its content cannot be labelled "
                f"under provenance schema {provenance.SCHEMA_VERSION} (text was found at: "
                f"{covered or 'nowhere recognised'}); the gateway refuses rather than "
                "forwarding content it cannot account for"
            )

        # The audit trail records classes and positions, never values. It goes to the
        # proxy log rather than back to the caller, so the guardrail cannot be used as an
        # oracle for what a caller managed to smuggle past it.
        if marked or redactions:
            audit_logger.info(
                "key=%s side=request spotlighted=%d redactions=%s",
                _key_fingerprint(user_api_key_dict),
                len(marked),
                _summarise(redactions),
            )
        return data

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> Any:
        """Redact secrets out of a model's response before any callback sees it.

        This closes the gap the pre_call hook cannot: redacting the request protects
        what this host sends outward, but says nothing about what comes back. A model
        asked to analyse target-derived content can quote a header, cookie or token out
        of that content into its answer, and an upstream error can arrive as a raw
        provider error body containing the same. Both were reaching the trace store
        verbatim. `egress_redaction.redact()` is reused unchanged - see the module
        docstring for why credential-shaped content is safe to strip here without
        touching the attack payloads and file hashes this workload is made of; that
        reasoning does not change because the text arrived from the model instead of
        the caller.

        Shapes covered, walked via plain attribute/key lookup so a dict or an
        attribute-bearing response object is handled identically without importing
        litellm's response classes (`redact_response` stays as free of that import as
        `egress_redaction` and `provenance` are, for the same testability reason):

        - Chat completions: `choices[].message.content` and
          `choices[].message.tool_calls[].function.arguments`.
        - The Responses API: `output[]` items of type `message`
          (`content[].text`) and items of type `function_call` (`arguments`).

        Streaming is explicitly NOT covered. LiteLLM never calls this hook on the
        streaming path - a streamed response reaches the caller chunk by chunk through
        a separate iterator hook this guardrail does not implement - so a caller that
        sets `stream: true` bypasses response redaction entirely. `sast-sol`,
        `sast-terra` and `sast-gpt55` pin `stream: false` in their `litellm_params` and
        cannot be made to stream; `cheap-sast` and `judge` do not pin it, so a caller on
        either alias can request a stream and reach the trace store unredacted. Fixing
        that means redacting a live chunk stream in place - a materially different
        problem, since a chunk already delivered to the caller cannot be un-sent and
        redaction there could only ever protect what is stored, not what was already
        read - and is left undone rather than half-done under this hook's name.

        A failure here must not fail the call. By the time this hook runs the model has
        already answered and the upstream request cannot be un-sent either, unlike the
        pre_call hook, which can still refuse before anything leaves this host. Raising
        here would turn a completed, successful answer into an error response over a
        bug in this redaction pass - discarding a real result is worse than one trace
        record whose response side this pass failed to clean. So an exception is caught,
        logged with `redaction_failed=true`, and the response is returned unredacted
        rather than raised; the trade-off is the same one this deployment already makes
        for a Langfuse outage (config.yaml: "the guardrail is the control, the trace is
        the record"), extended to a bug in the guardrail's own response-side pass.
        """
        try:
            response, findings = redact_response(response)
        except Exception:
            audit_logger.exception(
                "key=%s side=response redaction_failed=true; returning the response "
                "unredacted rather than failing a call the model already answered",
                _key_fingerprint(user_api_key_dict),
            )
            return response

        if findings:
            audit_logger.info(
                "key=%s side=response redactions=%s",
                _key_fingerprint(user_api_key_dict),
                _summarise(findings),
            )
        return response


def _get_field(obj: Any, name: str) -> Any:
    """Read one field whether `obj` is a dict or an attribute-bearing object."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _set_field(obj: Any, name: str, value: Any) -> None:
    """Write one field whether `obj` is a dict or an attribute-bearing object."""
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


def _redact_field(obj: Any, name: str, findings: list[dict], where: str) -> None:
    """Redact one string field in place if present, recording where it was."""
    value = _get_field(obj, name)
    if not isinstance(value, str) or not value:
        return
    redacted, found = egress_redaction.redact(value)
    if found:
        _set_field(obj, name, redacted)
        findings.extend({"location": where, **f} for f in found)


def redact_response(response: Any) -> tuple[Any, list[dict]]:
    """Redact every text-bearing location a chat completion or Responses API result
    can carry. Mutates `response` in place (matching how LiteLLM hands the hook a live
    response object, not a copy) and returns it together with the audit entries.

    Kept litellm-free like `egress_redaction` and `provenance`, on the same
    reasoning: this is the part with actual behaviour, and it must stay testable
    without the proxy installed. `sentinel_guardrail`'s own top-level import of
    litellm is guarded for exactly that reason.
    """
    findings: list[dict] = []

    choices = _get_field(response, "choices")
    if isinstance(choices, list):
        for c_index, choice in enumerate(choices):
            message = _get_field(choice, "message")
            if message is None:
                continue
            _redact_field(message, "content", findings, f"choices[{c_index}].message.content")
            tool_calls = _get_field(message, "tool_calls")
            if isinstance(tool_calls, list):
                for t_index, call in enumerate(tool_calls):
                    function = _get_field(call, "function")
                    if function is None:
                        continue
                    where = f"choices[{c_index}].message.tool_calls[{t_index}].function.arguments"
                    _redact_field(function, "arguments", findings, where)

    output = _get_field(response, "output")
    if isinstance(output, list):
        for o_index, item in enumerate(output):
            if _get_field(item, "type") == "function_call":
                _redact_field(item, "arguments", findings, f"output[{o_index}].arguments")
                continue
            content = _get_field(item, "content")
            if isinstance(content, list):
                for ci_index, part in enumerate(content):
                    where = f"output[{o_index}].content[{ci_index}].text"
                    _redact_field(part, "text", findings, where)

    return response, findings


def _key_fingerprint(user_api_key_dict: UserAPIKeyAuth) -> str:
    """Identify the caller without writing its key into a log line."""
    alias = getattr(user_api_key_dict, "key_alias", None)
    if alias:
        return str(alias)
    return getattr(user_api_key_dict, "user_id", None) or "unknown"


def _summarise(redactions: list[dict]) -> dict:
    """Collapse audit entries to class counts, so the log line cannot grow with content."""
    counts: dict[str, int] = {}
    for entry in redactions:
        name = str(entry.get("class", "unknown"))
        counts[name] = counts.get(name, 0) + int(entry.get("count", 1))
    return counts
