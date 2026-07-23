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

from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth

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
    caller who forgets to declare is refused rather than silently trusted. A caller that
    genuinely cannot declare - a vendored third-party tool, for instance - is exempted by
    giving it its own guardrail entry with the flag off, which makes the exemption a
    named, reviewable thing in the config rather than a global weakening.
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
                "key=%s spotlighted=%d redactions=%s",
                _key_fingerprint(user_api_key_dict),
                len(marked),
                _summarise(redactions),
            )
        return data


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
