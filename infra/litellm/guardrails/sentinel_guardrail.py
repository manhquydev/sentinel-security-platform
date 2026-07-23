"""LiteLLM CustomGuardrail wiring for the Sentinel gateway.

This is the thin adapter between LiteLLM's hook interface and the two pure modules that
hold the actual behaviour: provenance labelling/spotlighting and egress secret redaction.
It contains no policy of its own, deliberately - everything testable lives in the pure
modules so the suite runs without the proxy installed.

Order matters and is not arbitrary. Provenance runs first so that spotlighting markers
are already in place when redaction rewrites the text; running redaction first would let
it rewrite content that is about to be wrapped, and a marker inserted into a partially
redacted span is harder to reason about than the reverse. Both run before the request
leaves the host.

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

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth

import egress_redaction
import provenance

METADATA_KEY = "sentinel_provenance"


class SentinelGuardrail(CustomGuardrail):
    """Label provenance, spotlight untrusted spans, and redact secrets on egress.

    Configured in the proxy config as a `pre_call` guardrail. It rejects rather than
    repairs: a request whose provenance declaration is missing or incomplete is refused,
    because the alternative is guessing which content the system may trust.
    """

    def __init__(self, spotlight_mode: str = "auto", **kwargs):
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
        messages = data.get("messages")
        if not isinstance(messages, list):
            # Embeddings and other non-chat calls carry no messages; there is nothing to
            # label. They still pass through redaction below via their own input field.
            return data

        declaration = (data.get("metadata") or {}).get(METADATA_KEY)

        # Raising here is what makes the guardrail fail closed: LiteLLM surfaces the
        # exception to the caller and the upstream request is never issued.
        marked_messages, marked = provenance.apply(messages, declaration, self.spotlight_mode)
        redacted_messages, redactions = egress_redaction.redact_messages(marked_messages)

        data["messages"] = redacted_messages

        # The audit trail records classes and positions, never values. It is written to
        # the proxy log rather than returned to the caller, so a caller cannot use the
        # guardrail as an oracle for what it managed to smuggle in.
        if marked or redactions:
            verbose_proxy_logger.info(
                "sentinel guardrail: key=%s spotlighted=%d redactions=%s",
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
