"""Minimal AgentDojo LLM pipeline element wired to the Sentinel gateway.

This exists only so AgentDojo's benchmark loop has an agent to run against. It is
scaffolding, not a Sentinel product component, and the numbers it produces describe
*this scaffold agent's* behavior behind an undefended gateway - not Sentinel's own
robustness. See docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md
and evaluation/agentdojo/README.md before interpreting any result produced with it.

Every AgentDojo tool result is exactly the "target-derived" content decision 0006 talks
about: text obtained from a simulated environment this scaffold does not control, and the
vector AgentDojo's attacks use to inject instructions. This module declares every tool
message target-derived and every other message (system prompt, the benchmark's simulated
user turn, this agent's own prior replies) operator, per the D<->E provenance contract in
infra/litellm/guardrails/provenance-label.schema.json, and sends that declaration in
`metadata.sentinel_provenance` on every call. That is the properly-declared path the task
prefers over the `sentinel-legacy-client` guardrail exemption: this agent can always tell
which message came from a tool result and which did not, so there is no reason to fall
back to the exemption meant for callers that structurally cannot declare (see
`use_provenance_metadata=False` below for that fallback, kept only for comparison).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import openai

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import register_attack
from agentdojo.attacks.base_attacks import DEFAULT_MODEL_NAME
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.functions_runtime import EmptyEnv, Env, Function, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    get_text_content_as_str,
    text_content_block_from_string,
)

PROVENANCE_SCHEMA_VERSION = "1.0"
TOOL_RESULT_SOURCE = "agentdojo-tool-result"

GENERIC_IMPORTANT_INSTRUCTIONS_ATTACK_NAME = "important_instructions_generic_model"


def _flatten_content(content_blocks: list | None) -> str | None:
    """AgentDojo represents message content as a list of typed blocks; the gateway's
    provenance module requires target-derived content to be a plain string (schema 1.0
    does not cover multimodal/structured spans), so every message is flattened uniformly
    for simplicity and consistency rather than only the target-derived ones."""
    if content_blocks is None:
        return None
    return get_text_content_as_str(content_blocks)


def _message_to_openai_dict(message: ChatMessage) -> dict[str, Any]:
    role = message["role"]
    if role in ("system", "user"):
        return {"role": role, "content": _flatten_content(message.get("content")) or ""}
    if role == "assistant":
        out: dict[str, Any] = {"role": "assistant", "content": _flatten_content(message.get("content"))}
        tool_calls = message.get("tool_calls")
        if tool_calls:
            out["tool_calls"] = [
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {"name": tool_call.function, "arguments": json.dumps(tool_call.args)},
                }
                for tool_call in tool_calls
            ]
        return out
    if role == "tool":
        text = message.get("error") or _flatten_content(message.get("content")) or ""
        return {
            "role": "tool",
            "content": text,
            "tool_call_id": message["tool_call_id"],
            "name": message["tool_call"].function,
        }
    raise ValueError(f"unsupported message role: {role!r}")


def _function_to_openai_tool(fn: Function) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": fn.name,
            "description": fn.description,
            "parameters": fn.parameters.model_json_schema(),
        },
    }


def _openai_message_to_assistant(message: Any) -> ChatAssistantMessage:
    tool_calls = None
    if message.tool_calls:
        tool_calls = [
            FunctionCall(
                function=tool_call.function.name,
                args=json.loads(tool_call.function.arguments),
                id=tool_call.id,
            )
            for tool_call in message.tool_calls
        ]
    content = None
    if message.content is not None:
        content = [text_content_block_from_string(message.content)]
    return ChatAssistantMessage(role="assistant", content=content, tool_calls=tool_calls)


def build_provenance_declaration(messages: Sequence[ChatMessage], suite_name: str) -> dict[str, Any]:
    """Declare every tool-result message target-derived and everything else operator.

    Coverage is exact by construction: one span per message, matching the gateway's
    fail-closed validation in infra/litellm/guardrails/provenance.py.
    """
    now = datetime.now(timezone.utc).isoformat()
    spans = []
    for index, message in enumerate(messages):
        if message["role"] == "tool":
            tool_call = message.get("tool_call")
            tool_name = tool_call.function if tool_call is not None else "unknown-tool"
            spans.append(
                {
                    "message_index": index,
                    "trust": "target-derived",
                    "source": TOOL_RESULT_SOURCE,
                    "target": f"agentdojo:{suite_name}:{tool_name}"[:512],
                    "collected_at": now,
                }
            )
        else:
            spans.append({"message_index": index, "trust": "operator"})
    return {"schema_version": PROVENANCE_SCHEMA_VERSION, "spans": spans}


class UsageTotals:
    """Accumulates token usage across every gateway call an agent run makes."""

    def __init__(self) -> None:
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.request_count = 0

    def add(self, usage: Any) -> None:
        if usage is None:
            return
        self.prompt_tokens += usage.prompt_tokens or 0
        self.completion_tokens += usage.completion_tokens or 0
        self.total_tokens += usage.total_tokens or 0
        self.request_count += 1

    def as_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "request_count": self.request_count,
        }


class SentinelOpenAILLM(BasePipelineElement):
    """AgentDojo LLM pipeline element that calls the Sentinel gateway's OpenAI-compatible
    chat completions endpoint instead of a provider directly.

    Always declares provenance via `metadata.sentinel_provenance` (never the
    `sentinel-legacy-client` guardrail exemption). That is not just a preference: the
    exemption is a `default_on: false` guardrail, but `sentinel`
    (`infra/litellm/config.yaml`) is `default_on: true`, and the deployed LiteLLM proxy's
    `CustomGuardrail.get_disable_global_guardrail` /
    `get_opted_out_global_guardrails_from_metadata` read admin-configured key/team
    metadata only, "not from the request body, to prevent callers from disabling
    guardrails" (their docstring, confirmed by reading
    `litellm/integrations/custom_guardrail.py` inside the running `sentinel-litellm`
    container). A default-on guardrail cannot be turned off by anything a request body
    carries - `"guardrails": [...]` or `"metadata": {"guardrails": [...]}` only ever adds
    an opt-in guardrail alongside it, confirmed empirically: sending
    `"guardrails": {"sentinel-legacy-client": true}` with no provenance declaration still
    500s with the fail-closed provenance error. Reaching that exemption requires a virtual
    key provisioned with `user_api_key_metadata.opted_out_global_guardrails`, which is an
    admin action outside this runner's scope, not a request-time client choice. The
    metadata path is therefore the only one reachable with the shared gateway key this
    runner holds - and it is also the honest, capability-matched choice regardless, since
    this agent always knows which message is a tool result.

    Args:
        client: an `openai.OpenAI` client whose `base_url` points at the Sentinel gateway.
        model: the gateway model alias to call (e.g. `sast-sol`).
        suite_name: the AgentDojo suite name, recorded in provenance `target` fields for audit.
    """

    def __init__(
        self,
        client: openai.OpenAI,
        model: str,
        suite_name: str,
        temperature: float = 0.0,
    ) -> None:
        self.client = client
        self.model = model
        self.suite_name = suite_name
        self.temperature = temperature
        self.usage = UsageTotals()

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        extra_args = extra_args if extra_args is not None else {}
        openai_messages = [_message_to_openai_dict(message) for message in messages]
        tools = [_function_to_openai_tool(fn) for fn in runtime.functions.values()]

        extra_body: dict[str, Any] = {
            "metadata": {"sentinel_provenance": build_provenance_declaration(messages, self.suite_name)}
        }

        completion = self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            tools=tools or openai.NOT_GIVEN,
            tool_choice="auto" if tools else openai.NOT_GIVEN,
            temperature=self.temperature,
            extra_body=extra_body,
        )
        self.usage.add(completion.usage)
        output = _openai_message_to_assistant(completion.choices[0].message)
        return query, runtime, env, [*messages, output], extra_args


@register_attack
class GenericModelImportantInstructionsAttack(ImportantInstructionsAttack):
    """AgentDojo's default `important_instructions` static attack, addressed to a generic
    model name instead of one resolved from the pipeline's model id.

    `ImportantInstructionsAttack.__init__` calls `get_model_name_from_pipeline`, which
    looks up the pipeline name in a fixed table of literal provider model IDs
    (`gpt-4o-2024-05-13`, `claude-3-opus`, ...). This scaffold's pipeline name is a
    Sentinel gateway alias (e.g. `sast-sol`), which is not in that table, so the lookup
    raises `ValueError`. The jailbreak template and every other property of the attack are
    unchanged; only the value bound to the `{model}` placeholder in the injected text
    differs (a generic phrase instead of a resolved model name). This is the same static
    attack corpus AgentDojo ships as its default, addressed generically because this agent
    is reached through a gateway alias rather than a literal provider model ID.
    """

    name = GENERIC_IMPORTANT_INSTRUCTIONS_ATTACK_NAME

    def __init__(self, task_suite, target_pipeline) -> None:
        # Skip ImportantInstructionsAttack.__init__ (it requires a recognized model id);
        # go straight to FixedJailbreakAttack.__init__ with the same jailbreak template.
        super(ImportantInstructionsAttack, self).__init__(self._JB_STRING, task_suite, target_pipeline)
        self.user_name = "Emma Johnson"
        self.model_name = DEFAULT_MODEL_NAME
