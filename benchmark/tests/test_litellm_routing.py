"""Config-only tests for benchmark/litellm-config.yaml. No API key or network needed."""
import pathlib
import yaml

CONFIG_PATH = pathlib.Path(__file__).resolve().parents[1] / "litellm-config.yaml"


def load_config():
    return yaml.safe_load(CONFIG_PATH.read_text())


def model_by_name(config, name):
    for entry in config["model_list"]:
        if entry["model_name"] == name:
            return entry
    raise KeyError(name)


def test_cheap_sast_alias_reads_key_from_env_not_hardcoded():
    entry = model_by_name(load_config(), "cheap-sast")
    params = entry["litellm_params"]
    assert params["model"] == "deepseek/deepseek-chat"
    assert params["api_key"] == "os.environ/DEEPSEEK_API_KEY"
    assert "sk-" not in str(params.values())


def test_embed_alias_is_provider_agnostic_placeholder():
    entry = model_by_name(load_config(), "embed")
    params = entry["litellm_params"]
    assert params["model"].startswith("os.environ/")
    assert params["api_base"] == "os.environ/EMBED_API_BASE"
    assert params["api_key"].startswith("os.environ/")


def test_judge_alias_is_provider_agnostic_placeholder():
    entry = model_by_name(load_config(), "judge")
    params = entry["litellm_params"]
    assert params["model"].startswith("os.environ/")
    assert params["api_key"].startswith("os.environ/")


def test_master_key_never_hardcoded():
    config = load_config()
    assert config["general_settings"]["master_key"] == "os.environ/LITELLM_MASTER_KEY"


def test_budget_enforcement_is_fail_closed_where_it_applies():
    """`fail_closed_budget_enforcement` rejects a budgeted request whose spend cannot
    be verified, rather than letting it through. It binds only for models LiteLLM can
    price: with no pricing entry, spend is recorded as 0 and no cap is ever reached.
    It therefore covers the DeepSeek alias and does nothing for the router's models,
    whose blast radius is bounded by per-key model scoping instead. Asserted
    here so the setting stays on, and named so it stops implying router coverage."""
    config = load_config()
    assert config["general_settings"]["fail_closed_budget_enforcement"] is True


def test_database_url_never_hardcoded():
    config = load_config()
    assert config["general_settings"]["database_url"] == "os.environ/LITELLM_DATABASE_URL"


def test_drop_params_enabled_for_provider_param_incompatibility():
    """DeepSeek rejects OpenAI's strict json_schema response_format; without this,
    any engine requesting structured output hard-fails against DeepSeek (spike finding)."""
    config = load_config()
    assert config["litellm_settings"]["drop_params"] is True


def test_message_body_logging_is_disabled():
    config = load_config()
    assert config["litellm_settings"]["turn_off_message_logging"] is True


def test_virtual_key_info_is_redacted_from_logs():
    config = load_config()
    assert config["litellm_settings"]["redact_user_api_key_info"] is True


# Model identifiers that are allowed to be literals. The guardrail below exists to
# stop a *credential* being pasted into the config; a model id is not a credential,
# and pinning it literally is what makes a run's model recoverable from the config.
# Every entry here must be a model name, never a key. Extend deliberately.
LITERAL_MODEL_IDS = (
    "deepseek/deepseek-chat",
    "openai/cx/gpt-5.6-sol",
    "openai/cx/gpt-5.6-terra",
    "openai/cx/gpt-5.5",
)


def test_no_secret_field_is_a_literal_value():
    """Every api_key must defer to os.environ/, so a missing env var fails loudly at
    LiteLLM startup instead of silently using a hardcoded value. `model` may be a
    literal only if it is an allowlisted model id."""
    config = load_config()
    for entry in config["model_list"]:
        for key, value in entry["litellm_params"].items():
            if key == "api_key":
                assert value.startswith("os.environ/"), \
                    f"{entry['model_name']}.api_key is not env-sourced: {value!r}"
            elif key == "model":
                assert value.startswith("os.environ/") or value in LITERAL_MODEL_IDS, \
                    f"{entry['model_name']}.model is neither env-sourced nor an allowlisted model id: {value!r}"
    assert config["general_settings"]["master_key"].startswith("os.environ/")


def test_no_literal_model_id_looks_like_a_credential():
    """The allowlist is only safe while it holds model ids. A key pasted in here would
    otherwise inherit the exemption that keeps the guardrail above green."""
    for value in LITERAL_MODEL_IDS:
        assert "/" in value and not value.startswith("sk-")
        assert len(value) < 60


ROUTER_ALIASES = ("sast-sol", "sast-terra", "sast-gpt55")


def test_router_aliases_exist_and_are_env_sourced():
    config = load_config()
    for alias in ROUTER_ALIASES:
        params = model_by_name(config, alias)["litellm_params"]
        assert params["api_base"] == "os.environ/ROUTER_API_BASE"
        assert params["api_key"] == "os.environ/ROUTER_API_KEY"
        assert params["model"] in LITERAL_MODEL_IDS


def test_router_aliases_map_to_distinct_models():
    """Two tiers pointed at one model would produce two 'independent' arms of the
    same thing, and nothing downstream would notice."""
    config = load_config()
    models = {model_by_name(config, alias)["litellm_params"]["model"] for alias in ROUTER_ALIASES}
    assert len(models) == len(ROUTER_ALIASES)


def test_router_aliases_force_non_streaming():
    """The router defaults to text/event-stream; Metis cannot parse SSE. Pinned at the
    deployment level so no client can omit it."""
    config = load_config()
    for alias in ROUTER_ALIASES:
        assert model_by_name(config, alias)["litellm_params"]["stream"] is False


def test_frozen_deepseek_arm_is_still_reachable():
    """Renaming or dropping cheap-sast makes the frozen V0 scorecard unreproducible."""
    assert model_by_name(load_config(), "cheap-sast")["litellm_params"]["model"] == "deepseek/deepseek-chat"


def test_dropped_glm_model_is_not_configured():
    """glm/glm-5.2 returned HTTP 429 on 5/5 probes and was dropped."""
    config = load_config()
    assert not any("glm" in str(e["litellm_params"].get("model", "")) for e in config["model_list"])
