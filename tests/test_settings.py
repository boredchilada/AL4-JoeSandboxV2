"""Service settings and submission options: bad values never break start(), every knob takes effect."""
# ruff: noqa: F811

import os
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

HERE = Path(__file__).resolve().parent
os.environ["SERVICE_MANIFEST_PATH"] = str(HERE.parent / "service_manifest.yml")

import jbxapi  # noqa: E402

from joesandboxv2 import service as svc  # noqa: E402
from joesandboxv2 import settings  # noqa: E402
from tests.test_service import FINISHED, Client, clock, make_request, run, service, titles  # noqa: E402,F401

MANIFEST = yaml.safe_load((HERE.parent / "service_manifest.yml").read_text())
TIMEOUT = MANIFEST["timeout"]
CONFIG_NOT_NUMERIC = ("api_key", "api_url", "report_url")


def started(**config):
    instance = svc.JoeSandboxV2({"api_key": "k", **config})
    instance.start()
    return instance


# -- defaults ---------------------------------------------------------------------------------


def test_manifest_config_defaults_equal_code_defaults():
    config = MANIFEST["config"]
    assert config["api_url"] == svc.DEFAULT_API_URL
    assert config["report_url"] == svc.DEFAULT_REPORT_URL
    assert config["api_key"] == ""
    assert set(config) - set(CONFIG_NOT_NUMERIC) == set(svc.DEFAULTS)
    for name, default in svc.DEFAULTS.items():
        assert config[name] == default, name


def test_missing_config_keys_use_manifest_defaults():
    instance = started()
    assert instance.submission_timeout == MANIFEST["config"]["submission_timeout"]
    assert instance.poll_interval == MANIFEST["config"]["poll_interval"]
    assert instance.quota_cooldown_seconds == MANIFEST["config"]["quota_cooldown_seconds"]
    assert instance.http_timeout == MANIFEST["config"]["timeout"]
    assert instance.retries == MANIFEST["config"]["retries"]
    assert instance.systems == ["w10x64"]


def test_systems_param_default_is_empty_and_matches_value():
    param = next(p for p in MANIFEST["submission_params"] if p["name"] == "systems")
    assert param["type"] == "str" and param["default"] == "" and param["value"] == ""


# -- bad values -------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["many", None, [], {}, True, 1.5, float("nan")])
@pytest.mark.parametrize(
    "name", ["submission_timeout", "poll_interval", "quota_cooldown_seconds", "timeout", "retries"],
)
def test_unusable_values_fall_back_to_the_default(name, bad):
    instance = started(**{name: bad})
    attribute = "http_timeout" if name == "timeout" else name
    assert getattr(instance, attribute) == svc.DEFAULTS[name]


@pytest.mark.parametrize(("name", "attribute", "value", "expected"), [
    ("submission_timeout", "submission_timeout", 0, 60),
    ("submission_timeout", "submission_timeout", -5, 60),
    ("submission_timeout", "submission_timeout", 10**9, TIMEOUT - 60),
    ("submission_timeout", "submission_timeout", "1000", 1000),
    ("poll_interval", "poll_interval", 0, 5),
    ("poll_interval", "poll_interval", 10**6, 300),
    ("quota_cooldown_seconds", "quota_cooldown_seconds", -1, 0),
    ("quota_cooldown_seconds", "quota_cooldown_seconds", 10**9, 86400),
    ("timeout", "http_timeout", 1, 5),
    ("timeout", "http_timeout", 1000, 120),
    ("retries", "retries", -1, 0),
    ("retries", "retries", 99, 10),
])
def test_out_of_range_values_are_clamped(name, attribute, value, expected):
    assert getattr(started(**{name: value}), attribute) == expected


def warnings_of(log: Mock) -> list[str]:
    return [call.args[0] % call.args[1:] for call in log.warning.call_args_list]


def test_bad_value_logs_one_warning_naming_the_setting():
    log = Mock()
    assert settings.config_int({"retries": "lots"}, "retries", 3, 0, 10, log) == 3
    assert len(warnings_of(log)) == 1 and "retries" in warnings_of(log)[0] and "3" in warnings_of(log)[0]
    assert settings.config_int({"retries": 99}, "retries", 3, 0, 10, log) == 10
    assert len(warnings_of(log)) == 2 and "retries" in warnings_of(log)[1] and "10" in warnings_of(log)[1]


def test_secret_values_are_never_logged():
    log = Mock()
    assert settings.config_str({"api_key": 12345}, "api_key", "", log) == ""
    assert warnings_of(log) and all("12345" not in message for message in warnings_of(log))


def test_unusable_text_settings_do_not_break_start():
    instance = started(api_url=None, report_url=5, systems=7)
    assert instance.api_url == svc.DEFAULT_API_URL
    assert instance.report_url == svc.DEFAULT_REPORT_URL
    assert instance.systems == ["w10x64"]


def test_empty_systems_setting_stays_empty():
    assert started(systems="").systems == []


def test_systems_setting_accepts_list_and_comma_string():
    assert started(systems="w10x64, w11x64 ,").systems == ["w10x64", "w11x64"]
    assert started(systems=["w10x64", " w7x64 "]).systems == ["w10x64", "w7x64"]


def test_helpers_accept_documented_boolean_strings():
    assert settings.config_bool({"x": "TRUE"}, "x", False, None) is True
    assert settings.config_bool({"x": "0"}, "x", True, None) is False
    assert settings.config_bool({"x": "maybe"}, "x", True, None) is True
    assert settings.param_bool("false", "x", True) is False
    assert settings.param_int("7", "x", 1, 0, 5) == 5
    assert settings.param_choice("b", ["a", "b"], "a") == "b"
    assert settings.param_choice("c", ["a", "b"], "a") == "a"
    assert settings.config_float({"x": "2.5"}, "x", 1.0, 0.0, 2.0, None) == 2.0


# -- cache key --------------------------------------------------------------------------------


def test_tool_version_changes_with_a_public_setting_and_not_with_the_api_key():
    base = started().get_tool_version()
    assert base.startswith(f"jbxapi {jbxapi.__version__}-cfg-")
    assert started(poll_interval=60).get_tool_version() != base
    assert started(systems="w11x64").get_tool_version() != base
    assert started(api_key="another-key").get_tool_version() == base
    assert "another-key" not in started(api_key="another-key").get_tool_version()


# -- HTTP client knobs ------------------------------------------------------------------------


def test_timeout_and_retries_reach_the_api_client(monkeypatch):
    seen: dict = {}

    class Recorder:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(jbxapi, "JoeSandbox", Recorder)
    started(timeout=30, retries=1).make_client()
    assert seen["timeout"] == 30 and seen["retries"] == 1
    started().make_client()
    assert seen["timeout"] == 60 and seen["retries"] == 3


# -- submission option "systems" --------------------------------------------------------------


def upload(service, systems):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, upload=True)
    original = request.get_param
    request.get_param = lambda name: systems if name == "systems" else original(name)
    instance.execute(request)
    return client, request.result


def test_submission_systems_replace_the_service_setting_for_an_upload(service):
    client, result = upload(service, "w11x64, w7x64")
    assert client.params == {"systems": ["w11x64", "w7x64"]}
    assert "Joe Sandbox systems ignored" not in titles(result)


@pytest.mark.parametrize("systems", ["", None, "  ", ","])
def test_empty_submission_systems_use_the_service_setting(service, systems):
    client, result = upload(service, systems)
    assert client.params == {"systems": ["w10x64"]}
    assert "Joe Sandbox systems ignored" not in titles(result)


def test_invalid_system_names_are_dropped_with_a_warning(service):
    client, result = upload(service, "w11x64,bad name,$(id),../x," + "a" * 41)
    assert client.params == {"systems": ["w11x64"]}
    section = result.sections[0]
    assert section.title_text == "Joe Sandbox systems ignored"
    assert "bad name" in section.body and "$(id)" in section.body and "w11x64" not in section.body


def test_only_invalid_system_names_fall_back_to_the_service_setting(service):
    client, result = upload(service, "no way;")
    assert client.params == {"systems": ["w10x64"]}
    assert "service's systems setting was used" in result.sections[0].body


def test_systems_option_is_ignored_by_lookups(service):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, upload=False)
    original = request.get_param
    request.get_param = lambda name: "bad name" if name == "systems" else original(name)
    instance.execute(request)
    assert client.uploads == [] and titles(request.result) == []


def test_empty_service_systems_and_empty_option_let_joe_sandbox_choose(service):
    instance, sample = service
    instance.systems = []
    client = Client(search=[], infos=FINISHED)
    run(instance, sample, client, upload=True)
    assert client.params == {}
