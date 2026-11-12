"""Service behaviour around Joe Sandbox: lookup-only by default, opt-in upload, failure handling."""

import json
import logging
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import jbxapi
import pytest
from assemblyline.common.exceptions import NonRecoverableError, RecoverableError

HERE = Path(__file__).resolve().parent
os.environ["SERVICE_MANIFEST_PATH"] = str(HERE.parent / "service_manifest.yml")

from joesandboxv2 import service as svc  # noqa: E402

REPORT = next((HERE / "fixtures" / "jbx").glob("*.json"))
FIXTURE = json.loads(REPORT.read_text())
DEFAULT_RESPONSE = object()


class Client:
    """Scriptable external client with a real per-endpoint call log."""

    def __init__(self, search: list[dict], infos: dict[str, dict | Exception],
                 submit_error: Exception | None = None, submission_status: str = "finished",
                 search_error: Exception | None = None, download_error: Exception | None = None,
                 search_callback: Callable[[], None] | None = None,
                 submission_error: Exception | None = None, report_raw: bytes | None = None,
                 submit_response: object = DEFAULT_RESPONSE, submission_response: object = DEFAULT_RESPONSE) -> None:
        self.search, self.infos = search, infos
        self.submit_error, self.submission_status, self.search_error = submit_error, submission_status, search_error
        self.download_error = download_error
        self.search_callback = search_callback
        self.submission_error = submission_error
        self.report_raw = report_raw
        self.submit_response = submit_response
        self.submission_response = submission_response
        self.submission_ids: list[str] = []
        self.info_ids: list[str] = []
        self.downloads: list[tuple[str, str]] = []
        self.uploads: list[str] = []
        self.calls: list[str] = []

    def analysis_search(self, query: str) -> list[dict]:
        self.calls.append("analysis_search")
        if self.search_callback:
            self.search_callback()
        if self.search_error:
            raise self.search_error
        return self.search

    def analysis_info(self, webid: str) -> dict:
        self.calls.append("analysis_info")
        self.info_ids.append(str(webid))
        info = self.infos[str(webid)]
        if isinstance(info, Exception):
            raise info
        return info

    def analysis_download(self, webid: str, type: str) -> tuple[str, bytes]:  # noqa: A002 (jbxapi's name)
        self.calls.append("analysis_download")
        self.downloads.append((str(webid), type))
        assert type == "irjsonfixed"
        if self.download_error:
            raise self.download_error
        if self.report_raw is not None:
            return "report.json", self.report_raw
        report = json.loads(json.dumps(FIXTURE["report"]["1000001"]))
        report["analysis"]["id"] = int(webid)
        return "report.json", json.dumps(report).encode()

    def submit_sample(self, sample: tuple, params: dict | None = None) -> Any:
        self.calls.append("submit_sample")
        self.uploads.append(sample[0])
        self.params = params
        if self.submit_error:
            raise self.submit_error
        if self.submit_response is not DEFAULT_RESPONSE:
            return self.submit_response
        return {"submission_id": "S-1"}

    def submission_info(self, submission_id: str) -> Any:
        self.calls.append("submission_info")
        self.submission_ids.append(submission_id)
        if self.submission_error:
            raise self.submission_error
        if self.submission_response is not DEFAULT_RESPONSE:
            return self.submission_response
        return {"status": self.submission_status, "most_relevant_analysis": {"webid": "1000001"}}


FINISHED = {"1000001": FIXTURE["info"]["1000001"]}


@pytest.fixture
def service(monkeypatch, tmp_path, clock):
    instance = svc.JoeSandboxV2({"api_key": f"offline-test-key-{tmp_path.name}", "systems": "w10x64"})
    instance.start()
    # start() clamps the wait to at least 60 s; these tests drive the loop with no waiting.
    instance.submission_timeout = 0
    instance.poll_interval = 0
    monkeypatch.setattr(svc.time, "sleep", lambda _: None)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    return instance, sample


def make_request(sample: Path, upload: bool = False, depth: int = 0, file_type: str = "archive/zip",
                 lookup_depth: object = 6, extracted_types: object = ".*", upload_extracted: object = False) -> Any:
    params = {"submit_to_joesandbox": upload, "lookup_depth": lookup_depth, "extracted_types": extracted_types,
              "upload_extracted": upload_extracted}
    return SimpleNamespace(file_path=str(sample), file_name="sample.bin", sha256="0" * 64, result=None,
                           task=SimpleNamespace(depth=depth), file_type=file_type, get_param=params.get, partial=Mock())


def run(instance: Any, sample: Path, client: Client, upload: bool) -> Any:
    instance.make_client = lambda: client
    request = make_request(sample, upload=upload)
    instance.execute(request)
    return request.result


def titles(result: Any) -> list[str]:
    return [s.title_text for s in result.sections]


@pytest.mark.parametrize("name", ["submit_to_joesandbox", "upload_extracted"])
def test_upload_is_off_by_default_in_the_manifest(name):
    import yaml
    params = yaml.safe_load(Path(os.environ["SERVICE_MANIFEST_PATH"]).read_text())
    upload = next(p for p in params["submission_params"] if p["name"] == name)
    assert upload["default"] is False and upload["value"] is False


def test_unknown_file_without_upload_is_not_uploaded(service):
    instance, sample = service
    client = Client(search=[], infos={})
    assert titles(run(instance, sample, client, upload=False)) == []
    assert client.uploads == []
    assert client.calls == ["analysis_search"]


def test_known_file_is_never_uploaded_even_when_upload_is_on(service):
    instance, sample = service
    client = Client(search=[{"webid": "1000001"}], infos=FINISHED)
    result = run(instance, sample, client, upload=True)
    assert client.uploads == []
    assert titles(result)[0] == "Joe Sandbox analysis"
    # The Sandbox ontology part must validate against AL's model (add_result_part drops invalid data).
    assert [type(p).__name__ for p in instance.ontology._result_parts.values()] == ["Sandbox"]


def test_running_analysis_with_upload_opt_in_is_retried_not_uploaded(service):
    instance, sample = service
    client = Client(search=[{"webid": "1000002"}], infos={"1000002": {"status": "running"}})
    with pytest.raises(RecoverableError, match="1000002"):
        run(instance, sample, client, upload=True)
    assert client.uploads == []
    assert client.calls == ["analysis_search", "analysis_info"]
    assert client.info_ids == ["1000002"]


def test_upload_reports_the_analysis_and_says_it_is_public(service):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    result = run(instance, sample, client, upload=True)
    assert client.uploads == ["sample.bin"]
    assert client.params == {"systems": ["w10x64"]}  # the manifest default; Cloud Basic needs an explicit system
    assert titles(result)[:2] == ["Joe Sandbox analysis", "File uploaded to Joe Sandbox"]
    assert "public" in result.sections[1].body


def test_refused_upload_is_reported_not_retried(service):
    instance, sample = service
    quota = jbxapi.ApiError({"code": 7, "message": "Your daily submission quota is exhausted."})
    client = Client(search=[], infos={}, submit_error=quota)
    result = run(instance, sample, client, upload=True)
    assert titles(result) == ["Joe Sandbox did not accept the upload"]
    assert "quota" in result.sections[0].body


def test_unfinished_upload_is_retried_with_its_submission_id(service):
    instance, sample = service
    client = Client(search=[], infos={}, submission_status="running")
    with pytest.raises(RecoverableError, match="S-1"):
        run(instance, sample, client, upload=True)
    assert client.uploads == ["sample.bin"]


def test_rejected_api_key_is_not_retried(service):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=jbxapi.ApiError({"code": 4, "message": "invalid api key"}))
    with pytest.raises(NonRecoverableError, match="rejected the API key"):
        run(instance, sample, client, upload=False)
    assert client.calls == ["analysis_search"]
    assert client.uploads == []


def test_unreachable_api_is_retried(service):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=jbxapi.ConnectionError("timed out"))
    with pytest.raises(RecoverableError, match="lookup failed"):
        run(instance, sample, client, upload=False)


def test_missing_api_key_fails_clearly(monkeypatch, tmp_path):
    monkeypatch.delenv("JBX_API_KEY", raising=False)
    instance = svc.JoeSandboxV2({"api_key": ""})
    instance.start()
    request = make_request(tmp_path)
    with pytest.raises(NonRecoverableError, match="API key"):
        instance.execute(request)  # type: ignore[arg-type]


def test_empty_systems_lets_joe_sandbox_choose(service):
    instance, sample = service
    instance.systems = []
    client = Client(search=[], infos=FINISHED)
    run(instance, sample, client, upload=True)
    assert client.params == {}


@pytest.mark.parametrize("api_key", ["", "offline-test-key"])
@pytest.mark.parametrize(
    "depth,lookup_depth,extracted_types",
    [(1, 0, ".*"), (7, 6, ".*"), (1, 6, "executable/.*")],
)
def test_out_of_scope_files_skip_api_and_cache(service, api_key, depth, lookup_depth, extracted_types):
    instance, sample = service
    instance.api_key = api_key
    client = Client(search=[], infos=FINISHED)
    instance.make_client = Mock(return_value=client)
    request = make_request(sample, upload=True, depth=depth, lookup_depth=lookup_depth,
                           extracted_types=extracted_types, upload_extracted=True)
    instance.execute(request)
    assert titles(request.result) == []
    request.partial.assert_called_once_with()
    instance.make_client.assert_not_called()
    assert client.calls == []
    assert client.uploads == []


@pytest.mark.parametrize("api_key", ["", "offline-test-key"])
def test_invalid_extracted_types_is_nonrecoverable_before_api_checks(service, api_key):
    instance, sample = service
    instance.api_key = api_key
    instance.make_client = Mock(return_value=Client(search=[], infos={}))
    request = make_request(sample, depth=1, extracted_types="[")
    with pytest.raises(NonRecoverableError, match="extracted_types.*not a valid regular expression"):
        instance.execute(request)
    instance.make_client.assert_not_called()
    request.partial.assert_not_called()


@pytest.mark.parametrize("depth,extracted_types", [(1, "executable/.*"), (0, "[")])
def test_in_scope_files_are_looked_up_normally(service, depth, extracted_types):
    instance, sample = service
    client = Client(search=[{"webid": "1000001"}], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, depth=depth, file_type="executable/windows/pe32", extracted_types=extracted_types)
    instance.execute(request)
    assert titles(request.result)[0] == "Joe Sandbox analysis"
    assert client.calls == ["analysis_search", "analysis_info", "analysis_download"]
    assert client.uploads == []
    request.partial.assert_not_called()


@pytest.mark.parametrize("upload_extracted", [False, None, "true"])
def test_extracted_files_are_lookup_only_without_explicit_upload_permission(service, upload_extracted):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, upload=True, depth=1, upload_extracted=upload_extracted)
    instance.execute(request)
    assert titles(request.result) == []
    assert client.calls == ["analysis_search"]
    assert client.uploads == []
    request.partial.assert_not_called()


@pytest.mark.parametrize("depth,upload_extracted", [(0, False), (1, True)])
def test_upload_permission_keeps_upload_settings_and_results(service, depth, upload_extracted):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, upload=True, depth=depth, upload_extracted=upload_extracted)
    instance.execute(request)
    assert titles(request.result)[:2] == ["Joe Sandbox analysis", "File uploaded to Joe Sandbox"]
    assert client.calls == ["analysis_search", "submit_sample", "submission_info", "analysis_info", "analysis_download"]
    assert client.uploads == ["sample.bin"]
    assert client.params == {"systems": ["w10x64"]}
    request.partial.assert_not_called()


@pytest.mark.parametrize("depth", [0, 1])
def test_upload_extracted_alone_does_not_enable_uploads(service, depth):
    instance, sample = service
    client = Client(search=[], infos=FINISHED)
    instance.make_client = lambda: client
    request = make_request(sample, depth=depth, upload_extracted=True)
    instance.execute(request)
    assert titles(request.result) == []
    assert client.calls == ["analysis_search"]
    assert client.uploads == []
    request.partial.assert_not_called()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(svc.time, "monotonic", clock)
    return clock


def daily_request_quota() -> Exception:
    return jbxapi.ApiError({
        "code": 7, "message": "You have exceeded the number of available API requests today",
    })


def lookup_request(instance: Any, sample: Path, client: Client, upload: bool = False, sha256: str = "0" * 64) -> Any:
    instance.make_client = lambda: client
    request = make_request(sample, upload=upload)
    request.sha256 = sha256
    instance.execute(request)
    return request


def assert_quota_notice(request: Any) -> None:
    request.partial.assert_called_once_with()
    assert titles(request.result)[-1] == "Joe Sandbox lookup unavailable"
    assert all(section.heuristic is None for section in request.result.sections)
    notice = request.result.sections[-1]
    assert "quota" in notice.body.lower() or "api requests" in notice.body.lower()
    assert "unknown" not in notice.body.lower()


def assert_pending_notice(request: Any, webid: str) -> None:
    request.partial.assert_called_once_with()
    assert len(request.result.sections) == 1
    notice = request.result.sections[0]
    assert notice.heuristic is None
    text = f"{notice.title_text}\n{notice.body}".lower()
    assert "pending" in text or "running" in text or "in progress" in text
    assert f"https://www.joesandbox.com/analysis/{webid}/0/html" in notice.body
    assert "unknown" not in text


def test_complete_search_metadata_selects_newest_finished_with_two_calls_and_rich_report(service):
    instance, sample = service
    client = Client(search=[
        {"webid": "999", "status": "finished", "time": "2026-01-05T03:04:05+01:00"},
        {"webid": "1000002", "status": "running", "time": "2026-01-03T10:00:00+01:00"},
        dict(FINISHED["1000001"]),
        dict(FINISHED["1000001"]),
    ], infos={})

    request = lookup_request(instance, sample, client)

    assert client.calls == ["analysis_search", "analysis_download"]
    assert client.info_ids == []
    assert client.downloads == [("1000001", "irjsonfixed")]
    assert client.uploads == []
    request.partial.assert_not_called()
    assert titles(request.result) == [
        "Joe Sandbox analysis",
        "Joe Sandbox behaviour signatures",
        "Network activity observed by Joe Sandbox",
        "Files dropped during the Joe Sandbox analysis",
    ]
    summary, signatures, network, dropped = request.result.sections
    assert "malicious" in summary.body
    assert "88/100" in summary.body
    assert "2026-01-02T03:04:05+01:00" in summary.body
    assert "Windows 10 x64 22H2" in summary.body
    assert summary.heuristic.heur_id == 1
    assert "Creates an autostart registry key" in signatures.body
    assert "c2.example.com" in network.body
    assert "192.0.2.10" in network.body
    assert "http://c2.example.com/gate.php" in network.body
    assert "payload.exe" in dropped.body
    assert "abcdef0000000000000000000000000000000000000000000000000000000000" in dropped.body
    parts = list(instance.ontology._result_parts.values())
    assert [type(part).__name__ for part in parts] == ["Sandbox"]
    assert datetime.fromisoformat(str(parts[0].analysis_metadata.start_time).replace("Z", "+00:00")) == (
        datetime.fromisoformat("2026-01-02T03:04:05+01:00")
    )


@pytest.mark.parametrize("row", [
    {"webid": "1000001"},
    {"webid": "1000001", "status": "finished"},
    {"webid": "1000001", "time": "2026-01-02T03:04:05+01:00"},
])
def test_incomplete_search_metadata_reuses_selected_info_with_three_calls(service, row):
    instance, sample = service
    client = Client(search=[row], infos=FINISHED)

    request = lookup_request(instance, sample, client)

    assert titles(request.result)[0] == "Joe Sandbox analysis"
    assert "2026-01-02T03:04:05+01:00" in request.result.sections[0].body
    assert client.calls == ["analysis_search", "analysis_info", "analysis_download"]
    assert client.info_ids == ["1000001"]
    assert client.downloads == [("1000001", "irjsonfixed")]
    assert client.uploads == []
    request.partial.assert_not_called()


def test_mixed_search_metadata_fetches_only_the_incomplete_row_with_three_calls(service):
    instance, sample = service
    client = Client(search=[
        {"webid": "1000002", "status": "running", "time": "2026-01-03T10:00:00+01:00"},
        {"webid": "1000001"},
    ], infos=FINISHED)

    request = lookup_request(instance, sample, client)

    assert titles(request.result)[0] == "Joe Sandbox analysis"
    assert client.calls == ["analysis_search", "analysis_info", "analysis_download"]
    assert client.info_ids == ["1000001"]
    assert client.downloads == [("1000001", "irjsonfixed")]
    assert client.uploads == []


def test_incomplete_metadata_checks_five_newest_unique_analyses_with_seven_calls(service):
    instance, sample = service
    client = Client(search=[
        {"webid": "1000001"}, {"webid": "1000004"}, {"webid": "1000006"},
        {"webid": "1000003"}, {"webid": "1000006"}, {"webid": "1000002"}, {"webid": "1000005"},
    ], infos={
        **{str(webid): {"status": "running"} for webid in range(1000003, 1000007)},
        "1000002": {**FINISHED["1000001"], "webid": "1000002"},
    })

    request = lookup_request(instance, sample, client)

    assert titles(request.result)[0] == "Joe Sandbox analysis"
    assert client.calls == ["analysis_search"] + ["analysis_info"] * 5 + ["analysis_download"]
    assert client.info_ids == ["1000006", "1000005", "1000004", "1000003", "1000002"]
    assert client.downloads == [("1000002", "irjsonfixed")]
    assert client.uploads == []
    request.partial.assert_not_called()


def test_five_analysis_bound_never_checks_sixth_finished_analysis_with_six_calls(service):
    instance, sample = service
    client = Client(search=[{"webid": str(webid)} for webid in range(1000001, 1000007)], infos={
        **{str(webid): {"status": "running"} for webid in range(1000002, 1000007)},
        **FINISHED,
    })

    request = lookup_request(instance, sample, client)

    assert_pending_notice(request, "1000006")
    assert client.calls == ["analysis_search"] + ["analysis_info"] * 5
    assert client.info_ids == ["1000006", "1000005", "1000004", "1000003", "1000002"]
    assert client.downloads == []
    assert client.uploads == []


@pytest.mark.parametrize("status", ["running", "accepted", "submitted"])
def test_complete_running_metadata_returns_partial_pending_with_one_call_without_retry_or_upload(service, status):
    instance, sample = service
    client = Client(search=[
        {"webid": "1000002", "status": status, "time": "2026-01-03T10:00:00+01:00"},
    ], infos={})

    request = lookup_request(instance, sample, client)

    assert_pending_notice(request, "1000002")
    assert client.calls == ["analysis_search"]
    assert client.info_ids == []
    assert client.downloads == []
    assert client.uploads == []


@pytest.mark.parametrize("upload", [False, True])
def test_search_daily_request_quota_returns_unscored_partial_with_one_call_and_no_retry_or_upload(service, upload):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=daily_request_quota())

    request = lookup_request(instance, sample, client, upload=upload)

    assert_quota_notice(request)
    assert client.calls == ["analysis_search"]
    assert client.info_ids == []
    assert client.downloads == []
    assert client.uploads == []


@pytest.mark.parametrize("endpoint,expected_calls", [
    ("info", ["analysis_search", "analysis_info"]),
    ("download", ["analysis_search", "analysis_download"]),
])
def test_later_daily_request_quota_returns_same_partial_without_retry_or_upload(service, endpoint, expected_calls):
    instance, sample = service
    client = Client(
        search=[{"webid": "1000001"}] if endpoint == "info" else [dict(FINISHED["1000001"])],
        infos={"1000001": daily_request_quota()} if endpoint == "info" else {},
        download_error=daily_request_quota() if endpoint == "download" else None,
    )

    request = lookup_request(instance, sample, client, upload=True)

    assert_quota_notice(request)
    assert client.calls == expected_calls
    assert client.uploads == []
    repeated = lookup_request(instance, sample, client)
    assert_quota_notice(repeated)
    assert client.calls == expected_calls


@pytest.mark.parametrize("endpoint", ["search", "info", "download"])
def test_nonquota_permission_errors_still_retry_and_do_not_open_daily_quota_breaker(service, endpoint):
    instance, sample = service
    denied = jbxapi.ApiError({"code": 7, "message": "Permission denied for this report"})
    client = Client(
        search=[] if endpoint == "search" else (
            [{"webid": "1000001"}] if endpoint == "info" else [dict(FINISHED["1000001"])]
        ),
        infos={"1000001": denied} if endpoint == "info" else {},
        search_error=denied if endpoint == "search" else None,
        download_error=denied if endpoint == "download" else None,
    )
    with pytest.raises(RecoverableError):
        lookup_request(instance, sample, client)
    assert client.uploads == []

    healthy = Client(search=[], infos={})
    request = lookup_request(instance, sample, healthy)
    assert healthy.calls == ["analysis_search"]
    assert titles(request.result) == []
    request.partial.assert_not_called()


def test_account_cooldown_skips_repeated_hashes_and_other_service_instances_without_new_calls(service, clock):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, client))
    assert client.calls == ["analysis_search"]
    client.search_error = None

    for digit in ("1", "2", "3"):
        clock.advance(100)
        assert_quota_notice(lookup_request(instance, sample, client, sha256=digit * 64))
    peer = svc.JoeSandboxV2({"api_key": instance.api_key, "api_url": instance.api_url})
    peer.start()
    peer_client = Client(search=[], infos={})
    assert_quota_notice(lookup_request(peer, sample, peer_client, sha256="4" * 64))

    assert client.calls == ["analysis_search"]
    assert peer_client.calls == []
    assert client.uploads == peer_client.uploads == []


@pytest.mark.parametrize("changed_setting", ["api_key", "api_url"])
def test_account_or_api_url_change_isolates_quota_cooldown(service, clock, changed_setting):
    instance, sample = service
    exhausted = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, exhausted))
    original = getattr(instance, changed_setting)
    setattr(instance, changed_setting, original + "-other")
    healthy = Client(search=[], infos={})

    request = lookup_request(instance, sample, healthy)

    assert healthy.calls == ["analysis_search"]
    assert titles(request.result) == []
    request.partial.assert_not_called()
    setattr(instance, changed_setting, original)
    assert_quota_notice(lookup_request(instance, sample, healthy))
    assert healthy.calls == ["analysis_search"]
    assert exhausted.calls == ["analysis_search"]
    assert healthy.uploads == exhausted.uploads == []


def test_successful_half_open_probe_after_one_hour_closes_cooldown_with_one_search(service, clock):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, client))
    client.search_error = None
    clock.advance(3599)
    assert_quota_notice(lookup_request(instance, sample, client))
    assert client.calls == ["analysis_search"]
    clock.advance(1)

    request = lookup_request(instance, sample, client)

    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search", "analysis_search"]
    request = lookup_request(instance, sample, client)
    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search"] * 3
    assert client.uploads == []


def test_quota_half_open_probe_reopens_one_hour_cooldown_without_immediate_second_probe(service, clock):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, client))
    clock.advance(3600)
    assert_quota_notice(lookup_request(instance, sample, client))
    assert client.calls == ["analysis_search"] * 2
    client.search_error = None
    clock.advance(3599)
    assert_quota_notice(lookup_request(instance, sample, client))
    assert client.calls == ["analysis_search"] * 2
    clock.advance(1)
    request = lookup_request(instance, sample, client)
    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search"] * 3
    assert client.uploads == []


def test_configured_quota_cooldown_controls_half_open_probe_boundary(service, clock):
    instance, sample = service
    configured = svc.JoeSandboxV2({
        "api_key": instance.api_key + "-configured", "quota_cooldown_seconds": 10,
    })
    configured.start()
    client = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(configured, sample, client))
    client.search_error = None
    clock.advance(9)
    assert_quota_notice(lookup_request(configured, sample, client))
    assert client.calls == ["analysis_search"]
    clock.advance(1)
    request = lookup_request(configured, sample, client)
    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search"] * 2
    assert client.uploads == []


def test_half_open_search_allows_only_one_account_probe_while_another_task_arrives(service, clock):
    instance, sample = service
    exhausted = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, exhausted))
    peer = svc.JoeSandboxV2({"api_key": instance.api_key, "api_url": instance.api_url})
    peer.start()
    peer_client = Client(search=[], infos={})
    overlapping_requests = []

    def another_task_during_search() -> None:
        overlapping_requests.append(lookup_request(peer, sample, peer_client, sha256="9" * 64))

    clock.advance(3600)
    probe = Client(search=[], infos={}, search_callback=another_task_during_search)
    request = lookup_request(instance, sample, probe)

    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert len(overlapping_requests) == 1
    assert_quota_notice(overlapping_requests[0])
    assert peer_client.calls == []
    assert probe.calls == ["analysis_search"]
    assert exhausted.calls == ["analysis_search"]
    resumed = lookup_request(peer, sample, peer_client)
    assert titles(resumed.result) == []
    resumed.partial.assert_not_called()
    assert peer_client.calls == ["analysis_search"]
    assert exhausted.uploads == probe.uploads == peer_client.uploads == []


@pytest.mark.parametrize("endpoint,expected_calls", [
    ("info", ["analysis_search", "analysis_info"]),
    ("download", ["analysis_search", "analysis_download"]),
])
def test_later_temporary_outage_remains_recoverable_without_opening_quota_cooldown(
    service, endpoint, expected_calls,
):
    instance, sample = service
    outage = jbxapi.ConnectionError("timed out")
    client = Client(
        search=[{"webid": "1000001"}] if endpoint == "info" else [dict(FINISHED["1000001"])],
        infos={"1000001": outage} if endpoint == "info" else {},
        download_error=outage if endpoint == "download" else None,
    )
    with pytest.raises(RecoverableError):
        lookup_request(instance, sample, client)
    assert client.calls == expected_calls
    assert client.uploads == []

    healthy = Client(search=[], infos={})
    request = lookup_request(instance, sample, healthy)
    assert healthy.calls == ["analysis_search"]
    assert titles(request.result) == []
    request.partial.assert_not_called()


@pytest.mark.parametrize("status", [None, "unknown", "unrecognized"])
@pytest.mark.parametrize("upload", [False, True])
def test_nonempty_search_with_unresolved_five_row_statuses_is_partial_and_never_uploads(service, status, upload):
    instance, sample = service
    client = Client(
        search=[{"webid": str(webid)} for webid in range(1000001, 1000007)],
        infos={
            **{str(webid): ({} if status is None else {"status": status})
               for webid in range(1000002, 1000007)},
            **FINISHED,
        },
    )

    request = lookup_request(instance, sample, client, upload=upload)

    request.partial.assert_called_once_with()
    assert request.result.sections
    assert all(section.heuristic is None for section in request.result.sections)
    text = "\n".join(f"{section.title_text}\n{section.body}" for section in request.result.sections).lower()
    assert "lookup" in text
    assert "unavailable" in text or "incomplete" in text or "status" in text
    assert client.calls == ["analysis_search"] + ["analysis_info"] * 5
    assert client.info_ids == ["1000006", "1000005", "1000004", "1000003", "1000002"]
    assert client.downloads == []
    assert client.uploads == []


def test_unknown_search_status_falls_back_to_verified_finished_info_with_three_calls(service):
    instance, sample = service
    client = Client(
        search=[{"webid": "1000001", "status": "unrecognized", "time": "2026-01-02T03:04:05+01:00"}],
        infos=FINISHED,
    )

    request = lookup_request(instance, sample, client)

    assert titles(request.result)[0] == "Joe Sandbox analysis"
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search", "analysis_info", "analysis_download"]
    assert client.info_ids == ["1000001"]
    assert client.uploads == []


def test_submit_sample_daily_api_request_quota_is_partial_and_opens_cooldown_after_two_calls(service):
    instance, sample = service
    client = Client(search=[], infos={}, submit_error=daily_request_quota())

    request = lookup_request(instance, sample, client, upload=True)

    assert_quota_notice(request)
    assert "Joe Sandbox did not accept the upload" not in titles(request.result)
    assert client.calls == ["analysis_search", "submit_sample"]
    assert client.uploads == ["sample.bin"]
    repeated = lookup_request(instance, sample, client, upload=True, sha256="8" * 64)
    assert_quota_notice(repeated)
    assert client.calls == ["analysis_search", "submit_sample"]
    assert client.uploads == ["sample.bin"]


def test_ordinary_upload_refusal_is_a_distinct_unscored_partial_without_account_cooldown(service):
    instance, sample = service
    refusal = jbxapi.ApiError({"code": 7, "message": "Your daily submission quota is exhausted."})
    client = Client(search=[], infos={}, submit_error=refusal)

    request = lookup_request(instance, sample, client, upload=True)

    request.partial.assert_called_once_with()
    assert titles(request.result) == ["Joe Sandbox did not accept the upload"]
    assert request.result.sections[0].heuristic is None
    assert "daily submission quota" in request.result.sections[0].body.lower()
    assert client.calls == ["analysis_search", "submit_sample"]
    assert client.uploads == ["sample.bin"]
    healthy = Client(search=[], infos={})
    resumed = lookup_request(instance, sample, healthy)
    assert titles(resumed.result) == []
    resumed.partial.assert_not_called()
    assert healthy.calls == ["analysis_search"]
    assert healthy.uploads == []


@pytest.mark.parametrize("code,message", [
    pytest.param(5, "Joe Sandbox is offline", id="503-offline"),
    pytest.param(6, "An internal server error occurred", id="500-internal-server-error"),
])
def test_upload_server_outage_remains_recoverable_after_two_calls(service, code, message):
    instance, sample = service
    client = Client(search=[], infos={}, submit_error=jbxapi.ApiError({"code": code, "message": message}))
    instance.make_client = lambda: client
    request = make_request(sample, upload=True)

    with pytest.raises(RecoverableError, match="upload failed"):
        instance.execute(request)

    assert client.calls == ["analysis_search", "submit_sample"]
    assert client.uploads == ["sample.bin"]
    assert "Joe Sandbox did not accept the upload" not in titles(request.result)
    healthy = Client(search=[], infos={})
    resumed = lookup_request(instance, sample, healthy)
    assert titles(resumed.result) == []
    resumed.partial.assert_not_called()
    assert healthy.calls == ["analysis_search"]


@pytest.fixture
def poll_window(service, clock, monkeypatch):
    instance, sample = service
    instance.submission_timeout = 120
    instance.poll_interval = 30
    sleeps = []

    def advance_poll_clock(seconds: float) -> None:
        sleeps.append(seconds)
        clock.advance(seconds)

    monkeypatch.setattr(svc.time, "sleep", advance_poll_clock)
    return instance, sample, sleeps


def test_submission_info_invalid_key_fails_nonrecoverably_on_first_poll(poll_window):
    instance, sample, sleeps = poll_window
    client = Client(
        search=[], infos={}, submission_error=jbxapi.ApiError({"code": 4, "message": "invalid api key"}),
    )

    with pytest.raises(NonRecoverableError, match="API key"):
        lookup_request(instance, sample, client, upload=True)

    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.submission_ids == ["S-1"]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []


def test_submission_info_daily_request_quota_stops_first_poll_with_partial_and_account_cooldown(poll_window):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos={}, submission_error=daily_request_quota())

    request = lookup_request(instance, sample, client, upload=True)

    assert_quota_notice(request)
    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.submission_ids == ["S-1"]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []
    repeated = lookup_request(instance, sample, client, upload=True, sha256="7" * 64)
    assert_quota_notice(repeated)
    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.uploads == ["sample.bin"]


@pytest.mark.parametrize("error,reason", [
    pytest.param(
        jbxapi.ApiError({"code": 7, "message": "Permission denied for submission status"}),
        "Permission denied", id="nonquota-permission",
    ),
    pytest.param(jbxapi.ConnectionError("timed out"), "timed out", id="timeout"),
    pytest.param(jbxapi.ApiError({"code": 5, "message": "Joe Sandbox is offline"}), "offline", id="503-offline"),
    pytest.param(
        jbxapi.ApiError({"code": 6, "message": "An internal server error occurred"}),
        "internal server", id="500-internal-server-error",
    ),
])
def test_submission_info_failure_is_immediately_recoverable_with_submission_id_without_more_polling(
    poll_window, error, reason,
):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos={}, submission_error=error)

    with pytest.raises(RecoverableError) as failure:
        lookup_request(instance, sample, client, upload=True)

    assert "S-1" in str(failure.value)
    assert reason.lower() in str(failure.value).lower()
    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.submission_ids == ["S-1"]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []
    healthy = Client(search=[], infos={})
    resumed = lookup_request(instance, sample, healthy)
    assert titles(resumed.result) == []
    resumed.partial.assert_not_called()
    assert healthy.calls == ["analysis_search"]
    assert healthy.uploads == []


@pytest.mark.parametrize("upload,expected_calls", [
    (False, ["analysis_search", "analysis_download"]),
    (True, ["analysis_search", "submit_sample", "submission_info", "analysis_info", "analysis_download"]),
])
def test_download_quota_preserves_analysis_identity_time_and_public_upload_notice(
    service, upload, expected_calls,
):
    instance, sample = service
    client = Client(
        search=[] if upload else [dict(FINISHED["1000001"])],
        infos=FINISHED, download_error=daily_request_quota(),
    )

    request = lookup_request(instance, sample, client, upload=upload)

    assert_quota_notice(request)
    text = "\n".join(section.body for section in request.result.sections)
    assert "1000001" in text
    assert "https://www.joesandbox.com/analysis/1000001/0/html" in text
    assert "2026-01-02T03:04:05+01:00" in text
    assert client.calls == expected_calls
    assert client.downloads == [("1000001", "irjsonfixed")]
    if upload:
        assert client.uploads == ["sample.bin"]
        upload_index = titles(request.result).index("File uploaded to Joe Sandbox")
        assert upload_index < len(request.result.sections) - 1
        assert "public" in request.result.sections[upload_index].body.lower()
    else:
        assert client.uploads == []
        assert "File uploaded to Joe Sandbox" not in titles(request.result)


@pytest.mark.parametrize("payload", [
    pytest.param({}, id="empty-object"),
    pytest.param([], id="list"),
    pytest.param(None, id="null"),
    pytest.param(42, id="number"),
    pytest.param("server unavailable", id="string"),
    pytest.param(True, id="boolean"),
    pytest.param({"error": "permission denied"}, id="missing-analysis"),
    pytest.param({"analysis": None}, id="null-analysis"),
    pytest.param({"analysis": []}, id="list-analysis"),
    pytest.param({"analysis": "not an analysis"}, id="scalar-analysis"),
    pytest.param({"analysis": {"detection": {"clean": True}}}, id="missing-analysis-id"),
    pytest.param({"analysis": {"id": None}}, id="null-analysis-id"),
    pytest.param({"analysis": {"id": ""}}, id="empty-analysis-id"),
    pytest.param({"analysis": {"id": 1000002}}, id="mismatched-analysis-id"),
])
def test_invalid_downloaded_report_is_report_specific_recoverable_not_cached_score_zero(service, payload):
    instance, sample = service
    client = Client(
        search=[dict(FINISHED["1000001"])], infos={}, report_raw=json.dumps(payload).encode(),
    )
    instance.make_client = lambda: client
    request = make_request(sample)

    with pytest.raises(RecoverableError, match=r"(?i)report.*1000001|1000001.*report"):
        instance.execute(request)

    assert client.calls == ["analysis_search", "analysis_download"]
    assert client.uploads == []
    assert all(section.heuristic is None for section in request.result.sections)
    assert instance.ontology._result_parts == {}


@pytest.mark.parametrize("endpoint,phase_words", [
    ("search", ("search",)),
    ("info", ("info",)),
    ("download", ("download",)),
    ("upload", ("upload", "submit_sample")),
    ("submission", ("submission", "poll")),
])
def test_quota_open_and_half_open_reopen_log_phase_warning_without_api_key(
    service, clock, caplog, endpoint, phase_words,
):
    instance, sample = service
    client = Client(
        search=[] if endpoint in ("search", "upload", "submission") else (
            [{"webid": "1000001"}] if endpoint == "info" else [dict(FINISHED["1000001"])]
        ),
        infos={"1000001": daily_request_quota()} if endpoint == "info" else {},
        search_error=daily_request_quota() if endpoint == "search" else None,
        download_error=daily_request_quota() if endpoint == "download" else None,
        submit_error=daily_request_quota() if endpoint == "upload" else None,
        submission_error=daily_request_quota() if endpoint == "submission" else None,
    )
    upload = endpoint in ("upload", "submission")
    with caplog.at_level(logging.WARNING):
        assert_quota_notice(lookup_request(instance, sample, client, upload=upload))
        assert any(
            record.levelno >= logging.WARNING and "quota" in record.getMessage().lower()
            and "open" in record.getMessage().lower()
            and any(word in record.getMessage().lower() for word in phase_words)
            for record in caplog.records
        )
        assert instance.api_key not in caplog.text
        caplog.clear()
        clock.advance(3600)
        assert_quota_notice(lookup_request(instance, sample, client, upload=upload))
        assert any(
            record.levelno >= logging.WARNING and "quota" in record.getMessage().lower()
            and "open" in record.getMessage().lower()
            and any(word in record.getMessage().lower() for word in phase_words)
            for record in caplog.records
        )
        assert instance.api_key not in caplog.text
    assert client.uploads == (["sample.bin"] * 2 if upload else [])


def test_successful_half_open_probe_logs_cooldown_close_without_api_key(service, clock, caplog):
    instance, sample = service
    client = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, client))
    client.search_error = None
    clock.advance(3600)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        request = lookup_request(instance, sample, client)

    assert titles(request.result) == []
    request.partial.assert_not_called()
    assert client.calls == ["analysis_search", "analysis_search"]
    assert any(
        record.levelno >= logging.INFO and "clos" in record.getMessage().lower()
        and ("quota" in record.getMessage().lower() or "cooldown" in record.getMessage().lower())
        for record in caplog.records
    )
    assert instance.api_key not in caplog.text
    assert client.uploads == []


def test_cooldown_skip_and_half_open_probe_in_progress_have_distinct_partial_notices(service, clock):
    instance, sample = service
    exhausted = Client(search=[], infos={}, search_error=daily_request_quota())
    assert_quota_notice(lookup_request(instance, sample, exhausted))
    cooldown_skip = lookup_request(instance, sample, exhausted)
    assert_quota_notice(cooldown_skip)
    peer = svc.JoeSandboxV2({"api_key": instance.api_key, "api_url": instance.api_url})
    peer.start()
    peer_client = Client(search=[], infos={})
    overlap = []

    def another_task_during_probe() -> None:
        overlap.append(lookup_request(peer, sample, peer_client))

    clock.advance(3600)
    probe = Client(search=[], infos={}, search_callback=another_task_during_probe)
    request = lookup_request(instance, sample, probe)

    assert titles(request.result) == []
    assert len(overlap) == 1
    assert_quota_notice(overlap[0])
    cooldown_body = cooldown_skip.result.sections[-1].body.lower()
    probe_body = overlap[0].result.sections[-1].body.lower()
    assert "cooldown" in cooldown_body
    assert "probe" in probe_body and "progress" in probe_body
    assert cooldown_body != probe_body
    assert exhausted.calls == ["analysis_search"]
    assert probe.calls == ["analysis_search"]
    assert peer_client.calls == []
    assert exhausted.uploads == probe.uploads == peer_client.uploads == []


@pytest.mark.parametrize("row", [
    pytest.param({"webid": "1000001"}, id="id-only"),
    pytest.param(
        {"webid": "1000001", "time": "2026-01-02T03:04:05+01:00"}, id="timestamp-without-status",
    ),
    pytest.param(
        {"webid": "1000001", "status": "unknown", "time": "2026-01-02T03:04:05+01:00"},
        id="unknown-status-with-timestamp",
    ),
])
def test_fallback_info_quota_preserves_failed_candidate_id_link_and_available_search_time(service, row):
    instance, sample = service
    client = Client(
        search=[row, {"webid": "1000002", "status": "running", "time": "2026-01-03T10:00:00+01:00"}],
        infos={"1000001": daily_request_quota()},
    )

    request = lookup_request(instance, sample, client, upload=True)

    assert_quota_notice(request)
    text = "\n".join(section.body for section in request.result.sections)
    assert "1000001" in text
    assert "https://www.joesandbox.com/analysis/1000001/0/html" in text
    if "time" in row:
        assert row["time"] in text
    assert client.calls == ["analysis_search", "analysis_info"]
    assert client.info_ids == ["1000001"]
    assert client.downloads == []
    assert client.uploads == []


@pytest.mark.parametrize("upload", [False, True])
def test_unresolved_partial_lists_only_five_newest_unique_candidate_ids_and_report_links(service, upload):
    instance, sample = service
    client = Client(
        search=[
            {"webid": "1000002"}, {"webid": "1000006"}, {"webid": "1000001"},
            {"webid": "1000004"}, {"webid": "1000006"}, {"webid": "1000005"}, {"webid": "1000003"},
        ],
        infos={str(webid): {"status": "unknown"} for webid in range(1000001, 1000007)},
    )

    request = lookup_request(instance, sample, client, upload=upload)

    request.partial.assert_called_once_with()
    assert request.result.sections
    assert all(section.heuristic is None for section in request.result.sections)
    text = "\n".join(section.body for section in request.result.sections)
    expected_ids = ["1000006", "1000005", "1000004", "1000003", "1000002"]
    expected_links = [f"https://www.joesandbox.com/analysis/{webid}/0/html" for webid in expected_ids]
    for webid, link in zip(expected_ids, expected_links, strict=True):
        assert webid in text
        assert text.count(link) == 1
    positions = [text.index(link) for link in expected_links]
    assert positions == sorted(positions)
    assert "1000001" not in text
    assert client.calls == ["analysis_search"] + ["analysis_info"] * 5
    assert client.info_ids == expected_ids
    assert client.downloads == []
    assert client.uploads == []


@pytest.mark.parametrize("response", [
    pytest.param(None, id="null"),
    pytest.param([], id="list"),
    pytest.param("S-1", id="string"),
    pytest.param(42, id="number"),
    pytest.param(True, id="boolean"),
    pytest.param({}, id="missing-submission-id"),
    pytest.param({"submission_id": None}, id="null-submission-id"),
    pytest.param({"submission_id": ""}, id="empty-submission-id"),
    pytest.param({"submission_id": " \t"}, id="blank-submission-id"),
    pytest.param({"submission_id": []}, id="list-submission-id"),
    pytest.param({"submission_id": {}}, id="mapping-submission-id"),
])
def test_malformed_upload_response_fails_immediately_and_warns_file_may_already_be_uploaded(
    poll_window, response,
):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos=FINISHED, submit_response=response)

    with pytest.raises(RecoverableError) as failure:
        lookup_request(instance, sample, client, upload=True)

    message = str(failure.value).lower()
    assert "upload" in message
    assert "may" in message and "already" in message
    assert "response" in message or "submission" in message
    assert client.calls == ["analysis_search", "submit_sample"]
    assert client.submission_ids == []
    assert client.uploads == ["sample.bin"]
    assert sleeps == []


@pytest.mark.parametrize("response", [
    pytest.param(None, id="null"),
    pytest.param([], id="empty-list"),
    pytest.param([{"status": "finished"}], id="list"),
    pytest.param("finished", id="string"),
    pytest.param(42, id="number"),
    pytest.param(True, id="boolean"),
])
def test_nonmapping_submission_status_response_is_immediately_recoverable_with_submission_id(
    poll_window, response,
):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos=FINISHED, submission_response=response)

    with pytest.raises(RecoverableError) as failure:
        lookup_request(instance, sample, client, upload=True)

    message = str(failure.value).lower()
    assert "s-1" in message
    assert "status" in message or "submission_info" in message
    assert "invalid" in message or "malformed" in message or "mapping" in message
    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.submission_ids == ["S-1"]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []


@pytest.mark.parametrize("metadata", [
    pytest.param({}, id="no-analysis-metadata"),
    pytest.param({"most_relevant_analysis": None}, id="null-preferred-analysis"),
    pytest.param({"most_relevant_analysis": []}, id="list-preferred-analysis"),
    pytest.param({"most_relevant_analysis": "invalid"}, id="scalar-preferred-analysis"),
    pytest.param({"most_relevant_analysis": {"webid": None}}, id="null-preferred-id"),
    pytest.param({"most_relevant_analysis": {"webid": ""}}, id="empty-preferred-id"),
    pytest.param({"most_relevant_analysis": {"webid": " \t"}}, id="blank-preferred-id"),
    pytest.param({"most_relevant_analysis": {"webid": []}}, id="list-preferred-id"),
    pytest.param({"most_relevant_analysis": {"webid": {}}}, id="mapping-preferred-id"),
    pytest.param({"most_relevant_analysis": {"webid": True}}, id="boolean-preferred-id"),
    pytest.param({"analyses": None}, id="null-fallback"),
    pytest.param({"analyses": []}, id="empty-fallback"),
    pytest.param({"analyses": "invalid"}, id="scalar-fallback-container"),
    pytest.param({"analyses": {"webid": "1000001"}}, id="mapping-fallback-container"),
    pytest.param({"analyses": [None, [], "invalid", {}, {"webid": None}]}, id="invalid-fallback-entries"),
])
def test_finished_submission_without_valid_analysis_id_is_immediately_recoverable_not_timeout(
    poll_window, metadata,
):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos=FINISHED, submission_response={"status": "finished", **metadata})

    with pytest.raises(RecoverableError) as failure:
        lookup_request(instance, sample, client, upload=True)

    message = str(failure.value).lower()
    assert "s-1" in message
    assert "finished" in message
    assert "analysis" in message or "webid" in message
    assert "did not finish" not in message
    assert "timeout" not in message
    assert client.calls == ["analysis_search", "submit_sample", "submission_info"]
    assert client.submission_ids == ["S-1"]
    assert client.info_ids == []
    assert client.downloads == []
    assert client.uploads == ["sample.bin"]
    assert sleeps == []


@pytest.mark.parametrize("metadata", [
    pytest.param({"analyses": [{"webid": "1000001"}]}, id="fallback-without-preferred"),
    pytest.param(
        {"most_relevant_analysis": {}, "analyses": [{"webid": "1000001"}]}, id="empty-preferred-fallback",
    ),
    pytest.param(
        {"most_relevant_analysis": {"webid": ""}, "analyses": [{"webid": "1000001"}]},
        id="missing-preferred-id-fallback",
    ),
    pytest.param(
        {"most_relevant_analysis": "invalid", "analyses": [{"webid": "1000001"}]},
        id="malformed-preferred-fallback",
    ),
    pytest.param({
        "analyses": [None, [], "invalid", {}, {"webid": None}, {"webid": ""},
                     {"webid": "1000001"}, {"webid": "1000002"}],
    }, id="first-valid-fallback-entry"),
    pytest.param(
        {"most_relevant_analysis": {"webid": 1000001}}, id="numeric-preferred-id",
    ),
    pytest.param({
        "most_relevant_analysis": {"webid": "1000001"},
        "analyses": [{"webid": "1000002"}],
    }, id="preferred-wins-over-fallback"),
    pytest.param({
        "analyses": [MappingProxyType({"webid": "1000001"})],
    }, id="mapping-fallback-entry"),
])
def test_valid_finished_submission_metadata_selects_preferred_or_first_valid_fallback_without_extra_calls(
    poll_window, metadata,
):
    instance, sample, sleeps = poll_window
    client = Client(search=[], infos=FINISHED, submission_response={"status": "finished", **metadata})

    request = lookup_request(instance, sample, client, upload=True)

    assert titles(request.result)[:2] == ["Joe Sandbox analysis", "File uploaded to Joe Sandbox"]
    assert "public" in request.result.sections[1].body.lower()
    request.partial.assert_not_called()
    assert client.calls == [
        "analysis_search", "submit_sample", "submission_info", "analysis_info", "analysis_download",
    ]
    assert client.submission_ids == ["S-1"]
    assert client.info_ids == ["1000001"]
    assert client.downloads == [("1000001", "irjsonfixed")]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []


def test_mapping_upload_and_submission_status_responses_succeed_with_five_calls(poll_window):
    instance, sample, sleeps = poll_window
    client = Client(
        search=[], infos=FINISHED,
        submit_response=MappingProxyType({"submission_id": "S-1"}),
        submission_response=MappingProxyType({
            "status": "finished", "most_relevant_analysis": MappingProxyType({"webid": "1000001"}),
        }),
    )

    request = lookup_request(instance, sample, client, upload=True)

    assert titles(request.result)[:2] == ["Joe Sandbox analysis", "File uploaded to Joe Sandbox"]
    request.partial.assert_not_called()
    assert client.calls == [
        "analysis_search", "submit_sample", "submission_info", "analysis_info", "analysis_download",
    ]
    assert client.submission_ids == ["S-1"]
    assert client.downloads == [("1000001", "irjsonfixed")]
    assert client.uploads == ["sample.bin"]
    assert sleeps == []
