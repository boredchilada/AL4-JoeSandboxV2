"""Service behaviour around Joe Sandbox: lookup-only by default, opt-in upload, failure handling."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
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


class Client:
    """Scriptable Joe Sandbox client: one analysis per test, uploads recorded."""

    def __init__(self, search: list[dict], infos: dict[str, dict], submit_error: Exception | None = None,
                 submission_status: str = "finished", search_error: Exception | None = None) -> None:
        self.search, self.infos = search, infos
        self.submit_error, self.submission_status, self.search_error = submit_error, submission_status, search_error
        self.uploads: list[str] = []
        self.calls: list[str] = []

    def analysis_search(self, query: str) -> list[dict]:
        self.calls.append("analysis_search")
        if self.search_error:
            raise self.search_error
        return self.search

    def analysis_info(self, webid: str) -> dict:
        self.calls.append("analysis_info")
        return self.infos[webid]

    def analysis_download(self, webid: str, type: str) -> tuple[str, bytes]:  # noqa: A002 (jbxapi's name)
        self.calls.append("analysis_download")
        return "report.json", json.dumps(FIXTURE["report"]["1000001"]).encode()

    def submit_sample(self, sample: tuple, params: dict | None = None) -> dict:
        self.calls.append("submit_sample")
        self.uploads.append(sample[0])
        self.params = params
        if self.submit_error:
            raise self.submit_error
        return {"submission_id": "S-1"}

    def submission_info(self, submission_id: str) -> dict:
        self.calls.append("submission_info")
        return {"status": self.submission_status, "most_relevant_analysis": {"webid": "1000001"}}


FINISHED = {"1000001": FIXTURE["info"]["1000001"]}


@pytest.fixture
def service(monkeypatch, tmp_path):
    instance = svc.JoeSandboxV2({"api_key": "offline-test-key", "submission_timeout": 0, "poll_interval": 0,
                                 "systems": "w10x64"})
    instance.start()
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


def test_known_file_is_never_uploaded_even_when_upload_is_on(service):
    instance, sample = service
    client = Client(search=[{"webid": "1000001"}], infos=FINISHED)
    result = run(instance, sample, client, upload=True)
    assert client.uploads == []
    assert titles(result)[0] == "Joe Sandbox analysis"
    # The Sandbox ontology part must validate against AL's model (add_result_part drops invalid data).
    assert [type(p).__name__ for p in instance.ontology._result_parts.values()] == ["Sandbox"]


def test_running_analysis_is_retried_not_uploaded(service):
    instance, sample = service
    client = Client(search=[{"webid": "1000002"}], infos={"1000002": {"status": "running"}})
    with pytest.raises(RecoverableError, match="1000002"):
        run(instance, sample, client, upload=True)
    assert client.uploads == []


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
    assert client.calls == ["analysis_search", "analysis_info", "analysis_info", "analysis_download"]
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
