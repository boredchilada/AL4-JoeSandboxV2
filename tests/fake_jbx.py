"""Offline stand-in for jbxapi.JoeSandbox, fed by tests/fixtures/jbx/<sha256>.json.

Each fixture holds the responses Joe Sandbox would give for one file: ``search`` (analysis search
results), ``info`` (analysis info by web ID) and ``report`` (irjsonfixed report by web ID). Files
without a fixture are unknown to Joe Sandbox. The fake never touches the network.
"""

import json
import os
from pathlib import Path

import jbxapi

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "jbx"


class FakeJoeSandbox:
    submissions: list[str] = []  # names of files "uploaded", across instances

    def __init__(self, **_: object) -> None:
        self._data: dict = {}

    def _load(self, sha256: str) -> dict:
        path = FIXTURES / f"{sha256}.json"
        self._data = json.loads(path.read_text()) if path.exists() else {}
        return self._data

    def analysis_search(self, query: str) -> list[dict]:
        return self._load(query).get("search", [])

    def analysis_info(self, webid: str) -> dict:
        return self._data["info"][str(webid)]

    def analysis_download(self, webid: str, type: str) -> tuple[str, bytes]:  # noqa: A002 (jbxapi's name)
        assert type == "irjsonfixed"
        return f"report-{webid}.json", json.dumps(self._data["report"][str(webid)]).encode()

    def submit_sample(self, sample: tuple, params: dict | None = None) -> dict:
        FakeJoeSandbox.submissions.append(sample[0])
        raise AssertionError("tests must not upload through the shared fake; patch submit_sample explicitly")


def install() -> None:
    """Replace jbxapi.JoeSandbox and provide an API key, for pytest and for scripts/gentests.py."""
    jbxapi.JoeSandbox = FakeJoeSandbox  # type: ignore[misc]
    os.environ.setdefault("JBX_API_KEY", "offline-test-key")
