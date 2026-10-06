"""AssemblyLine 4 service that shows Joe Sandbox results for a file.

By default the service only looks up the file's SHA-256 on Joe Sandbox and reports the newest
finished analysis; the file never leaves AssemblyLine. Uploading the file is opt-in per
submission (``submit_to_joesandbox``), happens only when no analysis exists or is running, and
on Joe Sandbox Cloud Basic makes the file and its report public.
"""

import json
import os
import time
from dataclasses import dataclass
from typing import cast

import jbxapi
from assemblyline.common.exceptions import NonRecoverableError, RecoverableError
from assemblyline.odm.models.ontology.results.sandbox import Sandbox
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultKeyValueSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

from joesandboxv2.analysis import (
    VERDICT_HEURISTIC,
    InvalidScope,
    Report,
    in_lookup_scope,
    may_upload,
    newest_first,
    parse_report,
)

DEFAULT_API_URL = "https://www.joesandbox.com/api/"
DEFAULT_REPORT_URL = "https://www.joesandbox.com/analysis/{webid}/0/html"
# Analyses checked per lookup when looking for the newest finished one.
MAX_ANALYSES_CHECKED = 5
TAG_FOR_CONTACT = {"domain": "network.dynamic.domain", "ip": "network.dynamic.ip", "uri": "network.dynamic.uri"}


@dataclass
class Lookup:
    finished: str | None  # newest finished analysis
    running: str | None  # newest analysis still in progress


class JoeSandboxV2(ServiceBase):
    def start(self) -> None:
        config = self.config or {}
        self.api_key = str(config.get("api_key") or os.environ.get("JBX_API_KEY") or "")
        self.api_url = str(config.get("api_url") or DEFAULT_API_URL)
        self.report_url = str(config.get("report_url") or DEFAULT_REPORT_URL)
        self.submission_timeout = int(config.get("submission_timeout", 1200))
        self.poll_interval = int(config.get("poll_interval", 30))
        # Analysis systems for uploads. Joe Sandbox Cloud Basic needs an explicit list: its automatic
        # choice can name a system the account does not have ("Unknown system android9").
        self.systems = [s.strip() for s in str(config.get("systems", "w10x64")).split(",") if s.strip()]
        if not self.api_key:
            self.log.error("No Joe Sandbox API key: set api_key in the service configuration")

    def get_tool_version(self) -> str:
        return f"jbxapi {jbxapi.__version__}"

    def make_client(self) -> jbxapi.JoeSandbox:
        # accept_tac only takes effect on uploads, which happen when the user opts in per submission.
        return jbxapi.JoeSandbox(apikey=self.api_key, apiurl=self.api_url, accept_tac=True,
                                 timeout=60, retries=3, user_agent="AssemblyLine JoeSandboxV2")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result
        try:
            in_scope = in_lookup_scope(
                cast(int, request.task.depth), request.file_type,
                request.get_param("lookup_depth"), request.get_param("extracted_types"),
            )
        except InvalidScope as exc:
            raise NonRecoverableError(str(exc)) from None
        if not in_scope:
            # Partial: AssemblyLine must not reuse this empty result for a submission that looks deeper or wider.
            request.partial()
            return
        uploads_allowed = may_upload(cast(int, request.task.depth), request.get_param("upload_extracted"))
        if not self.api_key:
            raise NonRecoverableError("No Joe Sandbox API key configured (service setting api_key)")
        client = self.make_client()

        lookup = self._lookup(client, request.sha256)
        webid, submitted = lookup.finished, False
        if webid is None:
            if lookup.running is not None:
                # Not cached by AL: the retry fetches the finished report instead of uploading again.
                raise RecoverableError(f"Joe Sandbox analysis {lookup.running} of this file is still running")
            if not uploads_allowed or not request.get_param("submit_to_joesandbox"):
                return  # nothing known about this file; uploading is off
            webid = self._submit_and_wait(client, request, result)
            if webid is None:
                return
            submitted = True

        try:
            info = client.analysis_info(webid)
            _, raw = client.analysis_download(webid, "irjsonfixed")
            report = parse_report(json.loads(raw))
        except jbxapi.JoeException as exc:
            raise RecoverableError(f"Joe Sandbox report {webid} could not be fetched: {exc}") from exc
        except ValueError as exc:
            raise RecoverableError(f"Joe Sandbox report {webid} is not valid JSON: {exc}") from exc
        self._add_report(result, webid, info or {}, report, submitted)

    # -- Joe Sandbox calls ----------------------------------------------------------------

    def _lookup(self, client: jbxapi.JoeSandbox, sha256: str) -> Lookup:
        try:
            webids = newest_first(client.analysis_search(sha256))
            running = None
            for webid in webids[:MAX_ANALYSES_CHECKED]:
                status = (client.analysis_info(webid) or {}).get("status")
                if status == "finished":
                    return Lookup(finished=webid, running=running)
                if status in ("submitted", "running", "accepted") and running is None:
                    running = webid
            return Lookup(finished=None, running=running)
        except jbxapi.InvalidApiKeyError as exc:
            raise NonRecoverableError(f"Joe Sandbox rejected the API key: {exc}") from exc
        except jbxapi.JoeException as exc:
            raise RecoverableError(f"Joe Sandbox lookup failed: {exc}") from exc

    def _submit_and_wait(self, client: jbxapi.JoeSandbox, request: ServiceRequest, result: Result) -> str | None:
        """Upload the file and wait for its analysis. Returns the web ID, or None after reporting why not.

        A refused upload is reported in the result. If the analysis does not finish in time the
        service raises RecoverableError; AL's retry then finds the analysis by hash and does not
        upload the file again.
        """
        try:
            with open(request.file_path, "rb") as handle:
                params = {"systems": self.systems} if self.systems else {}
                submission = client.submit_sample((request.file_name or request.sha256, handle), params=params)
        except jbxapi.InvalidApiKeyError as exc:
            raise NonRecoverableError(f"Joe Sandbox rejected the API key: {exc}") from exc
        except jbxapi.ApiError as exc:
            # Quota exhausted, file type refused, terms not accepted: Joe Sandbox's own message says which.
            section = ResultTextSection("Joe Sandbox did not accept the upload")
            section.add_line(str(exc))
            result.add_section(section)
            return None
        except jbxapi.JoeException as exc:
            raise RecoverableError(f"Joe Sandbox upload failed: {exc}") from exc

        submission_id = str(submission.get("submission_id") or "")
        deadline = time.monotonic() + self.submission_timeout
        while True:  # check at least once, then until the deadline
            try:
                status = client.submission_info(submission_id) or {}
            except jbxapi.JoeException as exc:
                self.log.warning(f"Joe Sandbox submission {submission_id} status check failed: {exc}")
                status = {}
            if status.get("status") == "finished":
                best = status.get("most_relevant_analysis") or next(iter(status.get("analyses") or []), {})
                if best.get("webid"):
                    return str(best["webid"])
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(self.poll_interval)

        raise RecoverableError(f"Uploaded to Joe Sandbox as submission {submission_id}; the analysis did not finish "
                               f"within {self.submission_timeout} s. AL retries and fetches it by hash without "
                               "uploading again.")

    # -- Result building ------------------------------------------------------------------

    def _add_report(self, result: Result, webid: str, info: dict, report: Report, submitted: bool) -> None:
        summary = ResultKeyValueSection("Joe Sandbox analysis")
        summary.set_item("verdict", report.verdict)
        if report.score is not None:
            summary.set_item("score", f"{report.score}/100")
        if report.confidence is not None:
            summary.set_item("confidence", f"{report.confidence}/5")
        summary.set_item("analysis_id", webid)
        summary.set_item("report", self.report_url.format(webid=webid))
        summary.set_item("analysed_at", str(info.get("time") or ""))
        summary.set_item("system", report.system)
        summary.set_item("uploaded_by_this_service", submitted)
        summary.set_heuristic(VERDICT_HEURISTIC[report.verdict])
        result.add_section(summary)

        if submitted:
            notice = ResultTextSection("File uploaded to Joe Sandbox")
            notice.add_line("This file was uploaded because the submission enabled submit_to_joesandbox. "
                            "On Joe Sandbox Cloud Basic the file and its report are public.")
            result.add_section(notice)

        if report.signatures:
            sigs = ResultTableSection("Joe Sandbox behaviour signatures")
            for name in report.signatures:
                sigs.add_row(TableRow({"signature": name}))
                sigs.add_tag("dynamic.signature.name", name)
            result.add_section(sigs)

        if report.contacts:
            network = ResultTableSection("Network activity observed by Joe Sandbox")
            for contact in report.contacts:
                network.add_row(TableRow({"type": contact.kind, "value": contact.value,
                                          "malicious": contact.malicious, "resolved_ip": contact.resolved_ip or ""}))
                network.add_tag(TAG_FOR_CONTACT[contact.kind], contact.value)
                if contact.resolved_ip:
                    network.add_tag("network.dynamic.ip", contact.resolved_ip)
            result.add_section(network)

        if report.dropped:
            dropped = ResultTableSection("Files dropped during the Joe Sandbox analysis")
            for item in report.dropped:
                dropped.add_row(TableRow({"path": item.path, "malicious": item.malicious, "sha256": item.sha256 or ""}))
            result.add_section(dropped)

        start = str(info.get("time") or "")
        if start:
            # add_result_part takes the model class; its type hint says instance.
            self.ontology.add_result_part(Sandbox, {  # type: ignore[arg-type]
                "objectid": {"tag": f"joesandbox_{webid}"},
                "analysis_metadata": {"task_id": webid, "start_time": start,
                                      "machine_metadata": {"platform": report.platform, "version": report.system}},
                "sandbox_name": "Joe Sandbox",
                "sandbox_version": report.version or None,
            })
