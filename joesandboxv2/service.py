"""AssemblyLine 4 service that shows Joe Sandbox results for a file.

By default the service only looks up the file's SHA-256 on Joe Sandbox and reports the newest
finished analysis; the file never leaves AssemblyLine. Uploading the file is opt-in per
submission (``submit_to_joesandbox``), happens only after an empty hash search, and
on Joe Sandbox Cloud Basic makes the file and its report public.
"""

import json
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
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
from joesandboxv2.settings import config_fingerprint, config_int, config_list, config_str

DEFAULT_API_URL = "https://www.joesandbox.com/api/"
DEFAULT_REPORT_URL = "https://www.joesandbox.com/analysis/{webid}/0/html"
# Defaults of the service settings; tests assert they equal service_manifest.yml.
DEFAULTS = {
    "submission_timeout": 1200,
    "poll_interval": 30,
    "quota_cooldown_seconds": 3600,
    "timeout": 60,
    "retries": 3,
    "systems": "w10x64",
}
MIN_SUBMISSION_TIMEOUT = 60
SERVICE_TIMEOUT_HEADROOM = 60  # seconds between the end of the upload wait and the manifest timeout
DEFAULT_SERVICE_TIMEOUT = 1500  # manifest timeout, used only if AL reports none
SYSTEM_NAME = re.compile(r"[A-Za-z0-9_.-]{1,40}")
# Analyses checked per lookup when looking for the newest finished one.
MAX_ANALYSES_CHECKED = 5
ANALYSIS_STATUSES = ("finished", "submitted", "running", "accepted")
TAG_FOR_CONTACT = {"domain": "network.dynamic.domain", "ip": "network.dynamic.ip", "uri": "network.dynamic.uri"}


@dataclass
class Lookup:
    finished: str | None  # newest finished analysis
    running: str | None  # newest analysis still in progress
    info: dict | None = None  # metadata already obtained for the finished analysis
    has_matches: bool = False


@dataclass
class CallContext:
    phase: str = "search"
    webid: str | None = None
    info: dict | None = None
    submitted: bool = False
    submission_id: str | None = None
    candidates: list[str] | None = None


@dataclass
class QuotaCooldown:
    retry_at: float
    probing: bool = False


# Shared by service instances in this worker process; credentials never enter registry keys.
_QUOTA_COOLDOWNS: dict[tuple[str, str], QuotaCooldown] = {}
_QUOTA_LOCK = Lock()


def is_daily_request_quota(exc: jbxapi.JoeException) -> bool:
    return isinstance(exc, jbxapi.ApiError) and (
        "you have exceeded the number of available api requests today" in str(exc).casefold()
    )


def _identifier(value: object) -> str | None:
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


class JoeSandboxV2(ServiceBase):
    def start(self) -> None:
        config = self.config or {}
        log = self.log
        self.api_key = config_str(config, "api_key", "", log) or os.environ.get("JBX_API_KEY", "")
        self.api_url = config_str(config, "api_url", DEFAULT_API_URL, log)
        self.report_url = config_str(config, "report_url", DEFAULT_REPORT_URL, log)
        # The upload wait must end before the service timeout so AL gets a recoverable error, not a kill.
        manifest_timeout = int(getattr(self.service_attributes, "timeout", 0) or DEFAULT_SERVICE_TIMEOUT)
        self.submission_timeout = config_int(
            config, "submission_timeout", DEFAULTS["submission_timeout"], MIN_SUBMISSION_TIMEOUT,
            max(MIN_SUBMISSION_TIMEOUT, manifest_timeout - SERVICE_TIMEOUT_HEADROOM), log,
        )
        self.poll_interval = config_int(config, "poll_interval", DEFAULTS["poll_interval"], 5, 300, log)
        self.quota_cooldown_seconds = config_int(
            config, "quota_cooldown_seconds", DEFAULTS["quota_cooldown_seconds"], 0, 86400, log,
        )
        self.http_timeout = config_int(config, "timeout", DEFAULTS["timeout"], 5, 120, log)
        self.retries = config_int(config, "retries", DEFAULTS["retries"], 0, 10, log)
        # Analysis systems for uploads. Joe Sandbox Cloud Basic needs an explicit list: its automatic
        # choice can name a system the account does not have ("Unknown system android9").
        self.systems = config_list(config, "systems", [DEFAULTS["systems"]], log)
        if not self.api_key:
            self.log.error("No Joe Sandbox API key: set api_key in the service configuration")

    def get_tool_version(self) -> str:
        # Service settings are not part of AL's result cache key; the fingerprint makes a setting change a new key.
        return f"jbxapi {jbxapi.__version__}-{config_fingerprint(self.config)}"

    def make_client(self) -> jbxapi.JoeSandbox:
        # accept_tac only takes effect on uploads, which happen when the user opts in per submission.
        return jbxapi.JoeSandbox(apikey=self.api_key, apiurl=self.api_url, accept_tac=True,
                                 timeout=self.http_timeout, retries=self.retries,
                                 user_agent="AssemblyLine JoeSandboxV2")

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
        quota_key = (self.api_url, sha256(self.api_key.encode()).hexdigest())
        with _QUOTA_LOCK:
            probe = _QUOTA_COOLDOWNS.get(quota_key)
            probe_in_progress = probe is not None and probe.probing
            unavailable = probe is not None and (probe_in_progress or time.monotonic() < probe.retry_at)
            if probe is not None and not unavailable:
                probe.probing = True
        if unavailable:
            self._quota_notice(request, result, reason="probe" if probe_in_progress else "cooldown")
            return

        failure = "lookup failed"
        context = CallContext()
        try:
            client = self.make_client()
            lookup = self._lookup(client, request.sha256, context)
            # A completed search/status lookup closes this probe only, not a newer in-flight quota response.
            closed = False
            with _QUOTA_LOCK:
                if probe is not None and _QUOTA_COOLDOWNS.get(quota_key) is probe:
                    del _QUOTA_COOLDOWNS[quota_key]
                    closed = True
            if closed:
                self.log.info("Joe Sandbox quota cooldown closed after a successful search/status lookup")
            webid, submitted = lookup.finished, False
            context.webid, context.info = webid, lookup.info
            if webid is None:
                if lookup.running is not None:
                    if uploads_allowed and request.get_param("submit_to_joesandbox"):
                        raise RecoverableError(
                            f"Joe Sandbox analysis {lookup.running} of this file is still running"
                        )
                    pending = ResultTextSection("Joe Sandbox analysis pending")
                    pending.add_line(f"Analysis {lookup.running} is still in progress.")
                    pending.add_line(self.report_url.format(webid=lookup.running))
                    result.add_section(pending)
                    request.partial()
                    return
                if lookup.has_matches:
                    unavailable_analysis = ResultTextSection("Joe Sandbox lookup incomplete")
                    unavailable_analysis.add_line(
                        "Search found analyses, but the bounded status checks could not identify a finished "
                        "or pending analysis. Lookup coverage is unavailable."
                    )
                    for candidate in context.candidates or ():
                        unavailable_analysis.add_line(f"Analysis ID: {candidate}")
                        unavailable_analysis.add_line(self.report_url.format(webid=candidate))
                    result.add_section(unavailable_analysis)
                    request.partial()
                    return
                if not uploads_allowed or not request.get_param("submit_to_joesandbox"):
                    return  # nothing known about this file; uploading is off
                webid = self._submit_and_wait(client, request, result, context)
                if webid is None:
                    return
                submitted = True
                context.webid = webid

            failure = f"report {webid} could not be fetched"
            if lookup.info is None:
                context.phase = "analysis_info"
                context.info = client.analysis_info(webid)
            context.phase = "analysis_download"
            _, raw = client.analysis_download(webid, "irjsonfixed")
            try:
                payload = json.loads(raw)
            except ValueError as exc:
                raise RecoverableError(f"Joe Sandbox report {webid} is not valid JSON: {exc}") from exc
            try:
                if not isinstance(payload, dict) or not isinstance(payload.get("analysis"), dict):
                    raise ValueError("expected a report object containing an analysis object")
                analysis_id = payload["analysis"].get("id")
                if not isinstance(analysis_id, (str, int)) or str(analysis_id) != webid:
                    raise ValueError("analysis ID is missing or does not match the selected analysis")
                report = parse_report(payload)
            except (ValueError, TypeError, AttributeError) as exc:
                raise RecoverableError(f"Joe Sandbox report {webid} has invalid content: {exc}") from exc
            self._add_report(result, webid, context.info or {}, report, submitted)
        except jbxapi.InvalidApiKeyError as exc:
            raise NonRecoverableError(f"Joe Sandbox rejected the API key: {exc}") from exc
        except jbxapi.JoeException as exc:
            if is_daily_request_quota(exc):
                with _QUOTA_LOCK:
                    reopened = probe is not None or quota_key in _QUOTA_COOLDOWNS
                    _QUOTA_COOLDOWNS[quota_key] = QuotaCooldown(
                        time.monotonic() + self.quota_cooldown_seconds,
                    )
                self.log.warning(
                    f"Joe Sandbox quota cooldown {'reopened' if reopened else 'opened'} "
                    f"during {context.phase}; cooldown {self.quota_cooldown_seconds} seconds"
                )
                self._quota_notice(request, result, context=context)
                return
            raise RecoverableError(f"Joe Sandbox {failure}: {exc}") from exc
        finally:
            # A failed non-quota probe can be retried; never leave the account permanently half-open.
            with _QUOTA_LOCK:
                if probe is not None and _QUOTA_COOLDOWNS.get(quota_key) is probe:
                    probe.probing = False

    # -- Joe Sandbox calls ----------------------------------------------------------------

    def _lookup(self, client: jbxapi.JoeSandbox, sha256: str, context: CallContext) -> Lookup:
        context.phase = "search"
        search = client.analysis_search(sha256)
        rows: dict[str, dict] = {}
        for row in search:
            if row.get("webid") is not None:
                webid = str(row["webid"])
                previous = rows.get(webid)
                if previous is None or (
                    not (previous.get("status") in ANALYSIS_STATUSES and previous.get("time"))
                    and row.get("status") in ANALYSIS_STATUSES and row.get("time")
                ):
                    rows[webid] = row
        running = None
        context.candidates = newest_first(search)[:MAX_ANALYSES_CHECKED]
        for webid in context.candidates:
            info = rows[webid]
            if info.get("status") not in ANALYSIS_STATUSES or not info.get("time"):
                context.phase = "analysis_info"
                context.webid, context.info = webid, info
                info = client.analysis_info(webid) or {}
            status = info.get("status")
            if status == "finished":
                return Lookup(finished=webid, running=running, info=info, has_matches=True)
            if status in ("submitted", "running", "accepted") and running is None:
                running = webid
        return Lookup(finished=None, running=running, has_matches=bool(search))

    def _quota_notice(self, request: ServiceRequest, result: Result, reason: str = "quota",
                      context: CallContext | None = None) -> None:
        if context is not None and context.submitted:
            self._upload_notice(result)
        notice = ResultTextSection("Joe Sandbox lookup unavailable")
        if reason == "probe":
            notice.add_line("A quota recovery probe is in progress for this account; this task made no API calls.")
        elif reason == "cooldown":
            notice.add_line("The account is in a daily API request quota cooldown; this task made no API calls.")
        else:
            notice.add_line("The account's daily API request quota is exhausted.")
        notice.add_line(
            f"Lookups pause for {self.quota_cooldown_seconds} seconds after a quota response; "
            "the next task after that cooldown probes the API."
        )
        if context is not None:
            if context.webid is not None:
                notice.add_line(f"Analysis ID: {context.webid}")
                notice.add_line(self.report_url.format(webid=context.webid))
                if context.info and context.info.get("time"):
                    notice.add_line(f"Analysed at: {context.info['time']}")
            if context.submission_id:
                notice.add_line(f"Submission ID: {context.submission_id}")
        result.add_section(notice)
        request.partial()

    def _upload_systems(self, request: ServiceRequest, result: Result) -> list[str]:
        """Joe Sandbox systems for this upload: the submission's `systems` option, else the service setting."""
        requested = request.get_param("systems")
        names = [n.strip() for n in requested.split(",") if n.strip()] if isinstance(requested, str) else []
        valid = [n for n in names if SYSTEM_NAME.fullmatch(n)]
        invalid = [n for n in names if not SYSTEM_NAME.fullmatch(n)]
        if invalid:
            warning = ResultTextSection("Joe Sandbox systems ignored")
            warning.add_line(
                "These names in the systems option are not valid Joe Sandbox system names and were dropped: "
                + ", ".join(invalid[:5]) + (f" and {len(invalid) - 5} more" if len(invalid) > 5 else "")
            )
            if not valid:
                warning.add_line("The service's systems setting was used instead.")
            result.add_section(warning)
        return valid or self.systems

    def _submit_and_wait(self, client: jbxapi.JoeSandbox, request: ServiceRequest, result: Result,
                         context: CallContext) -> str | None:
        """Upload the file and wait for its analysis. Returns the web ID, or None after reporting why not.

        A refused upload is reported in the result. If the analysis does not finish in time the
        service raises RecoverableError; AL's retry then finds the analysis by hash and does not
        upload the file again.
        """
        context.phase = "upload"
        systems = self._upload_systems(request, result)
        try:
            with open(request.file_path, "rb") as handle:
                params = {"systems": systems} if systems else {}
                submission = client.submit_sample((request.file_name or request.sha256, handle), params=params)
        except jbxapi.InvalidApiKeyError as exc:
            raise NonRecoverableError(f"Joe Sandbox rejected the API key: {exc}") from exc
        except jbxapi.ApiError as exc:
            if is_daily_request_quota(exc):
                raise
            if exc.code in (5, 6):
                raise RecoverableError(f"Joe Sandbox upload failed: {exc}") from exc
            # An ordinary refusal is visible but cannot be cached as a completed negative lookup.
            section = ResultTextSection("Joe Sandbox did not accept the upload")
            section.add_line(str(exc))
            result.add_section(section)
            request.partial()
            return None
        except jbxapi.JoeException as exc:
            raise RecoverableError(f"Joe Sandbox upload failed: {exc}") from exc

        submission_id = _identifier(submission.get("submission_id")) if isinstance(submission, Mapping) else None
        if submission_id is None:
            raise RecoverableError(
                "Joe Sandbox returned an invalid upload response without a valid submission ID; "
                "the file may already have been uploaded."
            )
        context.submitted = True
        context.submission_id = submission_id
        deadline = time.monotonic() + self.submission_timeout
        while True:  # check at least once, then until the deadline
            try:
                context.phase = "submission_info"
                status = client.submission_info(submission_id)
            except jbxapi.InvalidApiKeyError as exc:
                raise NonRecoverableError(
                    f"Joe Sandbox rejected the API key while checking submission {submission_id}: {exc}"
                ) from exc
            except jbxapi.JoeException as exc:
                if is_daily_request_quota(exc):
                    raise
                raise RecoverableError(
                    f"Joe Sandbox submission {submission_id} status check failed: {exc}"
                ) from exc
            if not isinstance(status, Mapping):
                raise RecoverableError(
                    f"Joe Sandbox submission {submission_id} returned an invalid status response; expected a mapping"
                )
            if status.get("status") == "finished":
                preferred = status.get("most_relevant_analysis")
                webid = _identifier(preferred.get("webid")) if isinstance(preferred, Mapping) else None
                if webid is not None:
                    return webid
                analyses = status.get("analyses")
                if isinstance(analyses, list):
                    for analysis in analyses:
                        if isinstance(analysis, Mapping):
                            webid = _identifier(analysis.get("webid"))
                            if webid is not None:
                                return webid
                raise RecoverableError(
                    f"Joe Sandbox submission {submission_id} is finished but returned no valid analysis webid "
                    "in its preferred or fallback analysis metadata"
                )
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
            self._upload_notice(result)

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

    def _upload_notice(self, result: Result) -> None:
        notice = ResultTextSection("File uploaded to Joe Sandbox")
        notice.add_line("This file was uploaded because the submission enabled submit_to_joesandbox. "
                        "On Joe Sandbox Cloud Basic the file and its report are public.")
        result.add_section(notice)
