"""Pure helpers for Joe Sandbox lookups and irjsonfixed reports. No AssemblyLine imports."""

import re
from dataclasses import dataclass, field
from typing import Any

# Joe Sandbox verdict -> manifest heuristic id.
VERDICT_HEURISTIC = {"malicious": 1, "suspicious": 2, "clean": 3, "unknown": 3}

# Platform names accepted by AssemblyLine's Sandbox ontology model.
PLATFORMS = {"WINDOWS": "Windows", "LINUX": "Linux", "MACOS": "MacOS", "ANDROID": "Android", "IOS": "iOS"}

# Hostile or very large reports must not produce unbounded results.
MAX_ROWS = 500
DEFAULT_LOOKUP_DEPTH = 6


class InvalidScope(ValueError):
    """extracted_types is not a valid regular expression."""


def in_lookup_scope(depth: int, file_type: str, depth_param: object, types_param: object) -> bool:
    """Whether a file is looked up: within lookup_depth and, for extracted files, matching extracted_types."""
    try:
        limit = max(0, int(str(depth_param)))
    except ValueError:
        limit = DEFAULT_LOOKUP_DEPTH
    if depth > limit:
        return False
    if depth == 0:
        return True
    pattern = types_param if isinstance(types_param, str) and types_param else ".*"
    try:
        return re.match(pattern, file_type or "") is not None
    except re.error as exc:
        raise InvalidScope(f"Submission parameter extracted_types is not a valid regular expression: {exc}") from None


def may_upload(depth: int, upload_extracted: object) -> bool:
    """Uploads apply to the submitted file; to extracted files only when upload_extracted is true."""
    return depth == 0 or upload_extracted is True


@dataclass(frozen=True)
class Contact:
    kind: str  # "domain", "ip" or "uri"
    value: str
    malicious: bool
    resolved_ip: str | None = None


@dataclass(frozen=True)
class DroppedFile:
    path: str
    malicious: bool
    sha256: str | None


@dataclass
class Report:
    analysis_id: str
    sample: str
    verdict: str
    score: int | None
    confidence: int | None
    system: str
    version: str
    platform: str | None
    signatures: list[str] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    dropped: list[DroppedFile] = field(default_factory=list)


def newest_first(search_results: list[dict]) -> list[str]:
    """Web IDs from an analysis search, newest first. Joe Sandbox web IDs increase over time."""
    webids = {str(r["webid"]) for r in search_results if r.get("webid") is not None}
    return sorted(webids, key=lambda w: (w.isdigit(), int(w) if w.isdigit() else 0), reverse=True)


def _items(container: Any, key: str) -> list[dict]:
    """Entries of an irjsonfixed list node such as ``{"domain": [...]}``; tolerates null and single dicts."""
    if not isinstance(container, dict):
        return []
    value = container.get(key)
    if isinstance(value, dict):
        value = [value]
    return [v for v in value or [] if isinstance(v, dict)]


def _flag(value: Any) -> bool:
    """irjsonfixed writes booleans either as JSON booleans or as the strings "true"/"false"."""
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _resolved(ip: Any) -> str | None:
    return ip if isinstance(ip, str) and ip and ip != "unknown" else None


def parse_report(report: dict) -> Report:
    """Turn an irjsonfixed report into a :class:`Report`."""
    analysis = report.get("analysis") or {}
    detection = analysis.get("detection") or {}
    verdict = next((v for v in ("malicious", "suspicious", "clean", "unknown") if _flag(detection.get(v))), "unknown")
    score = detection.get("score")
    confidence = (analysis.get("confidence") or {}).get("score")
    contacted = analysis.get("contacted") or {}

    contacts: list[Contact] = []
    for item in _items(contacted.get("domains"), "domain"):
        if item.get("name"):
            contacts.append(Contact("domain", item["name"], _flag(item.get("malicious")), _resolved(item.get("ip"))))
    for item in _items(contacted.get("ips"), "ip"):
        if item.get("$"):
            contacts.append(Contact("ip", item["$"], _flag(item.get("@malicious"))))
    for item in _items(contacted.get("urls"), "url"):
        if item.get("name"):
            contacts.append(Contact("uri", item["name"], _flag(item.get("malicious")), _resolved(item.get("ip"))))

    dropped = [
        DroppedFile(item["name"], _flag(item.get("malicious")), (item.get("sha256") or "").lower() or None)
        for item in _items(analysis.get("dropped"), "file")
        if item.get("name")
    ]
    signatures = [s for s in (analysis.get("signatures") or {}).get("signare") or [] if isinstance(s, str) and s]

    return Report(
        analysis_id=str(analysis.get("id") or ""),
        sample=str(analysis.get("sample") or ""),
        verdict=verdict,
        score=score if isinstance(score, int) else None,
        confidence=confidence if isinstance(confidence, int) else None,
        system=str(analysis.get("system") or ""),
        version=str(analysis.get("version") or ""),
        platform=PLATFORMS.get(str(analysis.get("arch") or "").upper()),
        signatures=signatures[:MAX_ROWS],
        contacts=contacts[:MAX_ROWS],
        dropped=dropped[:MAX_ROWS],
    )
