"""Unit tests for the pure report helpers (no AssemblyLine runtime, no network)."""

import pytest

from joesandboxv2.analysis import (
    MAX_ROWS,
    Contact,
    DroppedFile,
    InvalidScope,
    in_lookup_scope,
    may_upload,
    newest_first,
    parse_report,
)


def test_newest_first_orders_by_webid_and_dedupes():
    results = [{"webid": "1000001"}, {"webid": "999"}, {"webid": "1000002"}, {"webid": "1000001"}, {"x": 1}]
    assert newest_first(results) == ["1000002", "1000001", "999"]


def test_newest_first_puts_non_numeric_ids_last():
    assert newest_first([{"webid": "abc"}, {"webid": "5"}]) == ["5", "abc"]


@pytest.mark.parametrize(
    "detection,verdict",
    [
        ({"malicious": True, "suspicious": True}, "malicious"),  # strongest verdict wins
        ({"suspicious": "true"}, "suspicious"),                  # booleans may arrive as strings
        ({"clean": True}, "clean"),
        ({"malicious": "false"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_verdict(detection, verdict):
    assert parse_report({"analysis": {"detection": detection}}).verdict == verdict


def test_parse_report_flattens_contacts_and_dropped_files():
    report = parse_report({"analysis": {
        "contacted": {
            "domains": {"domain": [{"name": "a.example", "malicious": True, "ip": "192.0.2.1"},
                                   {"name": "b.example", "malicious": False, "ip": "unknown"}]},
            "ips": {"ip": {"@malicious": "true", "$": "192.0.2.1"}},  # single entry written as an object
            "urls": {"url": [{"name": "http://a.example/x", "malicious": "false"}]},
        },
        "dropped": {"file": [{"name": "C:\\x.exe", "malicious": True, "sha256": "ABC"}, {"malicious": True}]},
        "signatures": {"signare": ["Sig one", "", None]},
        "arch": "WINDOWS",
    }})
    assert report.contacts == [
        Contact("domain", "a.example", True, "192.0.2.1"),
        Contact("domain", "b.example", False, None),
        Contact("ip", "192.0.2.1", True),
        Contact("uri", "http://a.example/x", False, None),
    ]
    assert report.dropped == [DroppedFile("C:\\x.exe", True, "abc")]  # entries without a name are skipped
    assert report.signatures == ["Sig one"]
    assert report.platform == "Windows"


def test_parse_report_tolerates_null_and_missing_sections():
    report = parse_report({"analysis": {"contacted": {"ips": None, "domains": None, "urls": None},
                                        "dropped": None, "signatures": None, "arch": "AMIGA"}})
    assert (report.contacts, report.dropped, report.signatures, report.platform) == ([], [], [], None)
    assert parse_report({}).verdict == "unknown"


def test_parse_report_caps_rows():
    many = {"domain": [{"name": f"h{i}.example"} for i in range(MAX_ROWS + 50)]}
    assert len(parse_report({"analysis": {"contacted": {"domains": many}}}).contacts) == MAX_ROWS


@pytest.mark.parametrize(
    "depth,file_type,depth_param,types_param,expected",
    [
        (6, "archive/zip", 6, ".*", True),
        (7, "archive/zip", 6, ".*", False),
        (2, "document/pdf", 2, ".*", True),
        (3, "document/pdf", 2, ".*", False),
        (0, "archive/zip", 0, "executable/.*", True),
        (0, "archive/zip", 0, "[", True),
        (1, "executable/windows/pe32", 6, "executable/.*", True),
        (1, "archive/zip", 6, "executable/.*", False),
        (1, "executable/windows/pe32", 6, "windows", False),
        (6, "archive/zip", None, ".*", True),
        (7, "archive/zip", None, ".*", False),
        (6, "archive/zip", "abc", ".*", True),
        (7, "archive/zip", "abc", ".*", False),
        (0, "archive/zip", -1, ".*", True),
        (1, "archive/zip", -1, ".*", False),
        (1, "archive/zip", 6, "", True),
        (1, "archive/zip", 6, None, True),
        (1, "archive/zip", 6, 42, True),
        (1, "", 6, ".*", True),
        (2, "document/pdf", "2", "document/.*", True),
        (7, "archive/zip", 6, "[", False),
    ],
)
def test_lookup_scope(depth, file_type, depth_param, types_param, expected):
    assert in_lookup_scope(depth, file_type, depth_param, types_param) is expected


def test_lookup_scope_rejects_invalid_extracted_types():
    with pytest.raises(InvalidScope, match="extracted_types.*not a valid regular expression"):
        in_lookup_scope(1, "archive/zip", 6, "[")


@pytest.mark.parametrize(
    "depth,upload_extracted,expected",
    [
        (0, True, True),
        (0, False, True),
        (0, None, True),
        (0, "true", True),
        (1, True, True),
        (1, False, False),
        (1, None, False),
        (1, "true", False),
    ],
)
def test_upload_scope(depth, upload_extracted, expected):
    assert may_upload(depth, upload_extracted) is expected
