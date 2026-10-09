# tests/test_scanner.py

from unittest.mock import Mock, patch

import requests

from scanner import (
    evaluate_affected_version,
    parse_requirements,
    query_osv,
    scan_requirements,
)


def test_parse_pinned_requirements():
    text = """
# Example dependencies
Django==2.2.0
requests==2.31.0
flask==2.0.0
"""

    packages = parse_requirements(text)

    assert len(packages) == 3
    assert packages[0]["name"] == "Django"
    assert packages[0]["version"] == "2.2.0"
    assert packages[1]["normalized_name"] == "requests"


def test_parse_ignores_unpinned_and_duplicate_packages():
    text = """
requests==2.31.0
requests==2.32.0
flask>=2.0
numpy
"""

    packages = parse_requirements(text)

    # The parser intentionally supports pinned == requirements only.
    assert len(packages) == 1
    assert packages[0]["normalized_name"] == "requests"
    assert packages[0]["version"] == "2.31.0"


def test_evaluate_version_inside_affected_range():
    affected = {
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.0"},
                {"fixed": "2.0"},
            ],
        }]
    }

    assert evaluate_affected_version("1.5", affected) == "affected"


def test_evaluate_version_at_fixed_boundary():
    affected = {
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.0"},
                {"fixed": "2.0"},
            ],
        }]
    }

    assert evaluate_affected_version("2.0", affected) == "not_affected"


def test_unsupported_range_returns_unknown():
    affected = {
        "ranges": [{
            "type": "GIT",
            "events": [
                {"introduced": "abc123"},
                {"fixed": "def456"},
            ],
        }]
    }

    assert evaluate_affected_version("1.0", affected) == "unknown"


def test_missing_version_returns_unknown():
    assert evaluate_affected_version(None, {"versions": ["1.0"]}) == "unknown"


@patch("scanner.requests.post")
def test_query_osv_preserves_advisory_metadata(mock_post):
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "vulns": [{
            "id": "GHSA-test-1234",
            "summary": "Test vulnerability",
            "details": "Test advisory details",
            "aliases": ["CVE-2025-12345"],
            "affected": [{
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI",
                },
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.0.0"},
                        {"fixed": "2.31.0"},
                    ],
                }],
            }],
            "references": [{
                "type": "WEB",
                "url": "https://example.com/advisory",
            }],
        }]
    }
    mock_post.return_value = mock_response

    package = {
        "name": "requests",
        "normalized_name": "requests",
        "version": "2.30.0",
    }

    result = query_osv(package)

    assert result["status"] == "checked"
    assert len(result["vulnerabilities"]) == 1

    finding = result["vulnerabilities"][0]
    assert finding["id"] == "GHSA-test-1234"
    assert finding["aliases"] == ["CVE-2025-12345"]
    assert finding["applicability"] == "affected"
    assert "https://example.com/advisory" in finding["references"]

    mock_post.assert_called_once()


@patch("scanner.requests.post")
def test_osv_timeout_returns_error(mock_post):
    mock_post.side_effect = requests.Timeout("Request timed out")

    package = {
        "name": "requests",
        "normalized_name": "requests",
        "version": "2.31.0",
    }

    result = query_osv(package)

    assert result["status"] == "error"
    assert "timed out" in result["message"].lower()
    assert result["vulnerabilities"] == []


@patch("scanner.requests.post")
def test_scan_requirements_reports_api_errors(mock_post):
    mock_post.side_effect = requests.ConnectionError("Connection failed")

    result = scan_requirements("requests==2.31.0")

    assert result["status"] == "partial"
    assert len(result["errors"]) == 1
    assert result["packages"][0]["status"] == "error"


def test_empty_requirements_return_error():
    result = scan_requirements("# no dependencies here")

    assert result["status"] == "error"
    assert result["packages"] == []
    assert result["findings"] == []
    

def test_disjoint_ecosystem_ranges():
    affected = {
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.2.5"},
                {"introduced": "2.3.0"},
                {"fixed": "2.3.2"},
            ],
        }]
    }

    assert evaluate_affected_version("2.0.0", affected) == "affected"
    assert evaluate_affected_version("2.2.5", affected) == "not_affected"
    assert evaluate_affected_version("2.3.1", affected) == "affected"
    assert evaluate_affected_version("2.3.2", affected) == "not_affected"

def test_explicit_version_list_does_not_override_range():
    from scanner import evaluate_affected_version

    advisory = {
        "versions": ["2.0.0"],
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "2.3.0"},
                {"fixed": "2.3.2"},
            ],
        }],
    }

    # Conflicting OSV evidence should not be treated as definitive.
    assert evaluate_affected_version("2.0.0", advisory) == "unknown"


def test_git_only_range_returns_unknown():
    from scanner import evaluate_affected_version

    advisory = {
        "ranges": [{
            "type": "GIT",
            "repo": "https://github.com/pallets/flask",
            "events": [
                {"introduced": "0"},
                {"fixed": "abc123"},
            ],
        }],
    }

    assert evaluate_affected_version("2.0.0", advisory) == "unknown"


def test_fixed_version_is_not_affected():
    from scanner import evaluate_affected_version

    advisory = {
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.2.5"},
            ],
        }],
    }

    assert evaluate_affected_version("2.2.5", advisory) == "not_affected"
