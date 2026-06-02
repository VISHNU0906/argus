"""Unit tests for the HTTP security-headers collector.

Exercises the pure header-evaluation logic and the collector behaviour with
the network GET mocked out. No real HTTP requests are made.
"""

from __future__ import annotations

import requests

from argus.collectors import http_headers
from argus.collectors.http_headers import HTTPHeadersCollector, evaluate_headers

WANTED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


class _Cfg:
    """Minimal stand-in for argus.config.Config."""

    def __init__(self, http_targets, headers=None):
        self.http_targets = http_targets
        self.security_headers = headers or list(WANTED)
        self.timeout = 5.0


def _collect_map(collector):
    out = {}
    for metric in collector.collect():
        for sample in metric.samples:
            out[(sample.name, frozenset(sample.labels.items()))] = sample.value
    return out


def key(name, **labels):
    """Build a lookup key matching _collect_map's (name, frozenset) shape."""

    return (name, frozenset(labels.items()))


# ---------------------------------------------------------------------------
# Pure logic: evaluate_headers
# ---------------------------------------------------------------------------


def test_evaluate_headers_all_present():
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    result = evaluate_headers(headers, WANTED)
    assert result == {h: 1 for h in WANTED}


def test_evaluate_headers_all_missing():
    result = evaluate_headers({"Server": "nginx"}, WANTED)
    assert result == {h: 0 for h in WANTED}


def test_evaluate_headers_is_case_insensitive():
    # Server sends lowercase header names; should still count as present.
    headers = {"strict-transport-security": "max-age=31536000"}
    result = evaluate_headers(headers, ["Strict-Transport-Security"])
    assert result == {"Strict-Transport-Security": 1}


def test_evaluate_headers_empty_value_counts_as_missing():
    # A header that is present but blank does not provide protection.
    headers = {"X-Frame-Options": "   "}
    result = evaluate_headers(headers, ["X-Frame-Options"])
    assert result == {"X-Frame-Options": 0}


def test_evaluate_headers_partial():
    headers = {
        "Strict-Transport-Security": "max-age=10",
        "X-Content-Type-Options": "nosniff",
    }
    result = evaluate_headers(headers, WANTED)
    assert result["Strict-Transport-Security"] == 1
    assert result["X-Content-Type-Options"] == 1
    assert result["Content-Security-Policy"] == 0
    assert result["X-Frame-Options"] == 0
    assert result["Referrer-Policy"] == 0


# ---------------------------------------------------------------------------
# Collector behaviour with mocked GET
# ---------------------------------------------------------------------------


def test_collector_reports_present_headers(monkeypatch):
    fake_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }
    monkeypatch.setattr(
        http_headers, "fetch_headers", lambda url, timeout: (fake_headers, 0.123)
    )

    collector = HTTPHeadersCollector(_Cfg([{"url": "https://secure.example.com"}]))
    metrics = _collect_map(collector)

    url = "https://secure.example.com"
    assert metrics[key("argus_endpoint_up", url=url)] == 1.0
    assert metrics[key("argus_endpoint_response_seconds", url=url)] == 0.123
    assert metrics[
        key("argus_security_header_present", url=url, header="Strict-Transport-Security")
    ] == 1.0
    assert metrics[
        key("argus_security_header_present", url=url, header="Content-Security-Policy")
    ] == 0.0


def test_collector_marks_endpoint_down_on_error(monkeypatch):
    def boom(url, timeout):
        raise requests.ConnectionError("name resolution failed")

    monkeypatch.setattr(http_headers, "fetch_headers", boom)

    collector = HTTPHeadersCollector(_Cfg([{"url": "https://dead.example.com"}]))
    metrics = _collect_map(collector)

    url = "https://dead.example.com"
    assert metrics[key("argus_endpoint_up", url=url)] == 0.0
    # Every wanted header should be reported absent so alerts fire.
    for header in WANTED:
        assert metrics[
            key("argus_security_header_present", url=url, header=header)
        ] == 0.0


def test_collector_skips_target_without_url(monkeypatch):
    monkeypatch.setattr(
        http_headers, "fetch_headers", lambda url, timeout: ({}, 0.0)
    )
    collector = HTTPHeadersCollector(_Cfg([{"noturl": "oops"}]))
    metrics = _collect_map(collector)
    # No url -> no endpoint_up series at all.
    assert not any(name == "argus_endpoint_up" for (name, _labels) in metrics)


def test_collector_honours_per_target_header_override(monkeypatch):
    monkeypatch.setattr(
        http_headers,
        "fetch_headers",
        lambda url, timeout: ({"X-Frame-Options": "DENY"}, 0.05),
    )
    collector = HTTPHeadersCollector(
        _Cfg([{"url": "https://x.example.com", "headers": ["X-Frame-Options"]}])
    )
    metrics = _collect_map(collector)
    url = "https://x.example.com"
    # Only the one overridden header should be scored.
    header_series = [
        labels
        for (name, labels) in metrics
        if name == "argus_security_header_present"
    ]
    assert len(header_series) == 1
    assert metrics[
        key("argus_security_header_present", url=url, header="X-Frame-Options")
    ] == 1.0


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
