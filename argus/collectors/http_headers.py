"""HTTP security-headers collector.

For each configured URL Argus issues a GET request and reports:

* ``argus_security_header_present{url,header}`` - ``1`` if the response
  carries the named security header, else ``0``. One series per
  (url, header) pair so you can see exactly which headers are missing
  where.
* ``argus_endpoint_up{url}`` - ``1`` if the GET returned any HTTP response
  (even a 4xx/5xx), ``0`` if the request failed outright (DNS, TLS,
  connection refused, timeout).
* ``argus_endpoint_response_seconds{url}`` - wall-clock time for the GET.

The headers we score default to the five that matter most for a basic
web-security posture (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy) but are fully configurable.
"""

from __future__ import annotations

import time
from typing import Iterator, Mapping

import requests
from prometheus_client.core import GaugeMetricFamily, Metric

from .base import Collector


# ---------------------------------------------------------------------------
# Pure logic (unit tested, no network)
# ---------------------------------------------------------------------------


def evaluate_headers(
    response_headers: Mapping[str, str],
    wanted: list[str],
) -> dict[str, int]:
    """Return a {header_name: 1|0} map of presence for each wanted header.

    Header lookup is case-insensitive: HTTP header names are not
    case-sensitive, and different servers vary the casing. A header counts
    as "present" only if it has a non-empty value.
    """

    # Normalise the response's header names to lowercase for lookup.
    lowered = {k.lower(): (v or "").strip() for k, v in response_headers.items()}
    result: dict[str, int] = {}
    for header in wanted:
        value = lowered.get(header.lower(), "")
        result[header] = 1 if value else 0
    return result


# ---------------------------------------------------------------------------
# I/O (thin, mocked in tests)
# ---------------------------------------------------------------------------


def fetch_headers(url: str, timeout: float) -> tuple[Mapping[str, str], float]:
    """GET ``url`` and return (response headers, elapsed seconds).

    Raises ``requests.RequestException`` on failure. Redirects are followed
    so we score the headers on the page a user actually lands on.
    """

    start = time.monotonic()
    resp = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "argus-security-exporter/0.1"},
    )
    elapsed = time.monotonic() - start
    return resp.headers, elapsed


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class HTTPHeadersCollector(Collector):
    """Collects HTTP security-header presence + endpoint liveness."""

    name = "http_headers"

    def collect(self) -> Iterator[Metric]:
        present = GaugeMetricFamily(
            "argus_security_header_present",
            "1 if the response includes the named security header, else 0.",
            labels=["url", "header"],
        )
        up = GaugeMetricFamily(
            "argus_endpoint_up",
            "1 if the endpoint returned an HTTP response, else 0.",
            labels=["url"],
        )
        latency = GaugeMetricFamily(
            "argus_endpoint_response_seconds",
            "Wall-clock seconds for the GET request.",
            labels=["url"],
        )

        wanted = self.config.security_headers

        for target in self.config.http_targets:
            url = target.get("url") or target.get("target")
            if not url:
                self.log.warning("HTTP target missing url: %r", target)
                continue
            # Allow per-target header overrides.
            headers_for_target = target.get("headers", wanted)

            try:
                resp_headers, elapsed = fetch_headers(url, self.config.timeout)
                up.add_metric([url], 1.0)
                latency.add_metric([url], elapsed)
                scored = evaluate_headers(resp_headers, headers_for_target)
                for header, is_present in scored.items():
                    present.add_metric([url, header], float(is_present))
            except requests.RequestException as exc:
                self.log.warning("HTTP check failed for %s: %s", url, exc)
                up.add_metric([url], 0.0)
                latency.add_metric([url], 0.0)
                # Report every wanted header as absent so the "missing"
                # alert fires instead of the series silently vanishing.
                for header in headers_for_target:
                    present.add_metric([url, header], 0.0)

        yield present
        yield up
        yield latency
