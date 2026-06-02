"""TLS certificate expiry collector.

For each configured ``host:port`` target Argus opens a TLS connection,
reads the certificate the server presents, and reports:

* ``argus_tls_cert_expiry_days{target}`` - whole days until the cert's
  ``notAfter`` date (negative if already expired).
* ``argus_tls_cert_valid{target}`` - ``1`` if the cert is currently within
  its validity window (notBefore <= now <= notAfter), else ``0``.
* ``argus_tls_cert_check_success{target}`` - ``1`` if Argus managed to read
  a certificate at all, ``0`` if the connection/parse failed.

Important design note: this is a *monitoring* tool, so it deliberately
connects with certificate verification **disabled**. We need to read and
report on certs that are expired, self-signed, or hostname-mismatched -
the exact cases an ordinary client would refuse to connect to. Disabling
verification here is correct; we are inspecting the cert, not trusting it.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Iterator

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from prometheus_client.core import GaugeMetricFamily, Metric

from .base import Collector


# ---------------------------------------------------------------------------
# Pure logic (unit tested, no network)
# ---------------------------------------------------------------------------


def days_until_expiry(not_after: datetime, now: datetime | None = None) -> float:
    """Return whole days from ``now`` until ``not_after``.

    Both datetimes are treated as UTC. Naive datetimes are assumed to be
    UTC. The result is negative when the certificate has already expired.
    """

    now = now or datetime.now(timezone.utc)
    not_after = _as_utc(not_after)
    now = _as_utc(now)
    delta = not_after - now
    # Truncate towards negative infinity so "0.9 days left" reports as 0,
    # not 1 - we never want to over-report remaining life.
    return float(delta.days)


def is_currently_valid(
    not_before: datetime,
    not_after: datetime,
    now: datetime | None = None,
) -> bool:
    """Return True if ``now`` falls within [not_before, not_after]."""

    now = _as_utc(now or datetime.now(timezone.utc))
    return _as_utc(not_before) <= now <= _as_utc(not_after)


def _as_utc(dt: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC."""

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def cert_expiry_dates(cert_der: bytes) -> tuple[datetime, datetime]:
    """Parse a DER-encoded certificate and return (not_before, not_after).

    Uses the timezone-aware ``*_utc`` accessors from cryptography so we get
    proper UTC datetimes (the legacy naive accessors are deprecated).
    """

    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return cert.not_valid_before_utc, cert.not_valid_after_utc


# ---------------------------------------------------------------------------
# I/O (thin, mocked in tests)
# ---------------------------------------------------------------------------


def fetch_peer_cert_der(host: str, port: int, timeout: float) -> bytes:
    """Open a TLS connection and return the peer certificate as DER bytes.

    Verification is intentionally disabled (see module docstring). Raises
    on connection failure or TLS errors so the caller can record a failed
    check.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("server presented no certificate")
    return der


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class TLSCertCollector(Collector):
    """Collects TLS certificate expiry / validity for configured targets."""

    name = "tls_cert"

    def collect(self) -> Iterator[Metric]:
        expiry = GaugeMetricFamily(
            "argus_tls_cert_expiry_days",
            "Days until the TLS certificate expires (negative if expired).",
            labels=["target"],
        )
        valid = GaugeMetricFamily(
            "argus_tls_cert_valid",
            "1 if the certificate is within its validity window, else 0.",
            labels=["target"],
        )
        success = GaugeMetricFamily(
            "argus_tls_cert_check_success",
            "1 if Argus successfully read the certificate, else 0.",
            labels=["target"],
        )

        for target in self.config.tls_targets:
            host, port, label = self._parse_target(target)
            if host is None:
                continue
            try:
                der = fetch_peer_cert_der(host, port, self.config.timeout)
                not_before, not_after = cert_expiry_dates(der)
                expiry.add_metric([label], days_until_expiry(not_after))
                valid.add_metric([label], 1.0 if is_currently_valid(not_before, not_after) else 0.0)
                success.add_metric([label], 1.0)
            except Exception as exc:  # noqa: BLE001 - one bad target must not kill the scrape
                self.log.warning("TLS check failed for %s: %s", label, exc)
                # Emit explicit "bad" values so dashboards/alerts can see the
                # failure rather than a silently missing series.
                expiry.add_metric([label], -1.0)
                valid.add_metric([label], 0.0)
                success.add_metric([label], 0.0)

        yield expiry
        yield valid
        yield success

    def _parse_target(self, target: dict) -> tuple[str | None, int, str]:
        """Extract (host, port, label) from a target entry.

        A target may be ``{"target": "example.com:443"}`` or
        ``{"host": "example.com", "port": 443}``. Defaults to port 443.
        """

        raw = target.get("target") or target.get("host") or ""
        port = int(target.get("port", 0))
        host = raw

        if ":" in raw and "host" not in target:
            host, _, port_str = raw.rpartition(":")
            try:
                port = int(port_str)
            except ValueError:
                self.log.warning("Bad port in TLS target %r, skipping", raw)
                return None, 0, raw

        if not host:
            self.log.warning("TLS target missing host: %r", target)
            return None, 0, str(target)
        if not port:
            port = 443

        label = f"{host}:{port}"
        return host, port, label
