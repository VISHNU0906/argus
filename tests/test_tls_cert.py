"""Unit tests for the TLS certificate collector.

These tests exercise the *pure logic* (expiry maths, validity windows, cert
parsing) and the collector's behaviour, with all network I/O mocked. No
sockets are opened.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from argus.collectors import tls_cert
from argus.collectors.tls_cert import (
    TLSCertCollector,
    cert_expiry_dates,
    days_until_expiry,
    is_currently_valid,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_self_signed_cert(not_before: datetime, not_after: datetime) -> bytes:
    """Build a real (self-signed) DER cert with the given validity window.

    Lets us test cert parsing against genuine cryptography output instead of
    a mock, without any network.
    """

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "argus-test.local")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.DER)


class _Cfg:
    """Minimal stand-in for argus.config.Config."""

    def __init__(self, tls_targets):
        self.tls_targets = tls_targets
        self.timeout = 5.0


def _collect_map(collector):
    """Run collect() and return {(metric_name, frozenset(labels)): value}."""

    out = {}
    for metric in collector.collect():
        for sample in metric.samples:
            key = (sample.name, frozenset(sample.labels.items()))
            out[key] = sample.value
    return out


def key(name, **labels):
    """Build a lookup key matching _collect_map's (name, frozenset) shape."""

    return (name, frozenset(labels.items()))


# ---------------------------------------------------------------------------
# Pure logic: days_until_expiry
# ---------------------------------------------------------------------------


def test_days_until_expiry_future():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now + timedelta(days=30)
    assert days_until_expiry(not_after, now) == 30


def test_days_until_expiry_already_expired_is_negative():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    not_after = now - timedelta(days=5)
    assert days_until_expiry(not_after, now) == -5


def test_days_until_expiry_truncates_partial_day():
    # 1 day and 23 hours of life left should report 1, never 2.
    now = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    not_after = now + timedelta(days=1, hours=23)
    assert days_until_expiry(not_after, now) == 1


def test_days_until_expiry_assumes_utc_for_naive():
    now = datetime(2026, 1, 1)  # naive -> treated as UTC
    not_after = datetime(2026, 1, 11)  # naive -> UTC
    assert days_until_expiry(not_after, now) == 10


# ---------------------------------------------------------------------------
# Pure logic: is_currently_valid
# ---------------------------------------------------------------------------


def test_is_currently_valid_inside_window():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    nb = now - timedelta(days=10)
    na = now + timedelta(days=10)
    assert is_currently_valid(nb, na, now) is True


def test_is_currently_valid_expired():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    nb = now - timedelta(days=20)
    na = now - timedelta(days=1)
    assert is_currently_valid(nb, na, now) is False


def test_is_currently_valid_not_yet_active():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    nb = now + timedelta(days=1)
    na = now + timedelta(days=30)
    assert is_currently_valid(nb, na, now) is False


# ---------------------------------------------------------------------------
# Cert parsing against a real (self-signed) cert - no network
# ---------------------------------------------------------------------------


def test_cert_expiry_dates_roundtrip():
    nb = datetime(2026, 1, 1, tzinfo=timezone.utc)
    na = datetime(2027, 1, 1, tzinfo=timezone.utc)
    der = _make_self_signed_cert(nb, na)
    parsed_nb, parsed_na = cert_expiry_dates(der)
    # cryptography returns tz-aware UTC datetimes.
    assert parsed_nb.replace(tzinfo=timezone.utc).date() == nb.date()
    assert parsed_na.replace(tzinfo=timezone.utc).date() == na.date()


# ---------------------------------------------------------------------------
# Collector behaviour with mocked network
# ---------------------------------------------------------------------------


def test_collector_reports_valid_cert(monkeypatch):
    now = datetime.now(timezone.utc)
    der = _make_self_signed_cert(now - timedelta(days=1), now + timedelta(days=40))
    monkeypatch.setattr(tls_cert, "fetch_peer_cert_der", lambda h, p, t: der)

    collector = TLSCertCollector(_Cfg([{"target": "good.example.com:443"}]))
    metrics = _collect_map(collector)

    t = "good.example.com:443"
    assert metrics[key("argus_tls_cert_check_success", target=t)] == 1.0
    assert metrics[key("argus_tls_cert_valid", target=t)] == 1.0
    assert metrics[key("argus_tls_cert_expiry_days", target=t)] >= 39  # ~40 days


def test_collector_reports_expired_cert(monkeypatch):
    now = datetime.now(timezone.utc)
    der = _make_self_signed_cert(now - timedelta(days=400), now - timedelta(days=5))
    monkeypatch.setattr(tls_cert, "fetch_peer_cert_der", lambda h, p, t: der)

    collector = TLSCertCollector(_Cfg([{"target": "expired.example.com:443"}]))
    metrics = _collect_map(collector)

    t = "expired.example.com:443"
    assert metrics[key("argus_tls_cert_check_success", target=t)] == 1.0
    assert metrics[key("argus_tls_cert_valid", target=t)] == 0.0
    assert metrics[key("argus_tls_cert_expiry_days", target=t)] < 0


def test_collector_handles_connection_failure(monkeypatch):
    def boom(host, port, timeout):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(tls_cert, "fetch_peer_cert_der", boom)

    collector = TLSCertCollector(_Cfg([{"target": "down.example.com:443"}]))
    metrics = _collect_map(collector)

    t = "down.example.com:443"
    # A failed check must produce explicit "bad" series, not vanish.
    assert metrics[key("argus_tls_cert_check_success", target=t)] == 0.0
    assert metrics[key("argus_tls_cert_valid", target=t)] == 0.0
    assert metrics[key("argus_tls_cert_expiry_days", target=t)] == -1.0


def test_collector_parses_hostport_shorthand(monkeypatch):
    captured = {}

    def fake(host, port, timeout):
        captured["host"] = host
        captured["port"] = port
        raise TimeoutError("ignore - we only care about parsing")

    monkeypatch.setattr(tls_cert, "fetch_peer_cert_der", fake)
    collector = TLSCertCollector(_Cfg([{"target": "example.org:8443"}]))
    _collect_map(collector)
    assert captured == {"host": "example.org", "port": 8443}


def test_collector_defaults_port_443(monkeypatch):
    captured = {}

    def fake(host, port, timeout):
        captured["port"] = port
        raise TimeoutError()

    monkeypatch.setattr(tls_cert, "fetch_peer_cert_der", fake)
    collector = TLSCertCollector(_Cfg([{"host": "example.org"}]))
    _collect_map(collector)
    assert captured["port"] == 443


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
