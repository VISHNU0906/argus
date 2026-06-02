"""Open-port drift collector.

For each configured host Argus is given an *allowlist* of ports that are
expected to be open. It then TCP-connects to a configurable range of ports
and reports any port that is open but **not** on the allowlist - i.e. port
drift, the classic "someone left a debug service exposed" failure.

Metrics:

* ``argus_unexpected_open_port{host,port}`` - ``1`` for every open port
  that is not in the host's allowlist.
* ``argus_open_ports_total{host}`` - total number of open ports found in
  the scanned range.
* ``argus_unexpected_open_ports_total{host}`` - count of open ports that
  are not on the allowlist (handy for a single alert threshold).

Documented limitation
----------------------
This is a deliberately small, polite TCP-connect scan, not nmap. It only
scans the explicit ``scan_ports`` list (or a small default range) so a
scrape stays fast and we never hammer a host. It does not do UDP, service
fingerprinting, or full 1-65535 sweeps - use a dedicated scanner for that.
The point here is *drift detection against a known-good allowlist*, run
continuously and alertable, not exhaustive discovery.
"""

from __future__ import annotations

import socket
from typing import Iterable, Iterator

from prometheus_client.core import GaugeMetricFamily, Metric

from .base import Collector


# A small, sensible default set of ports to probe when a target does not
# specify its own scan list. These are the ports most likely to be
# accidentally exposed.
DEFAULT_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3000, 3306, 3389,
    5000, 5432, 5601, 5900, 6379, 8000, 8008, 8080,
    8443, 8888, 9000, 9090, 9200, 11211, 27017,
]


# ---------------------------------------------------------------------------
# Pure logic (unit tested, no network)
# ---------------------------------------------------------------------------


def unexpected_ports(open_ports: Iterable[int], allowed: Iterable[int]) -> list[int]:
    """Return the sorted list of open ports that are not in the allowlist."""

    allowed_set = set(allowed)
    return sorted(p for p in set(open_ports) if p not in allowed_set)


def expand_scan_ports(spec: object) -> list[int]:
    """Normalise a scan-ports spec into a concrete, de-duplicated list.

    Accepts:
      * a list of ints (``[22, 80, 443]``)
      * a list that may contain ``"start-end"`` range strings
        (``[22, "8000-8010"]``)
      * ``None`` -> the default scan set
    """

    if spec is None:
        return list(DEFAULT_SCAN_PORTS)
    if not isinstance(spec, (list, tuple)):
        raise ValueError(f"scan_ports must be a list, got {type(spec).__name__}")

    ports: set[int] = set()
    for item in spec:
        if isinstance(item, int):
            ports.add(item)
        elif isinstance(item, str) and "-" in item:
            start_s, _, end_s = item.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    return sorted(p for p in ports if 1 <= p <= 65535)


# ---------------------------------------------------------------------------
# I/O (thin, mocked in tests)
# ---------------------------------------------------------------------------


def is_port_open(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class PortsCollector(Collector):
    """Detects open ports that drift from a per-host allowlist."""

    name = "ports"

    def collect(self) -> Iterator[Metric]:
        unexpected = GaugeMetricFamily(
            "argus_unexpected_open_port",
            "1 for each open port that is not on the host's allowlist.",
            labels=["host", "port"],
        )
        total = GaugeMetricFamily(
            "argus_open_ports_total",
            "Total number of open ports found in the scanned range.",
            labels=["host"],
        )
        unexpected_total = GaugeMetricFamily(
            "argus_unexpected_open_ports_total",
            "Number of open ports not present on the host's allowlist.",
            labels=["host"],
        )

        # Per-port connect timeout: keep this short so a host with many
        # filtered ports does not blow out scrape latency.
        connect_timeout = min(self.config.timeout, 1.0)

        for target in self.config.port_targets:
            host = target.get("host") or target.get("target")
            if not host:
                self.log.warning("Port target missing host: %r", target)
                continue
            try:
                allowed = [int(p) for p in target.get("allowed_ports", [])]
                scan_ports = expand_scan_ports(target.get("scan_ports"))
            except (ValueError, TypeError) as exc:
                self.log.warning("Bad port config for %s: %s", host, exc)
                continue

            open_found: list[int] = []
            for port in scan_ports:
                if is_port_open(host, port, connect_timeout):
                    open_found.append(port)

            drift = unexpected_ports(open_found, allowed)
            total.add_metric([host], float(len(open_found)))
            unexpected_total.add_metric([host], float(len(drift)))
            for port in drift:
                unexpected.add_metric([host, str(port)], 1.0)

        yield unexpected
        yield total
        yield unexpected_total
