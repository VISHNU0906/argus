"""Argus exporter - the Prometheus HTTP server and collector registry.

Run it directly::

    python -m argus.exporter --config config.yaml

This starts an HTTP server (default :9882) that serves ``/metrics``. On
each scrape every enabled collector runs its checks and yields fresh
metrics. Each collector is wrapped defensively so that one failing
collector can never take down the whole scrape - a broken target produces
a logged warning and a ``argus_collector_up{collector="..."} 0`` series,
not an empty page.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from typing import Iterator

from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily, Metric

from . import __version__
from .config import Config, ConfigError, load_config
from .collectors.dependencies import DependenciesCollector
from .collectors.http_headers import HTTPHeadersCollector
from .collectors.ports import PortsCollector
from .collectors.tls_cert import TLSCertCollector

log = logging.getLogger("argus.exporter")


# Maps config toggle attribute -> collector class.
COLLECTOR_CLASSES = {
    "tls_cert": TLSCertCollector,
    "http_headers": HTTPHeadersCollector,
    "ports": PortsCollector,
    "dependencies": DependenciesCollector,
}


def build_collectors(config: Config) -> list:
    """Instantiate the collectors enabled in the config."""

    collectors = []
    for attr, cls in COLLECTOR_CLASSES.items():
        if getattr(config.enabled, attr):
            collectors.append(cls(config))
            log.info("Enabled collector: %s", attr)
        else:
            log.info("Collector disabled in config: %s", attr)
    return collectors


class ArgusRegistry:
    """A prometheus_client custom collector that fans out to sub-collectors.

    Registering a single object (rather than each collector) lets us add
    per-collector timing and an ``argus_collector_up`` meta-metric, and
    guarantees that an exception in one collector never aborts the scrape.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.collectors = build_collectors(config)

    # prometheus_client calls this on every scrape.
    def collect(self) -> Iterator[Metric]:
        up = GaugeMetricFamily(
            "argus_collector_up",
            "1 if the collector ran without raising during this scrape, else 0.",
            labels=["collector"],
        )
        duration = GaugeMetricFamily(
            "argus_collector_duration_seconds",
            "How long the collector took to run during this scrape.",
            labels=["collector"],
        )

        for collector in self.collectors:
            start = time.monotonic()
            try:
                # Materialise here so any exception is caught inside the
                # try/except rather than later, during HTTP serialization.
                metrics = list(collector.collect())
                for metric in metrics:
                    yield metric
                up.add_metric([collector.name], 1.0)
            except Exception:  # noqa: BLE001 - defensive: never kill the scrape
                log.exception("Collector %s raised; reporting collector_up=0", collector.name)
                up.add_metric([collector.name], 0.0)
            finally:
                duration.add_metric([collector.name], time.monotonic() - start)

        # Build/version info as a constant gauge.
        info = GaugeMetricFamily(
            "argus_build_info",
            "Argus build information (value is always 1).",
            labels=["version"],
        )
        info.add_metric([__version__], 1.0)

        yield up
        yield duration
        yield info

    def describe(self):
        """Return nothing so prometheus_client does not call collect() at
        registration time (which would trigger real network I/O)."""
        return []


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Prometheus exporter for security-posture metrics.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to the Argus config file (default: config.yaml).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"argus {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 2

    registry = ArgusRegistry(config)
    REGISTRY.register(registry)

    log.info(
        "Argus %s starting; serving /metrics on http://%s:%d/metrics",
        __version__,
        config.listen_host,
        config.listen_port,
    )
    start_http_server(config.listen_port, addr=config.listen_host)

    # Block forever, exiting cleanly on SIGINT/SIGTERM.
    stop = {"flag": False}

    def _handle(signum, _frame):  # noqa: ANN001
        log.info("Received signal %s, shutting down.", signum)
        stop["flag"] = True

    signal.signal(signal.SIGINT, _handle)
    try:
        signal.signal(signal.SIGTERM, _handle)
    except (ValueError, AttributeError):  # SIGTERM not available everywhere
        pass

    while not stop["flag"]:
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
