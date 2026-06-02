"""Base class shared by all Argus collectors."""

from __future__ import annotations

import logging
from typing import Iterable, Iterator

from prometheus_client.core import Metric


class Collector:
    """Base class for a security-signal collector.

    Subclasses implement :meth:`collect`, which runs the checks and yields
    Prometheus metric families. Subclasses should keep network calls thin
    and behind their own try/except so a single bad target never aborts a
    whole scrape - but the exporter also wraps each collector defensively
    (see :class:`argus.exporter.ArgusRegistry`).
    """

    #: Human-readable name used in logs and the meta "up" metric.
    name: str = "base"

    def __init__(self, config) -> None:  # noqa: ANN001 - config is argus.config.Config
        self.config = config
        self.log = logging.getLogger(f"argus.collectors.{self.name}")

    def collect(self) -> Iterator[Metric]:  # pragma: no cover - abstract
        """Yield Prometheus metric families. Must be overridden."""
        raise NotImplementedError
        yield  # pragma: no cover - makes the type a generator

    # Convenience used by the exporter when introspecting collectors.
    def describe(self) -> Iterable[Metric]:
        """Return an empty iterable so prometheus_client does not call
        :meth:`collect` at registration time (which would do real I/O)."""
        return []
