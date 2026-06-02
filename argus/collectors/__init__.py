"""Argus collectors.

Each collector knows how to gather one family of security signals and
yield Prometheus metric families. Collectors follow the
``prometheus_client`` custom-collector pattern: they expose a ``collect()``
method that runs the checks *on scrape* and yields metric families.

The design goal for every collector is a clean split between:

* **pure logic** (e.g. "given this cert, how many days until it expires?")
  which is unit-tested without any network, and
* **I/O** (open a socket, send a GET) which is thin and mocked in tests.
"""

from .base import Collector

__all__ = ["Collector"]
