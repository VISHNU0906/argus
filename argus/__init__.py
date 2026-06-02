"""Argus - a Prometheus exporter for security-posture metrics.

Argus scrapes security signals (TLS certificate expiry, HTTP security
headers, unexpected open ports, dependency vulnerabilities) from a
configurable list of targets and exposes them as Prometheus metrics.

It answers "is my security infrastructure healthy?" the way node_exporter
answers "is my host healthy?".
"""

__version__ = "0.1.0"
__author__ = "Vishnu Kosuri"
