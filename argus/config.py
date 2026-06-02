"""Configuration loading and validation for Argus.

Argus is driven entirely by a single ``config.yaml`` file. This module
loads that file, fills in sensible defaults, and exposes typed helpers so
the rest of the codebase never has to reach into raw dictionaries.

The shape of the config is intentionally flat and obvious - see
``config.example.yaml`` for a fully worked example.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_PORT = 9882  # /metrics listens here
DEFAULT_HOST = "0.0.0.0"
DEFAULT_TIMEOUT = 5.0  # seconds, per network operation

# Which security headers we score by default. Order is preserved so the
# Grafana "coverage" view is stable.
DEFAULT_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


@dataclass
class CollectorToggle:
    """Whether a single collector is enabled."""

    tls_cert: bool = True
    http_headers: bool = True
    ports: bool = True
    dependencies: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "CollectorToggle":
        data = data or {}
        return cls(
            tls_cert=bool(data.get("tls_cert", True)),
            http_headers=bool(data.get("http_headers", True)),
            ports=bool(data.get("ports", True)),
            dependencies=bool(data.get("dependencies", True)),
        )


@dataclass
class Config:
    """Top-level Argus configuration."""

    # Exporter HTTP server
    listen_host: str = DEFAULT_HOST
    listen_port: int = DEFAULT_PORT
    timeout: float = DEFAULT_TIMEOUT

    # Which collectors run on each scrape
    enabled: CollectorToggle = field(default_factory=CollectorToggle)

    # Collector targets / settings
    tls_targets: list[dict[str, Any]] = field(default_factory=list)
    http_targets: list[dict[str, Any]] = field(default_factory=list)
    port_targets: list[dict[str, Any]] = field(default_factory=list)
    security_headers: list[str] = field(default_factory=lambda: list(DEFAULT_SECURITY_HEADERS))

    # Dependency scanning
    dependency_files: list[str] = field(default_factory=list)
    # Cap how many unique vuln IDs we look up for severity per scrape. The
    # OSV querybatch endpoint only returns vuln IDs, so each one needs a
    # follow-up request - we bound that work to keep scrapes fast.
    dependency_max_lookups: int = 100

    # Raw config retained for debugging / forward-compat fields
    raw: dict[str, Any] = field(default_factory=dict)


def _coerce_targets(value: Any, key_name: str) -> list[dict[str, Any]]:
    """Normalise a targets list.

    Accepts either a list of plain strings (shorthand) or a list of dicts.
    Strings are wrapped into ``{key_name: <string>}`` dicts so collectors
    only ever deal with one shape.
    """

    if not value:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"'{key_name}' targets must be a list, got {type(value).__name__}")

    out: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, str):
            out.append({key_name: item})
        elif isinstance(item, dict):
            out.append(item)
        else:
            raise ConfigError(
                f"Each entry under a targets list must be a string or mapping, "
                f"got {type(item).__name__}"
            )
    return out


class ConfigError(Exception):
    """Raised when the config file is missing or malformed."""


def load_config(path: str) -> Config:
    """Load and validate an Argus config file.

    Parameters
    ----------
    path:
        Filesystem path to a YAML config file.

    Raises
    ------
    ConfigError
        If the file is missing, is not valid YAML, or is not a mapping.
    """

    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:  # pragma: no cover - thin wrapper
        raise ConfigError(f"Could not parse YAML in {path}: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"Top level of {path} must be a mapping, got {type(data).__name__}")

    return parse_config(data)


def parse_config(data: dict[str, Any]) -> Config:
    """Build a ``Config`` from an already-parsed dict.

    Split out from :func:`load_config` so tests can exercise validation
    without touching the filesystem.
    """

    server = data.get("server", {}) or {}
    collectors = data.get("collectors", {}) or {}

    tls_cfg = collectors.get("tls_cert", {}) or {}
    http_cfg = collectors.get("http_headers", {}) or {}
    ports_cfg = collectors.get("ports", {}) or {}
    deps_cfg = collectors.get("dependencies", {}) or {}

    cfg = Config(
        listen_host=str(server.get("host", DEFAULT_HOST)),
        listen_port=int(server.get("port", DEFAULT_PORT)),
        timeout=float(server.get("timeout", DEFAULT_TIMEOUT)),
        enabled=CollectorToggle.from_dict(data.get("enabled")),
        tls_targets=_coerce_targets(tls_cfg.get("targets"), "target"),
        http_targets=_coerce_targets(http_cfg.get("targets"), "url"),
        port_targets=_coerce_targets(ports_cfg.get("targets"), "host"),
        security_headers=list(http_cfg.get("headers", DEFAULT_SECURITY_HEADERS)),
        dependency_files=list(deps_cfg.get("files", [])),
        dependency_max_lookups=int(deps_cfg.get("max_lookups", 100)),
        raw=data,
    )

    if cfg.listen_port < 1 or cfg.listen_port > 65535:
        raise ConfigError(f"server.port out of range: {cfg.listen_port}")
    if cfg.timeout <= 0:
        raise ConfigError(f"server.timeout must be positive: {cfg.timeout}")

    return cfg
