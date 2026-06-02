"""Dependency-vulnerability collector (OSV.dev).

Given one or more ``requirements.txt`` files, Argus parses the pinned
packages and asks the OSV.dev batch API which of them have known
vulnerabilities. It then reports the number of vulnerable findings bucketed
by severity:

* ``argus_dependency_vulnerabilities{file,severity}`` - count of vulnerable
  (package, vuln) findings, bucketed into CRITICAL / HIGH / MODERATE / LOW /
  UNKNOWN.
* ``argus_dependency_scan_success{file}`` - ``1`` if the scan completed,
  ``0`` if OSV could not be reached (e.g. no network).
* ``argus_dependencies_total{file}`` - number of pinned packages parsed.

How severity is derived
-----------------------
The OSV ``querybatch`` endpoint only returns vulnerability *IDs* per
package - it does not include severity. For severity we make a follow-up
``GET /v1/vulns/{id}`` call per unique vuln ID and read
``database_specific.severity`` (e.g. "MODERATE"), falling back to a CVSS
base-score bucket parsed from the ``severity`` field, and finally
"UNKNOWN". To keep scrapes bounded we cap the number of follow-up lookups
per scrape (``dependencies.max_lookups`` in config).

Documented limitation
----------------------
Only pinned requirements (``pkg==1.2.3``) are scanned - unpinned or
range-pinned lines are skipped because OSV needs an exact version to answer
accurately. Severity follow-up lookups are capped, so a file with a huge
number of distinct vulns may report some findings as UNKNOWN once the cap
is hit. The collector handles "no network" gracefully: it logs a warning,
sets ``scan_success`` to 0, and reports zero vulnerabilities rather than
crashing the scrape.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from typing import Iterator

import requests
from prometheus_client.core import GaugeMetricFamily, Metric

from .base import Collector

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

SEVERITY_BUCKETS = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]

# Matches a pinned requirement line like "requests==2.4.1" capturing
# name + version. Tolerates extras ("requests[security]==2.4.1") and
# trailing environment markers / comments.
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._\-+!]+)"
)


# ---------------------------------------------------------------------------
# Pure logic (unit tested, no network)
# ---------------------------------------------------------------------------


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Parse requirements.txt text into a list of (name, version) tuples.

    Only exact (``==``) pins are returned. Comments, blank lines, ``-r``
    includes, options, and non-pinned lines are skipped.
    """

    packages: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _REQ_RE.match(line)
        if match:
            name, version = match.group(1), match.group(2)
            packages.append((name.lower(), version))
    return packages


def cvss_vector_to_bucket(vector: str) -> str:
    """Map a CVSS v3 vector string to a severity bucket via base score.

    We do a lightweight base-score estimate from the vector's metrics. This
    is intentionally approximate - it is only a fallback when OSV does not
    give us a named severity. Returns one of the SEVERITY_BUCKETS.
    """

    # Pull out the metric=value pairs.
    metrics = dict(
        part.split(":", 1)
        for part in vector.split("/")
        if ":" in part and not part.startswith("CVSS")
    )
    score = _cvss_base_score(metrics)
    return score_to_bucket(score)


def score_to_bucket(score: float) -> str:
    """Map a CVSS base score (0.0-10.0) to a severity bucket label."""

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def normalize_severity_label(label: str) -> str:
    """Normalise an OSV database_specific.severity string to a bucket.

    OSV uses labels like LOW / MODERATE / HIGH / CRITICAL (GitHub style).
    Anything unrecognised falls back to UNKNOWN.
    """

    if not label:
        return "UNKNOWN"
    upper = label.strip().upper()
    aliases = {"MEDIUM": "MODERATE"}
    upper = aliases.get(upper, upper)
    return upper if upper in SEVERITY_BUCKETS else "UNKNOWN"


def _cvss_base_score(metrics: dict[str, str]) -> float:
    """A compact CVSS v3.1 base-score approximation.

    Implements the standard CVSS v3.1 base formula. Good enough to bucket a
    finding when OSV gives us a vector but no named severity.
    """

    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    try:
        av = weights["AV"][metrics["AV"]]
        ac = weights["AC"][metrics["AC"]]
        ui = weights["UI"][metrics["UI"]]
        scope = metrics.get("S", "U")
        # Privileges Required weight changes when scope is Changed.
        pr_raw = metrics["PR"]
        pr = weights["PR"][pr_raw]
        if scope == "C" and pr_raw in ("L", "H"):
            pr = {"L": 0.68, "H": 0.50}[pr_raw]
        conf = weights["C"][metrics["C"]]
        integ = weights["I"][metrics["I"]]
        avail = weights["A"][metrics["A"]]
    except KeyError:
        return 0.0

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    # Round up to one decimal, per spec.
    import math

    return math.ceil(base * 10) / 10.0


# ---------------------------------------------------------------------------
# I/O (thin, mocked in tests)
# ---------------------------------------------------------------------------


def query_osv_batch(packages: list[tuple[str, str]], timeout: float) -> list[list[str]]:
    """Query OSV querybatch; return a per-package list of vuln IDs.

    The result aligns positionally with ``packages``. Raises
    ``requests.RequestException`` on network failure.
    """

    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]
    resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
    resp.raise_for_status()
    results = resp.json().get("results", [])

    out: list[list[str]] = []
    for entry in results:
        vulns = entry.get("vulns") or []
        out.append([v["id"] for v in vulns if "id" in v])
    return out


def fetch_vuln_severity(vuln_id: str, timeout: float) -> str:
    """Fetch a single vuln and return its severity bucket.

    Prefers ``database_specific.severity``; falls back to a CVSS-vector
    bucket; finally UNKNOWN. Raises ``requests.RequestException`` on
    network failure.
    """

    resp = requests.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    db_specific = (data.get("database_specific") or {}).get("severity")
    if db_specific:
        bucket = normalize_severity_label(db_specific)
        if bucket != "UNKNOWN":
            return bucket

    for sev in data.get("severity") or []:
        if sev.get("type", "").startswith("CVSS") and sev.get("score"):
            bucket = cvss_vector_to_bucket(sev["score"])
            if bucket != "UNKNOWN":
                return bucket

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class DependenciesCollector(Collector):
    """Scans requirements files against OSV.dev for known vulnerabilities."""

    name = "dependencies"

    def collect(self) -> Iterator[Metric]:
        vulns = GaugeMetricFamily(
            "argus_dependency_vulnerabilities",
            "Count of vulnerable dependency findings, bucketed by severity.",
            labels=["file", "severity"],
        )
        scan_ok = GaugeMetricFamily(
            "argus_dependency_scan_success",
            "1 if the OSV scan completed for this file, else 0.",
            labels=["file"],
        )
        deps_total = GaugeMetricFamily(
            "argus_dependencies_total",
            "Number of pinned packages parsed from the requirements file.",
            labels=["file"],
        )

        for path in self.config.dependency_files:
            label = os.path.basename(path)
            counts, parsed_count, ok = self._scan_file(path)
            deps_total.add_metric([label], float(parsed_count))
            scan_ok.add_metric([label], 1.0 if ok else 0.0)
            # Always emit every bucket (even zeros) so series are stable and
            # alert rules have something to evaluate.
            for severity in SEVERITY_BUCKETS:
                vulns.add_metric([label, severity], float(counts.get(severity, 0)))

        yield vulns
        yield scan_ok
        yield deps_total

    def _scan_file(self, path: str) -> tuple[Counter, int, bool]:
        """Scan one requirements file. Returns (severity_counts, n_pkgs, ok)."""

        counts: Counter = Counter()
        if not os.path.exists(path):
            self.log.warning("Dependency file not found: %s", path)
            return counts, 0, False

        try:
            with open(path, "r", encoding="utf-8") as fh:
                packages = parse_requirements(fh.read())
        except OSError as exc:
            self.log.warning("Could not read %s: %s", path, exc)
            return counts, 0, False

        if not packages:
            self.log.info("No pinned packages found in %s", path)
            return counts, 0, True

        timeout = self.config.timeout
        try:
            per_pkg_vuln_ids = query_osv_batch(packages, timeout)
        except requests.RequestException as exc:
            # No network / OSV down: degrade gracefully per the spec.
            self.log.warning("OSV query failed for %s (continuing with 0 vulns): %s", path, exc)
            return counts, len(packages), False

        # Resolve severity for each finding, with a cap on follow-up lookups
        # and a per-id cache so repeated vulns are only fetched once.
        severity_cache: dict[str, str] = {}
        lookups_left = self.config.dependency_max_lookups

        for vuln_ids in per_pkg_vuln_ids:
            for vuln_id in vuln_ids:
                if vuln_id in severity_cache:
                    bucket = severity_cache[vuln_id]
                elif lookups_left > 0:
                    try:
                        bucket = fetch_vuln_severity(vuln_id, timeout)
                    except requests.RequestException as exc:
                        self.log.warning("Severity lookup failed for %s: %s", vuln_id, exc)
                        bucket = "UNKNOWN"
                    severity_cache[vuln_id] = bucket
                    lookups_left -= 1
                else:
                    # Cap hit: count it but as UNKNOWN.
                    bucket = "UNKNOWN"
                counts[bucket] += 1

        return counts, len(packages), True
