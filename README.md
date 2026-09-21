# Argus

**Argus is a Prometheus exporter that tells you whether your security infrastructure is healthy** :  the same way `node_exporter` tells you whether a server is healthy.

You give it a list of things to watch (HTTPS endpoints, hosts, a `requirements.txt` file). On every scrape it checks them and turns the results into Prometheus metrics: certificates about to expire, missing security headers, endpoints that went dark, ports that shouldn't be open, and dependencies with known vulnerabilities. It ships with Grafana dashboards and Alertmanager rules so you can *see* your posture and get paged when it slips.

It is named after Argus Panoptes, the hundred-eyed giant of Greek myth who never closed all his eyes at once.

---

## Run it in 3 commands

```bash
cp config.example.yaml config.yaml          # 1. create your config (edit targets later)
docker compose -f deploy/docker-compose.yml up   # 2. bring up the whole stack
open http://localhost:3000                   # 3. log into Grafana (admin / admin)
```

That starts four containers, wired together:

| Service | URL | What it's for |
|---|---|---|
| **Grafana** | http://localhost:3000 | Dashboards (login `admin` / `admin`) |
| **Prometheus** | http://localhost:9090 | Stores metrics, evaluates alert rules |
| **Alertmanager** | http://localhost:9093 | Routes firing alerts (Slack/webhook) |
| **Argus exporter** | http://localhost:9882/metrics | Raw metrics, if you want to see them |

The Prometheus datasource and the "Argus - Security Posture" dashboard are auto-provisioned, so Grafana works the moment it boots.

### Just want the exporter, no stack?

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
python -m argus.exporter --config config.yaml
curl http://localhost:9882/metrics
```

---

## What each check means

Argus runs four **collectors**. Each one is independent :  if one fails, the others still produce metrics, and you get an `argus_collector_up{collector="..."} 0` series telling you which one broke.

### 1. TLS certificate expiry (`tls_cert`)
Opens a TLS connection to each `host:port`, reads the certificate the server presents, and reports how many days until it expires. Certificate **verification is intentionally disabled** here :  Argus needs to inspect certs that are expired, self-signed, or hostname-mismatched, which is exactly the set a normal client refuses to talk to. We're inspecting the cert, not trusting it.

### 2. HTTP security headers (`http_headers`)
Does a GET to each URL and checks whether five important security headers are present: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy. Also records whether the endpoint responded at all and how long it took.

### 3. Unexpected open ports (`ports`)
For each host you give it an **allowlist** of ports you expect to be open. Argus probes a (small, configurable) set of ports and flags anything that's open but *not* on the list :  classic config drift, like a debug service left exposed. This is drift detection, not a full nmap sweep (see [Limitations](#limitations)).

### 4. Dependency vulnerabilities (`dependencies`)
Reads a `requirements.txt`, parses the pinned packages, and asks the public [OSV.dev](https://osv.dev) database which ones have known vulnerabilities. Counts are bucketed by severity (CRITICAL / HIGH / MODERATE / LOW / UNKNOWN). If there's no network, it logs a warning, reports zero, and sets `argus_dependency_scan_success` to 0 instead of crashing.

---

## Architecture

```
                         scrape every 2m
   ┌──────────────┐  GET /metrics   ┌──────────────┐  evaluates   ┌───────────────┐
   │  Prometheus  │ ───────────────▶│    Argus     │              │  alerts.yml   │
   │              │                 │   exporter   │              │ (alert rules) │
   │  (TSDB +     │◀─── metrics ────│  :9882       │              └───────┬───────┘
   │  rule eval)  │                 └──────┬───────┘                      │ fires
   └──────┬───────┘                        │ on each scrape runs:         ▼
          │ datasource                     │                      ┌───────────────┐
          ▼                                ├─ tls_cert  ──▶ TLS sockets
   ┌──────────────┐                        ├─ http_headers ▶ HTTP GETs   │ Alertmanager │
   │   Grafana    │                        ├─ ports ───────▶ TCP connects │   :9093      │
   │   :3000      │                        └─ dependencies ▶ OSV.dev API  └──────┬───────┘
   │ (dashboards) │                                                              │
   └──────────────┘                                            Slack / webhook ◀─┘
```

The exporter itself is a plain `prometheus_client` custom collector. Each collector is split into **pure logic** (testable, e.g. "given this cert, how many days left?") and **thin I/O** (open a socket, send a GET), which is why the core collectors have real unit tests with no network.

---

## Metrics reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `argus_tls_cert_expiry_days` | gauge | `target` | Days until the cert expires (negative if expired). |
| `argus_tls_cert_valid` | gauge | `target` | 1 if the cert is within its validity window, else 0. |
| `argus_tls_cert_check_success` | gauge | `target` | 1 if Argus could read the cert at all, else 0. |
| `argus_security_header_present` | gauge | `url`, `header` | 1 if the response set that security header, else 0. |
| `argus_endpoint_up` | gauge | `url` | 1 if the endpoint returned any HTTP response, else 0. |
| `argus_endpoint_response_seconds` | gauge | `url` | Wall-clock time for the GET. |
| `argus_unexpected_open_port` | gauge | `host`, `port` | 1 for each open port not on the host's allowlist. |
| `argus_open_ports_total` | gauge | `host` | Number of open ports found in the scanned range. |
| `argus_unexpected_open_ports_total` | gauge | `host` | Count of open ports not on the allowlist. |
| `argus_dependency_vulnerabilities` | gauge | `file`, `severity` | Known-vuln findings, bucketed by severity. |
| `argus_dependency_scan_success` | gauge | `file` | 1 if the OSV scan completed, else 0. |
| `argus_dependencies_total` | gauge | `file` | Pinned packages parsed from the file. |
| `argus_collector_up` | gauge | `collector` | 1 if that collector ran without raising this scrape. |
| `argus_collector_duration_seconds` | gauge | `collector` | How long that collector took this scrape. |
| `argus_build_info` | gauge | `version` | Always 1; carries the Argus version as a label. |

---

## Alert rules

Shipped in [`deploy/alerts.yml`](deploy/alerts.yml). Each alert has a `summary`, a `description`, and a `runbook` annotation with concrete next steps.

| Alert | Fires when | For | Severity |
|---|---|---|---|
| `ArgusCertExpiringSoon` | Cert valid but < 14 days of life left | 1h | warning |
| `ArgusCertExpired` | Cert expired or unreadable (`expiry_days < 0`) | 5m | critical |
| `ArgusSecurityHeaderMissing` | A live endpoint is missing a scored header | 30m | warning |
| `ArgusEndpointDown` | `argus_endpoint_up == 0` | 5m | critical |
| `ArgusUnexpectedOpenPort` | A host has open ports not on its allowlist | 15m | warning |
| `ArgusDependencyVulnHigh` | Any HIGH/CRITICAL dependency vulnerability | 1h | high |

By default alerts go to a **null receiver** (visible in the Alertmanager UI, paged nowhere) so a first run never surprises you. To wire Slack, open [`deploy/alertmanager.yml`](deploy/alertmanager.yml), uncomment the `slack` receiver, paste your webhook URL, and repoint the route. Comments in the file walk you through it.

---

## Adding your own targets

Everything is driven by `config.yaml` (copy it from `config.example.yaml`). No code changes needed.

```yaml
collectors:
  tls_cert:
    targets:
      - "your-api.example.com:443"   # host:port shorthand
      - host: "internal.example.com" # or a mapping
        port: 8443

  http_headers:
    targets:
      - "https://your-site.example.com"

  ports:
    targets:
      - host: "your-host.example.com"
        allowed_ports: [22, 443]       # what SHOULD be open
        scan_ports: [22, 80, 443, "8000-8010"]  # what to probe

  dependencies:
    files:
      - "requirements.txt"   # scan your real pinned deps
```

> The shipped `config.example.yaml` points the dependency scanner at
> `examples/vulnerable-requirements.txt` :  a deliberately old, clearly
> labelled demo fixture :  so a first run actually shows HIGH/CRITICAL
> findings from live OSV.dev data. Argus's own runtime dependencies
> (`requirements.txt`) are kept current. Point the scanner at your own file
> to check your real dependencies.

Turn whole collectors off in the `enabled:` block. After editing, restart the exporter (or `docker compose restart argus`).

---

## Running the tests

```bash
pip install pytest
python -m pytest tests/ -v
```

The two core collectors (`tls_cert`, `http_headers`) have full unit tests covering the expiry maths, validity windows, case-insensitive header matching, and failure handling :  all with the network mocked, so the suite is fast and offline.

---

## Limitations

Honest notes, because this is real software, not a demo:

- **Synchronous scrape.** Every check runs in series when Prometheus scrapes, so a config with many targets makes a scrape slow. The default `scrape_interval` is 2 minutes and `scrape_timeout` is 110s to accommodate this. If you only run `tls_cert` + `http_headers`, you can safely drop those to ~30s.
- **Port scan is deliberately small.** The `ports` collector is a polite TCP-connect probe over a configurable list of ports, not a full 1-65535 sweep, and it doesn't do UDP or service fingerprinting. It's built for *drift detection against a known-good allowlist*, not discovery. Use a dedicated scanner (nmap) for exhaustive work.
- **Dependency severity needs follow-up calls.** OSV's batch endpoint returns only vulnerability IDs, so Argus makes one extra request per unique vuln to fetch its severity. These follow-ups are capped per scrape (`dependencies.max_lookups`); past the cap, findings are counted as `UNKNOWN`. Only exact (`==`) pins are scanned.

---

## Roadmap

These are signals worth adding next. **They are not built yet** :  listed here so the direction is clear:

- **AWS IAM key age** :  flag access keys older than N days (`argus_iam_key_age_days`).
- **Public S3 buckets** :  detect buckets with public-read/-write ACLs or policies.
- **Cloud security-group drift** :  the `ports` idea, but for AWS/GCP firewall rules.
- **DNS / DNSSEC health** :  missing CAA records, unsigned zones.
- **Certificate transparency** :  alert on unexpected certs issued for your domains.
- **Pushgateway / batch mode** :  for environments that can't scrape a long-running server.

---

## License

MIT © 2026 Vishnu Kosuri. See [LICENSE](LICENSE).
