# OSINT Dependency Vulnerability Intelligence

[![Live Demo](https://img.shields.io/badge/Live%20Demo-online-00f5ff?style=flat)](https://passive-vuln-osint-production.up.railway.app)
[![CI](https://github.com/todorslavovv/passive-vuln-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/todorslavovv/passive-vuln-osint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**▶ Live demo: [passive-vuln-osint-production.up.railway.app](https://passive-vuln-osint-production.up.railway.app)** — try it in the browser (each visitor gets a private sandbox).

**Passive OSINT supply-chain dependency vulnerability intelligence CLI and dashboard.** Discovers software dependencies from public web artifacts (HTML, JS bundles, source maps, manifests), resolves versions with evidence chains, correlates known vulnerabilities (OSV, NVD), scores risk, and outputs JSON/text/DOT/SBOM reports. Zero third-party dependencies. 90% test coverage. Designed for offensive security recon and defensive posture assessment — no active scanning required.

---

This project is a passive OSINT-based Supply Chain Dependency Vulnerability Intelligence System. It discovers dependency evidence from public artifacts, normalizes that evidence, builds a confidence-aware dependency graph, enriches dependencies with vulnerability data, correlates exploit availability as a separate signal, scores risk, and writes JSON, text, DOT graph, and SBOM reports.

## Design Choices

- **Language:** Python 3.10+ for portability, strong standard-library support, and easy local execution on Windows 10 and Ubuntu.
- **Dependencies:** no required third-party packages for the core CLI and tests. The web dashboard uses `fastapi` and `uvicorn` only when the server is started.
- **Storage:** JSON files for target configuration, fixtures, and reports. No database setup required.
- **Architecture:** modular package with discovery plugins, enrichment providers, graph construction, scoring, reporting, a global registry, and a web dashboard.
- **Passive-only:** the tool performs optional public HTTP GET/POST requests to published artifacts and advisory APIs. It does not port scan, brute force, crawl private endpoints, exploit, or actively probe vulnerabilities.

## Web Dashboard

Start the dashboard from the repository root:

```powershell
python3 -m osintdepintel --server --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000` in a browser.

### Dashboard tabs

- **Dashboard** — overview cards and recent scan activity.
- **Target Manager** — add, edit, and delete target definitions (URL, GitHub repos, SBOM URLs, package hints, etc.).
- **Scan Runner** — select a single target via radio button and choose live or offline mode. A per-target AI summary is generated automatically when the server has an OpenCode key.
- **Report Explorer** — browse per-target reports, view the AI summary flag, download artifacts, and delete reports.

### Per-target AI summaries

The dashboard can generate a plain-language AI summary for each scanned website using **OpenCode Zen** (an OpenAI-compatible gateway). The default model is `laguna-s-2.1-free`.

The API key is set as an environment variable:

```powershell
$env:OPENCODE_API_KEY="your-key"
$env:OPENCODE_MODEL="laguna-s-2.1-free"  # optional; this is the default
```

When `OPENCODE_API_KEY` is set in the environment, the dashboard generates an AI summary for every scanned target automatically — no UI toggle or per-visitor setup needed (this is the Railway deployment path). It is also available on the CLI with `--opencode-summary`.

`OPENCODE_MODEL` defaults to `laguna-s-2.1-free`; any id from `https://opencode.ai/zen/v1/models` works. (Note: the Muse Spark free tier `muse-spark-1.2-contributor-free` returns HTTP 500 for raw API keys — it requires the interactive OpenCode CLI contributor opt-in and is not usable from a server.)

If no key is provided, the scanner writes a deterministic local-fallback explanation to the per-target summary file so the report remains complete. The same fallback is used if the model is temporarily unavailable, so a scan never fails because of an AI error.

### Report artifacts

For each target, the dashboard and CLI write:

- `reports/<target>.json` — machine-readable report with dependencies, graph, vulnerabilities, findings, and registry state.
- `reports/<target>.txt` — human-readable report.
- `reports/<target>.dot` — Graphviz DOT dependency graph.
- `reports/<target>_cyclonedx.json` — CycloneDX SBOM.
- `reports/<target>_spdx.json` — SPDX SBOM.
- `reports/<target>_opencode_summary.txt` — per-target OpenCode AI summary.

It also writes:

- `reports/aggregate_report.json` — aggregate summary across processed targets.

Re-scanning the same target overwrites the previous report files, so the report list stays clean.

## Deploy the dashboard on Railway

The repo ships a container image and Railway config for the web dashboard:

- `Dockerfile.railway` — runs the FastAPI dashboard from source (so the static assets and example targets are present) and binds to Railway's injected `$PORT`.
- `railway.json` — points Railway at that Dockerfile.

Steps:

1. Create a new Railway project from this GitHub repo (Railway auto-detects `railway.json`).
2. In the service **Variables**, add `OPENCODE_API_KEY` (and optionally `OPENCODE_MODEL`, default `laguna-s-2.1-free`). With the key set, every scan gets an AI summary automatically.
3. Deploy. Railway assigns a public URL; the container serves the dashboard on `$PORT`.

The container reads its config from `OSINT_CONFIG_PATH` and writes reports to `OSINT_OUTPUT_DIR` (both preset in the image). Railway's filesystem is ephemeral — attach a volume at the output dir if you want reports to persist across restarts.

To build/run the same image locally:

```bash
docker build -f Dockerfile.railway -t osintdepintel-web .
docker run --rm -p 8000:8000 -e OPENCODE_API_KEY="your-key" osintdepintel-web
```

## CLI Usage

Run all sample targets offline:

```powershell
python -m osintdepintel --config examples/targets.json --all --offline --output-dir reports
```

Run one target offline:

```powershell
python -m osintdepintel --config examples/targets.json --target juice-shop --offline --output-dir reports
```

Run live passive collection and enrichment:

```powershell
python -m osintdepintel --config examples/targets.json --target juice-shop --output-dir reports
```

Live mode may query public target HTML/JS artifacts, configured GitHub raw manifests, configured SBOM URLs, the Wayback Machine CDX API, OSV.dev, and NVD. Missing sources are recorded in the global registry rather than treated as fatal.

### Fail-on severity gate (CI/CD)

Use `--fail-on` to make the CLI exit with a non-zero status when a finding meets or exceeds a severity, so it can block a pipeline on risky dependencies:

```bash
python -m osintdepintel --config examples/targets.json --all --offline --output-dir reports --fail-on high
```

- Accepted thresholds: `critical`, `high`, `medium`, `low`.
- Exit code `3` means the gate tripped (at least one finding at or above the threshold). This is kept distinct from exit code `2` (usage/execution errors) so CI can tell "risky finding" apart from "bad invocation".
- Reports are still written normally before the process exits; the gate only changes the exit status.

## Target Modes

Every target is labeled as one of:

- `LAB TARGETS`
- `AUTHORIZED REAL TARGETS`
- `PUBLIC OSINT TARGETS`

The sample config in `examples/targets.json` includes all seven targets named in the original brief plus an optional public-website probe target.

## Extending Discovery

Create a new class that implements `DiscoveryPlugin` from `osintdepintel.discovery.base`, return a `DiscoveryResult`, and normalize every dependency into `DependencyRecord` with:

- package name
- ecosystem
- version or `None`
- confirmed/inferred status
- confidence
- provenance
- timestamp through provenance

Then add the plugin to `default_plugins()` or pass it into `Pipeline(plugins=[...])`.

## Confidence Model

The project explicitly separates:

- `confirmed`: direct evidence from manifests, SBOMs, or similarly strong artifacts.
- `inferred`: weaker evidence from bundle tokens, public hints, transitive metadata, or ambiguous source material.

Every dependency and edge carries confidence. Conflicts are kept in the global registry and are not silently discarded.

## JS/HTML Evidence Chains

The JavaScript discovery plugin converts passive web artifacts into structured dependency candidates. It inspects:

- HTML script tags and inline scripts
- inline runtime config dependency blocks such as `window.__APP_CONFIG__.dependencies`
- public JavaScript bundles
- source map references and source map contents
- Webpack `node_modules` paths
- Next.js, Webpack, React, and SharePoint-style public fingerprints
- versioned asset filenames such as `jquery-3.6.0.min.js`
- embedded package metadata such as source-map `package.json` contents
- dependency declarations embedded in runtime config blocks

Each candidate includes an evidence chain in `dependency.qualifiers.evidence_chain` with the source URL, fetch method, timestamp, content hash, snippet/token, plugin name, direct/indirect evidence marker, and reasoning. Exact package metadata from manifests or source-map `package.json` content can confirm a dependency. Bundle-only, filename-only, or framework-fingerprint evidence stays inferred and lower confidence.

Conflicting versions are preserved as separate claims and recorded in the registry conflict summary. Unknown-version hints from the same package are not treated as conflicts when a stronger exact version is present; they are folded into the evidence trail conservatively.

## Risk Scoring

Risk findings are ranked with transparent factors:

- vulnerability severity or CVSS
- exploit availability signal
- exposure confidence
- patch lag
- provenance quality
- inferred-status penalty

Exploit availability is never treated as proof that a target is exploitable.

## Tests

```powershell
python -m pytest tests
```

Tests use fixtures from `tests/fixtures/offline_intel.json` and do not require network access.

## Continuous Integration

Every push and pull request to `main` runs the full quality gate on Python 3.10, 3.11, and 3.12 via GitHub Actions (`.github/workflows/ci.yml`): `ruff check`, `ruff format --check`, `mypy` (strict), and `pytest`. The same gate can be run locally with `make check`.

## Assumptions and Limitations

- JavaScript bundle discovery uses passive public artifacts and conservative package hint extraction. Minified bundles and sourcemaps can be incomplete or misleading.
- GitHub discovery requires configured repositories. The system still works when GitHub data is absent.
- Container image and APK/IPA artifact analysis are implemented as plugin hooks and documented stubs. Full registry layer parsing and mobile extraction are intentionally left as extension points.
- GitHub Advisory Database is represented through OSV overlap unless a richer authenticated provider is added.
- NVD keyword matching is supplemental because precise CPE matching is difficult across package ecosystems without curated mappings.
- Offline sample findings are demonstration fixtures, not assertions that any live target is vulnerable.

## License

[MIT](LICENSE) — see [LICENSE](LICENSE) for the full text.
