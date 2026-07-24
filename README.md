# OSINT Dependency Vulnerability Intelligence

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
- **Scan Runner** — select a single target via radio button, choose live or offline mode, and optionally generate per-target AI summaries with NVIDIA or Gemini.
- **Report Explorer** — browse per-target reports, view AI summary flags, download artifacts, and delete reports.

### Per-target AI summaries

The dashboard can generate a separate AI summary for each scanned website:

- **NVIDIA** — choose from `nvidia/nemotron-3-ultra-550b-a55b`, `nvidia/llama-3.1-nemotron-70b-instruct`, and `nvidia/mistralai/mixtral-8x22b-instruct-v0.1`.
- **Gemini** — choose from `gemini-1.5-flash`, `gemini-1.5-flash-8b`, `gemini-1.5-pro`, and `gemini-2.0-flash`.

API keys can be pasted in the UI or set as environment variables:

```powershell
$env:NVIDIA_API_KEY="your-key"
$env:GEMINI_API_KEY="your-key"
```

If no key is provided, the scanner writes a fallback explanation to the per-target summary file so the report remains complete.

### Report artifacts

For each target, the dashboard and CLI write:

- `reports/<target>.json` — machine-readable report with dependencies, graph, vulnerabilities, findings, and registry state.
- `reports/<target>.txt` — human-readable report.
- `reports/<target>.dot` — Graphviz DOT dependency graph.
- `reports/<target>_cyclonedx.json` — CycloneDX SBOM.
- `reports/<target>_spdx.json` — SPDX SBOM.
- `reports/<target>_nvidia_summary.txt` — per-target NVIDIA AI summary.
- `reports/<target>_gemini_summary.txt` — per-target Gemini AI summary.

It also writes:

- `reports/aggregate_report.json` — aggregate summary across processed targets.

Re-scanning the same target overwrites the previous report files, so the report list stays clean.

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

## Assumptions and Limitations

- JavaScript bundle discovery uses passive public artifacts and conservative package hint extraction. Minified bundles and sourcemaps can be incomplete or misleading.
- GitHub discovery requires configured repositories. The system still works when GitHub data is absent.
- Container image and APK/IPA artifact analysis are implemented as plugin hooks and documented stubs. Full registry layer parsing and mobile extraction are intentionally left as extension points.
- GitHub Advisory Database is represented through OSV overlap unless a richer authenticated provider is added.
- NVD keyword matching is supplemental because precise CPE matching is difficult across package ecosystems without curated mappings.
- Offline sample findings are demonstration fixtures, not assertions that any live target is vulnerable.

## License

[MIT](LICENSE) — see [LICENSE](LICENSE) for the full text.
