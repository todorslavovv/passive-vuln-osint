# OSINT Dependency Vulnerability Intelligence

**Passive OSINT supply-chain dependency vulnerability intelligence CLI.** Discovers software dependencies from public web artifacts (HTML, JS bundles, source maps, manifests), resolves versions with evidence chains, correlates known vulnerabilities (OSV, NVD), scores risk, and outputs JSON/text/DOT reports. Zero third-party dependencies. 90% test coverage. Designed for offensive security recon and defensive posture assessment — no active scanning required.

---

This project is a passive OSINT-based Supply Chain Dependency Vulnerability Intelligence System. It discovers dependency evidence from public artifacts, normalizes that evidence, builds a confidence-aware dependency graph, enriches dependencies with vulnerability data, correlates exploit availability as a separate signal, scores risk, and writes JSON, text, and DOT graph reports.

## Design Choices

- **Language:** Python 3.10+ for portability, strong standard-library support, and easy local execution on Windows 10 and Ubuntu.
- **Dependencies:** no required third-party packages. The CLI, tests, HTTP client, parsing, graph export, and reports use only the Python standard library.
- **Storage:** JSON files for target configuration, fixtures, and reports. This keeps the portfolio project inspectable and easy to run without database setup.
- **Architecture:** modular package with discovery plugins, enrichment providers, graph construction, scoring, reporting, and a global registry.
- **Passive-only:** the tool performs optional public HTTP GET/POST requests to published artifacts and advisory APIs. It does not port scan, brute force, crawl private endpoints, exploit, or actively probe vulnerabilities.

## Target Modes

Every target is labeled as one of:

- `LAB TARGETS`
- `AUTHORIZED REAL TARGETS`
- `PUBLIC OSINT TARGETS`

The sample config in `examples/targets.json` includes all seven targets named in the original brief. The brief later says "six targets", but seven concrete targets were listed, so none were removed.

## Quick Start

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

## Output

For each target, the CLI writes:

- `reports/<target>.json`: machine-readable report with dependencies, graph, vulnerabilities, findings, and registry state.
- `reports/<target>.txt`: human-readable report.
- `reports/<target>.dot`: Graphviz DOT dependency graph.

It also writes:

- `reports/aggregate_report.json`: aggregate summary across processed targets.

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

The JavaScript discovery plugin now converts passive web artifacts into structured dependency candidates instead of only recording detected files. It inspects:

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
python -m unittest discover -s tests
```

Tests use fixtures from `tests/fixtures/offline_intel.json` and do not require network access.

## Assumptions and Limitations

- JavaScript bundle discovery uses passive public artifacts and conservative package hint extraction. Minified bundles and sourcemaps can be incomplete or misleading.
- GitHub discovery requires configured repositories. The system still works when GitHub data is absent.
- Container image and APK/IPA artifact analysis are implemented as plugin hooks and documented stubs. Full registry layer parsing and mobile extraction are intentionally left as extension points.
- GitHub Advisory Database is represented through OSV overlap unless a richer authenticated provider is added.
- NVD keyword matching is supplemental because precise CPE matching is difficult across package ecosystems without curated mappings.
- Offline sample findings are demonstration fixtures, not assertions that any live target is vulnerable.
