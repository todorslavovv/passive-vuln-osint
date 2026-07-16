# Contributing

## Dev Setup

```bash
git clone <repo>
cd OSINT_Project
pip install -e ".[dev]"
pre-commit install
```

## Running Tests

```bash
python -m pytest --cov=osintdepintel --cov-report=term-missing
```

## Code Style

This project enforces ruff (lint + format) and mypy strict mode. Pre-commit hooks run automatically on commit. Run manually:

```bash
ruff check .
ruff format .
mypy osintdepintel --strict
```

## Adding a Discovery Plugin

1. Subclass `DiscoveryPlugin` from `osintdepintel/discovery/base.py`
2. Set a unique `name` class attribute
3. Implement `discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult`
4. Register in `default_plugins()` in `osintdepintel/discovery/plugins.py`
5. Write tests in `tests/test_<plugin_name>_plugin.py`
6. All HTTP must go through `self.http` (HttpClient) — no direct urllib calls

## Adding an Enrichment Provider

1. Add a method to `EnrichmentEngine` in `osintdepintel/enrichment/providers.py`
2. Call it from `EnrichmentEngine.enrich()`
3. Return a list of `VulnerabilityRecord` objects
4. Write mocked tests in `tests/test_enrichment_providers.py`
5. Respect the rate limiter — use the injected `HttpClient`

## PR Requirements

- All existing tests must pass
- New code must have tests
- Total coverage must not drop below current baseline (80% module-level)
- Each module with coverage ≤80% must show improvement (no regressions in per-module coverage below its current level)
- mypy strict and ruff must be clean
- No direct urllib usage outside HttpClient
