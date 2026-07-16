from __future__ import annotations

import io
import json
import plistlib
import re
import urllib.parse
import zipfile
from hashlib import sha256
from typing import Any, cast

from ..http import HttpClient, HttpError, join_url
from ..js_inference import (
    DependencyCandidate,
    decode_inline_source_map,
    extract_script_urls,
    extract_source_map_urls,
    infer_from_html,
    infer_from_js,
    infer_from_source_map,
)
from ..models import DependencyRecord, DependencyStatus, DiscoveryResult, Provenance, TargetConfig
from ..parsers import (
    normalize_ecosystem,
    parse_cyclonedx_sbom,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements,
    parse_spdx_sbom,
)
from ..registry import GlobalRegistry
from .base import DiscoveryPlugin


class PackageHintsPlugin(DiscoveryPlugin):
    name = "package_hints"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if not self.offline:
            registry.add_gap(
                target.name,
                self.name,
                "unverified",
                "online mode does not promote configured package hints into dependency records",
            )
            registry.add_plugin_event(
                target.name, self.name, "skipped configured hints as dependency evidence in online mode"
            )
            return result
        for hint in target.package_hints:
            name = hint.get("name")
            ecosystem = hint.get("ecosystem")
            if not name or not ecosystem:
                result.failures.append("package hint missing name or ecosystem")
                continue
            provenance = Provenance(
                source_type="target_config",
                source_name=self.name,
                locator=target.name,
                evidence=hint.get("evidence", "configured package hint"),
                fetch_method="CONFIG",
                snippet=hint.get("evidence", "configured package hint")[:240],
            )
            result.observations.append(
                _observation(
                    target.name,
                    self.name,
                    "target_config",
                    target.name,
                    "CONFIG",
                    hint.get("evidence", "configured package hint"),
                )
            )
            result.inferences.append(
                _inference(
                    target.name,
                    self.name,
                    name,
                    normalize_ecosystem(ecosystem),
                    hint.get("version"),
                    "configured package hint is not strong source evidence unless explicitly marked confirmed",
                    hint.get("status", DependencyStatus.INFERRED.value),
                    float(hint.get("confidence", 0.55)),
                )
            )
            result.records.append(
                DependencyRecord(
                    target_name=target.name,
                    name=name,
                    ecosystem=normalize_ecosystem(ecosystem),
                    version=hint.get("version"),
                    status=DependencyStatus(hint.get("status", DependencyStatus.INFERRED.value)),
                    confidence=float(hint.get("confidence", 0.55)),
                    provenance=[provenance],
                    relationship=hint.get("relationship", "direct"),
                    scope=hint.get("scope", "runtime"),
                )
            )
            if hint.get("status", DependencyStatus.INFERRED.value) == DependencyStatus.INFERRED.value:
                registry.add_gap(
                    target.name,
                    self.name,
                    "unverified",
                    f"package hint for {name} requires stronger target-derived evidence",
                )
        registry.add_plugin_event(target.name, self.name, f"loaded {len(result.records)} configured package hints")
        return result


class JavaScriptBundlePlugin(DiscoveryPlugin):
    name = "javascript_bundles"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped public JavaScript collection")
            registry.add_gap(
                target.name, self.name, "not_collected", "offline mode skipped public JavaScript collection"
            )
            return result
        try:
            html = self.http.fetch(target.url)
        except HttpError as exc:
            result.failures.append(f"could not fetch target HTML: {exc}")
            return result
        result.observations.append(_observation(target.name, self.name, "target_html", target.url, "GET", html))
        html_candidates = infer_from_html(target.name, html, target.url, self.name)
        _add_candidates(result, html_candidates)
        script_urls = extract_script_urls(target.url, html)
        registry.add_plugin_event(target.name, self.name, f"found {len(script_urls)} script candidates")
        if not script_urls:
            registry.add_gap(
                target.name, self.name, "collected_but_empty", "target HTML was fetched but no script tags were found"
            )
        for script_url in script_urls[:10]:
            try:
                body = self.http.fetch(script_url)
            except HttpError as exc:
                result.failures.append(f"could not fetch JS artifact {script_url}: {exc}")
                continue
            result.observations.append(
                _observation(target.name, self.name, "public_js_bundle", script_url, "GET", body)
            )
            js_candidates = infer_from_js(target.name, body, script_url, self.name)
            _add_candidates(result, js_candidates)
            source_map_urls = extract_source_map_urls(script_url, body)
            if not js_candidates and not source_map_urls:
                registry.add_gap(
                    target.name,
                    self.name,
                    "collected_but_empty",
                    f"JS artifact fetched but no dependency candidates were extracted: {script_url}",
                )
            for source_map_url in source_map_urls[:3]:
                if source_map_url.startswith("data:"):
                    source_map_body = decode_inline_source_map(source_map_url)
                    locator = f"{script_url}#inline-source-map"
                    if source_map_body is None:
                        registry.add_gap(
                            target.name,
                            self.name,
                            "collected_but_empty",
                            f"inline source map could not be decoded: {script_url}",
                        )
                        continue
                else:
                    locator = source_map_url
                    try:
                        source_map_body = self.http.fetch(source_map_url)
                    except HttpError as exc:
                        result.failures.append(f"could not fetch source map {source_map_url}: {exc}")
                        registry.add_gap(
                            target.name,
                            self.name,
                            "not_collected",
                            f"source map reference was present but could not be fetched: {source_map_url}",
                        )
                        continue
                result.observations.append(
                    _observation(target.name, self.name, "source_map", locator, "GET", source_map_body)
                )
                map_candidates = infer_from_source_map(target.name, source_map_body, locator, self.name)
                if not map_candidates:
                    registry.add_gap(
                        target.name,
                        self.name,
                        "collected_but_empty",
                        f"source map fetched but no dependency candidates were extracted: {locator}",
                    )
                _add_candidates(result, map_candidates)
        _add_candidate_conflicts(result)
        return result


class GitHubRepositoryPlugin(DiscoveryPlugin):
    name = "github_repositories"

    manifest_paths = [
        "package.json",
        "requirements.txt",
        "pom.xml",
        "go.mod",
        "Gemfile.lock",
    ]

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if not target.github_repos:
            registry.add_assumption(target.name, self.name, "no GitHub repository was configured or discovered")
            registry.add_gap(
                target.name, self.name, "missing_input", "no GitHub repository was configured or discovered"
            )
            return result
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped GitHub repository collection")
            registry.add_gap(
                target.name, self.name, "not_collected", "offline mode skipped GitHub repository collection"
            )
            return result
        for repo in target.github_repos:
            owner_repo = _owner_repo(repo)
            if not owner_repo:
                result.failures.append(f"unsupported GitHub repo locator: {repo}")
                continue
            repo_found = False
            for branch in ("main", "master"):
                if repo_found:
                    break
                for path in self.manifest_paths:
                    url = f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{path}"
                    try:
                        text = self.http.fetch(url)
                    except HttpError:
                        continue
                    result.observations.append(
                        _observation(target.name, self.name, "github_manifest", url, "GET", text)
                    )
                    new_records = _manifest_records(target.name, text, path, url, self.name)
                    if new_records:
                        result.records.extend(new_records)
                        repo_found = True
                        for record in new_records:
                            result.inferences.append(
                                _inference(
                                    target.name,
                                    self.name,
                                    record.name,
                                    record.ecosystem,
                                    record.version,
                                    "dependency parsed from public repository manifest",
                                    DependencyStatus.CONFIRMED.value,
                                    record.confidence,
                                )
                            )
        if not result.records:
            registry.add_gap(
                target.name,
                self.name,
                "collected_but_empty",
                "configured GitHub repositories were checked but no supported manifests were loaded",
            )
        registry.add_plugin_event(
            target.name, self.name, f"loaded {len(result.records)} dependencies from GitHub manifests"
        )
        return result


class SBOMPlugin(DiscoveryPlugin):
    name = "public_sboms"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if not target.sbom_urls:
            registry.add_assumption(target.name, self.name, "no public SBOM URL configured")
            registry.add_gap(target.name, self.name, "missing_input", "no public SBOM URL configured")
            return result
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped public SBOM collection")
            registry.add_gap(target.name, self.name, "not_collected", "offline mode skipped public SBOM collection")
            return result
        for url in target.sbom_urls:
            try:
                raw = json.loads(self.http.fetch(url))
            except (HttpError, json.JSONDecodeError) as exc:
                result.failures.append(f"could not load SBOM {url}: {exc}")
                continue
            result.observations.append(
                _observation(target.name, self.name, "public_sbom", url, "GET", json.dumps(raw, sort_keys=True))
            )
            parsed = parse_cyclonedx_sbom(raw) if "components" in raw else parse_spdx_sbom(raw)
            for name, ecosystem, version, scope in parsed:
                result.records.append(
                    _record(
                        target.name,
                        name,
                        ecosystem,
                        version,
                        DependencyStatus.CONFIRMED,
                        0.9,
                        "public_sbom",
                        self.name,
                        url,
                        "package listed in public SBOM",
                        scope,
                    )
                )
                result.inferences.append(
                    _inference(
                        target.name,
                        self.name,
                        name,
                        ecosystem,
                        version,
                        "package listed in public SBOM",
                        DependencyStatus.CONFIRMED.value,
                        0.9,
                    )
                )
        return result


class WaybackMachinePlugin(DiscoveryPlugin):
    name = "wayback_machine"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped Wayback Machine collection")
            registry.add_gap(target.name, self.name, "not_collected", "offline mode skipped Wayback Machine collection")
            return result
        host = urllib.parse.urlparse(target.url).netloc
        if not host:
            return result
        cdx = (
            f"https://web.archive.org/cdx?url={urllib.parse.quote(host)}/*"
            "&output=json&fl=original,timestamp,statuscode&filter=mimetype:application/javascript&limit=30"
        )
        try:
            raw = self.http.get_json(cdx)
        except HttpError as exc:
            result.failures.append(f"could not query Wayback CDX: {exc}")
            return result
        rows: list[list[str]] = cast("list[list[str]]", raw) if isinstance(raw, list) else []
        data_rows = rows[1:] if len(rows) > 1 else []
        if not data_rows:
            registry.add_gap(
                target.name, self.name, "collected_but_empty", "Wayback CDX query returned no archived JavaScript URLs"
            )
            return result
        url_to_timestamps: dict[str, list[str]] = {}
        for row in data_rows:
            if len(row) >= 3 and row[2] == "200":
                original_url = row[0]
                timestamp = row[1]
                url_to_timestamps.setdefault(original_url, []).append(timestamp)
        result.observations.append(
            _observation(target.name, self.name, "wayback_cdx", cdx, "GET", json.dumps(rows[:20]))
        )
        registry.add_plugin_event(target.name, self.name, f"found {len(url_to_timestamps)} unique archived JS URLs")
        for original_url, timestamps in url_to_timestamps.items():
            for ts in sorted(timestamps, reverse=True)[:3]:
                wayback_url = f"https://web.archive.org/web/{ts}/{original_url}"
                try:
                    js_text = self.http.fetch(wayback_url)
                except HttpError:
                    registry.add_observation(
                        _observation(
                            target.name,
                            self.name,
                            "wayback_fetch_failed",
                            wayback_url,
                            "GET",
                            f"could not fetch archived JS from {wayback_url}",
                        )
                    )
                    continue
                candidates = infer_from_js(target.name, js_text, original_url, self.name, "wayback_archive")
                for candidate in candidates:
                    candidate.confidence = max(0.1, candidate.confidence - 0.1)
                    candidate.reasoning += " [historical snapshot from Wayback Machine]"
                    for ev in candidate.evidence_chain:
                        ev.source_url = wayback_url
                        ev.source_type = "wayback_machine"
                        ev.plugin_name = self.name
                        ev.fetch_method = "CDX+GET"
                    candidate.conflict_notes.append(f"historical_snapshot:true, archived_timestamp:{ts}")
                    record = candidate.to_record()
                    for prov in record.provenance:
                        prov.source_type = "wayback_machine"
                        prov.source_name = "Wayback Machine"
                        prov.locator = wayback_url
                        prov.fetch_method = "CDX+GET"
                        prov.evidence = f"Archived JS snapshot from {ts}"
                    record.qualifiers["historical_snapshot"] = True
                    record.qualifiers["archived_timestamp"] = ts
                    result.records.append(record)
                    result.inferences.append(candidate.to_inference(self.name))
        return result


class ContainerImagePlugin(DiscoveryPlugin):
    name = "container_images"

    DOCKER_HUB_REGISTRY = "registry-1.docker.io"
    DOCKER_HUB_TOKEN_URL = "https://auth.docker.io/token"
    DOCKER_HUB_SERVICE = "registry.docker.io"
    KNOWN_REGISTRIES = frozenset({"docker.io", "ghcr.io"})

    MANIFEST_MEDIA_TYPES = [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ]

    _PKG_PATTERNS: list[tuple[str, str]] = [
        (r"apt-get\s+install", "deb"),
        (r"(?<!/)apt\s+install", "deb"),
        (r"apk\s+add", "apk"),
        (r"npm\s+install", "npm"),
        (r"pip3?\s+install", "pip"),
        (r"gem\s+install", "gem"),
    ]

    _ENV_VERSION_RE = re.compile(r"^([A-Z][A-Z0-9_]*_VERSION)=(.+)$")

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if not target.container_images:
            registry.add_assumption(target.name, self.name, "no container image was configured")
            registry.add_gap(target.name, self.name, "missing_input", "no container image was configured")
            return result
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped container image collection")
            registry.add_gap(target.name, self.name, "not_collected", "offline mode skipped container image collection")
            for image in target.container_images:
                result.assumptions.append(f"container image skipped due to offline mode: {image}")
            return result
        for image_ref in target.container_images[:5]:
            try:
                reg, repo, ref = self._parse_image_ref(image_ref)
            except ValueError as exc:
                result.failures.append(f"could not parse image reference {image_ref}: {exc}")
                continue
            try:
                token = self._exchange_token(reg, repo)
            except HttpError as exc:
                result.failures.append(f"token exchange failed for {image_ref}: {exc}")
                registry.add_gap(target.name, self.name, "not_collected", f"token exchange failed for {image_ref}")
                continue
            try:
                manifest = self._fetch_manifest(reg, repo, ref, token)
            except HttpError as exc:
                result.failures.append(f"manifest fetch failed for {image_ref}: {exc}")
                registry.add_gap(target.name, self.name, "not_collected", f"manifest fetch failed for {image_ref}")
                continue
            result.observations.append(
                _observation(
                    target.name,
                    self.name,
                    "oci_manifest",
                    f"{reg}/{repo}:{ref}",
                    "GET",
                    json.dumps(manifest, sort_keys=True),
                )
            )
            config_digest, child_failed = self._resolve_manifest_config(
                manifest, reg, repo, ref, image_ref, token, result
            )
            if config_digest is None and not child_failed:
                registry.add_gap(
                    target.name,
                    self.name,
                    "collected_but_empty",
                    f"no config blob digest in manifest for {image_ref}",
                )
            if config_digest is None:
                continue
            try:
                config = self._fetch_blob(reg, repo, config_digest, token)
            except HttpError as exc:
                result.failures.append(f"config blob fetch failed for {image_ref}: {exc}")
                continue
            result.observations.append(
                _observation(
                    target.name,
                    self.name,
                    "oci_config",
                    f"{reg}/{repo}@{config_digest}",
                    "GET",
                    json.dumps(config, sort_keys=True),
                )
            )
            self._extract_from_config(result, target, image_ref, reg, repo, ref, config)
        if not result.records:
            registry.add_gap(
                target.name,
                self.name,
                "collected_but_empty",
                "container images were checked but no dependencies were extracted",
            )
        registry.add_plugin_event(
            target.name,
            self.name,
            f"loaded {len(result.records)} dependencies from {len(target.container_images)} container images",
        )
        return result

    @staticmethod
    def _parse_oci_manifest(manifest: dict[str, Any]) -> tuple[str | None, str | None]:
        mt = manifest.get("mediaType", "")
        if mt in (
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.index.v1+json",
        ):
            manifests = manifest.get("manifests", [])
            child_digest = manifests[0].get("digest") if manifests else None
            return None, child_digest
        return manifest.get("config", {}).get("digest"), None

    def _resolve_manifest_config(
        self,
        manifest: dict[str, Any],
        reg: str,
        repo: str,
        ref: str,
        image_ref: str,
        token: str,
        result: DiscoveryResult,
    ) -> tuple[str | None, bool]:
        config_digest, child_digest = self._parse_oci_manifest(manifest)
        if child_digest:
            try:
                child = self._fetch_manifest(reg, repo, child_digest, token, digest=True)
            except HttpError as exc:
                result.failures.append(f"child manifest fetch failed for {image_ref}: {exc}")
                return None, True
            result.observations.append(
                _observation(
                    self.name,
                    self.name,
                    "oci_child_manifest",
                    f"{reg}/{repo}@{child_digest}",
                    "GET",
                    json.dumps(child, sort_keys=True),
                )
            )
            config_digest = child.get("config", {}).get("digest")
        return config_digest, False

    @staticmethod
    def _parse_image_ref(ref: str) -> tuple[str, str, str]:
        tag: str = "latest"
        if "@" in ref:
            ref, tag = ref.split("@", 1)
        if ":" in ref:
            parts = ref.rsplit(":", 1)
            if "/" not in parts[1]:
                ref = parts[0]
                tag = parts[1]
        if "/" not in ref:
            return "docker.io", f"library/{ref}", tag
        first = ref.split("/", 1)[0]
        if "." in first or ":" in first or first in {"docker.io", "ghcr.io"}:
            registry = first
            repository = ref[len(first) + 1 :]
        else:
            registry = "docker.io"
            repository = ref
        return registry, repository, tag

    def _exchange_token(self, registry: str, repository: str) -> str:
        import urllib.parse

        scope = f"repository:{repository}:pull"
        if registry == "docker.io":
            params = urllib.parse.urlencode({"service": self.DOCKER_HUB_SERVICE, "scope": scope})
            url = f"{self.DOCKER_HUB_TOKEN_URL}?{params}"
        else:
            params = urllib.parse.urlencode({"scope": scope})
            url = f"https://{registry}/token?{params}"
        data: Any = self.http.get_json(url)
        token: str | None = data.get("token") or data.get("access_token")
        if not token:
            raise HttpError(f"no token in auth response from {registry}")
        return token

    def _fetch_with_auth(self, url: str, token: str, accept: str) -> str:
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": accept,
        }
        return self.http.fetch(url, headers=headers)

    def _registry_base(self, registry: str) -> str:
        if registry == "docker.io":
            return f"https://{self.DOCKER_HUB_REGISTRY}"
        return f"https://{registry}"

    def _fetch_manifest(self, registry: str, repository: str, ref: str, token: str, digest: bool = False) -> Any:
        base = self._registry_base(registry)
        url = f"{base}/v2/{repository}/manifests/{ref}"
        accept = ", ".join(self.MANIFEST_MEDIA_TYPES)
        text = self._fetch_with_auth(url, token, accept)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise HttpError(f"invalid JSON manifest from {url}: {exc}") from exc

    def _fetch_blob(self, registry: str, repository: str, digest: str, token: str) -> Any:
        base = self._registry_base(registry)
        url = f"{base}/v2/{repository}/blobs/{digest}"
        text = self._fetch_with_auth(url, token, "application/vnd.docker.container.image.v1+json")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise HttpError(f"invalid JSON blob from {url}: {exc}") from exc

    def _extract_from_config(
        self,
        result: DiscoveryResult,
        target: TargetConfig,
        image_ref: str,
        registry: str,
        repository: str,
        ref: str,
        config: dict[str, Any],
    ) -> None:
        cfg = config.get("config", {}) or {}
        labels: dict[str, str] = cfg.get("Labels", {}) or {}
        env_vars: list[str] = cfg.get("Env", []) or []
        history: list[dict[str, Any]] = config.get("history", []) or []

        self._extract_base_image_label(result, target, image_ref, registry, repository, ref, labels)
        self._extract_env_versions(result, target, image_ref, registry, repository, ref, env_vars)
        self._extract_history_packages(result, target, image_ref, registry, repository, ref, history)

    def _extract_base_image_label(
        self,
        result: DiscoveryResult,
        target: TargetConfig,
        image_ref: str,
        registry: str,
        repository: str,
        ref: str,
        labels: dict[str, str],
    ) -> None:
        base = labels.get("org.opencontainers.image.base.name")
        if not base:
            return
        locator = f"{registry}/{repository}:{ref}"
        result.records.append(
            _record(
                target.name,
                base,
                "oci",
                None,
                DependencyStatus.INFERRED,
                0.7,
                "oci_config",
                self.name,
                locator,
                f"base image label: {base}",
                "runtime",
            )
        )
        result.inferences.append(
            _inference(
                target.name,
                self.name,
                base,
                "oci",
                None,
                "base image extracted from OCI label org.opencontainers.image.base.name",
                DependencyStatus.INFERRED.value,
                0.7,
            )
        )

    def _extract_env_versions(
        self,
        result: DiscoveryResult,
        target: TargetConfig,
        image_ref: str,
        registry: str,
        repository: str,
        ref: str,
        env_vars: list[str],
    ) -> None:
        locator = f"{registry}/{repository}:{ref}"
        for env_line in env_vars:
            m = self._ENV_VERSION_RE.match(env_line)
            if not m:
                continue
            env_name = m.group(1)
            env_value = m.group(2)
            eco = self._ecosystem_for_env(env_name)
            result.records.append(
                _record(
                    target.name,
                    env_name.lower(),
                    eco,
                    env_value,
                    DependencyStatus.INFERRED,
                    0.65,
                    "oci_config",
                    self.name,
                    locator,
                    f"version env var {env_name}={env_value}",
                    "runtime",
                )
            )
            result.inferences.append(
                _inference(
                    target.name,
                    self.name,
                    env_name.lower(),
                    eco,
                    env_value,
                    f"runtime version from OCI config env {env_name}",
                    DependencyStatus.INFERRED.value,
                    0.65,
                )
            )

    @staticmethod
    def _ecosystem_for_env(env_name: str) -> str:
        low = env_name.lower()
        if low.startswith("node"):
            return "npm"
        if low.startswith("python") or low.startswith("pypy"):
            return "PyPI"
        if low.startswith("ruby"):
            return "RubyGems"
        if low.startswith(("go", "golang")):
            return "Go"
        if low.startswith("nginx"):
            return "deb"
        if low.startswith("alpine") or low.startswith("apk"):
            return "apk"
        return "runtime"

    def _extract_history_packages(
        self,
        result: DiscoveryResult,
        target: TargetConfig,
        image_ref: str,
        registry: str,
        repository: str,
        ref: str,
        history: list[dict[str, Any]],
    ) -> None:
        locator = f"{registry}/{repository}:{ref}"
        for entry in history:
            created_by: str = entry.get("created_by", "") or ""
            if not created_by:
                continue
            for token in re.split(r"\s*&&\s*|\s*;\s*", created_by):
                token = token.strip()
                if not token:
                    continue
                self._match_install_command(result, target.name, token, locator)

    def _match_install_command(self, result: DiscoveryResult, target_name: str, token: str, locator: str) -> None:
        for pattern, ecosystem in self._PKG_PATTERNS:
            m = re.search(pattern, token)
            if not m:
                continue
            after = token[m.end() :]
            for pkg in after.split():
                pkg_clean = pkg.strip().rstrip(";\"'\\")
                if not pkg_clean or pkg_clean.startswith("-"):
                    continue
                if not re.match(r"^[a-zA-Z0-9]", pkg_clean):
                    continue
                if ecosystem == "npm" and pkg_clean.startswith("-"):
                    continue
                ev = pkg_clean[:240]
                result.records.append(
                    _record(
                        target_name,
                        pkg_clean,
                        ecosystem,
                        None,
                        DependencyStatus.INFERRED,
                        0.6,
                        "oci_config",
                        self.name,
                        locator,
                        f"package install from history: {ev}",
                        "runtime",
                    )
                )
                result.inferences.append(
                    _inference(
                        target_name,
                        self.name,
                        pkg_clean,
                        ecosystem,
                        None,
                        f"package installed via {ecosystem} in container build history",
                        DependencyStatus.INFERRED.value,
                        0.6,
                    )
                )
            break


class MobileArtifactPlugin(DiscoveryPlugin):
    name = "mobile_artifacts"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        if not target.mobile_artifacts:
            registry.add_assumption(target.name, self.name, "no APK/IPA artifacts were configured")
            registry.add_gap(target.name, self.name, "missing_input", "no APK/IPA artifacts were configured")
            return result
        if self.offline:
            registry.add_assumption(target.name, self.name, "offline mode skipped mobile artifact collection")
            registry.add_gap(target.name, self.name, "not_collected", "offline mode skipped mobile artifact collection")
            return result
        for artifact_url in target.mobile_artifacts:
            try:
                raw = self.http.fetch_bytes(artifact_url)
            except (HttpError, OSError):
                raw = None
            if raw is None:
                result.failures.append(f"could not download mobile artifact {artifact_url}")
                registry.add_gap(
                    target.name, self.name, "not_collected", f"mobile artifact could not be downloaded: {artifact_url}"
                )
                continue
            meta_desc = f"Binary archive metadata - size: {len(raw)} bytes"
            result.observations.append(
                _observation(target.name, self.name, "mobile_artifact", artifact_url, "GET", meta_desc)
            )
            if raw[:4] != b"PK\x03\x04":
                result.failures.append(f"mobile artifact is not a valid ZIP file: {artifact_url}")
                registry.add_gap(
                    target.name, self.name, "unparseable", f"mobile artifact is not a valid ZIP format: {artifact_url}"
                )
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    names = zf.namelist()
                    if _is_apk(names):
                        registry.add_plugin_event(target.name, self.name, f"detected APK: {artifact_url}")
                        _parse_apk(target, registry, result, zf, names, artifact_url)
                    elif _is_ipa(names):
                        registry.add_plugin_event(target.name, self.name, f"detected IPA: {artifact_url}")
                        _parse_ipa(target, registry, result, zf, names, artifact_url)
                    else:
                        result.assumptions.append(f"ZIP artifact does not match APK or IPA structure: {artifact_url}")
                        registry.add_gap(
                            target.name,
                            self.name,
                            "unparseable",
                            f"ZIP artifact does not match APK or IPA structure: {artifact_url}",
                        )
            except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                result.failures.append(f"could not parse ZIP artifact {artifact_url}: {exc}")
                registry.add_gap(target.name, self.name, "unparseable", f"ZIP parsing failed: {artifact_url}")
        registry.add_plugin_event(
            target.name, self.name, f"generated {len(result.records)} records from mobile artifacts"
        )
        return result


def _safe_zip_read(zf: zipfile.ZipFile, name: str, max_size: int = 10 * 1024 * 1024) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > max_size:
        raise ValueError(f"File {name} in zip is too large ({info.file_size} bytes)")
    return zf.read(name)


def _is_apk(names: list[str]) -> bool:
    return "AndroidManifest.xml" in names


def _is_ipa(names: list[str]) -> bool:
    return any(n.endswith(".app/Info.plist") for n in names)


def _extract_axml_strings(data: bytes, min_length: int = 4) -> list[str]:
    strings: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0x00:
            current.append(chr(data[i]))
            i += 2
        elif data[i] == 0x00 and current:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
            i += 1
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
            i += 1
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def _parse_apk(
    target: TargetConfig,
    registry: GlobalRegistry,
    result: DiscoveryResult,
    zf: zipfile.ZipFile,
    names: list[str],
    locator: str,
) -> None:
    try:
        manifest_data = _safe_zip_read(zf, "AndroidManifest.xml")
    except KeyError:
        registry.add_gap(target.name, "mobile_artifacts", "unparseable", "AndroidManifest.xml not found in APK")
        result.failures.append("AndroidManifest.xml not found in APK")
        return

    axml_strings = _extract_axml_strings(manifest_data)
    package_name: str | None = None
    version_name: str | None = None
    min_sdk: str | None = None

    for i, s in enumerate(axml_strings):
        if s == "package" and i + 1 < len(axml_strings) and package_name is None:
            candidate = axml_strings[i + 1]
            if re.match(r"^[a-zA-Z_][\w.]*$", candidate):
                package_name = candidate
        elif s == "versionName" and i + 1 < len(axml_strings) and version_name is None:
            version_name = axml_strings[i + 1]
        elif s == "minSdkVersion" and i + 1 < len(axml_strings) and min_sdk is None:
            min_sdk = axml_strings[i + 1]

    if package_name is None:
        for s in axml_strings:
            if re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", s):
                package_name = s
                break

    if package_name is not None:
        result.records.append(
            _record(
                target.name,
                package_name,
                "android",
                version_name,
                DependencyStatus.CONFIRMED,
                0.85,
                "mobile_artifact",
                "mobile_artifacts",
                locator,
                f"package={package_name}",
                "runtime",
            )
        )
        result.inferences.append(
            _inference(
                target.name,
                "mobile_artifacts",
                package_name,
                "android",
                version_name,
                "package name extracted from AndroidManifest.xml in APK",
                DependencyStatus.CONFIRMED.value,
                0.85,
            )
        )
        if version_name:
            result.assumptions.append(f"APK versionName={version_name} for package={package_name}")
        if min_sdk:
            result.assumptions.append(f"APK minSdkVersion={min_sdk} for package={package_name}")
    else:
        registry.add_gap(
            target.name, "mobile_artifacts", "unparseable", "could not extract package name from AndroidManifest.xml"
        )

    dex_jars = [n for n in names if (n.endswith(".dex") or n.endswith(".jar")) and not n.startswith("META-INF/")]
    for path in dex_jars:
        name = path.split("/")[-1].rsplit(".", 1)[0]
        if name in ("classes", "classes2", "classes3", ""):
            continue
        pr = Provenance(
            source_type="mobile_artifact",
            source_name="mobile_artifacts",
            locator=locator,
            evidence=f"bundled_artifact={path}",
            fetch_method="GET",
            snippet=path,
        )
        result.records.append(
            DependencyRecord(
                target_name=target.name,
                name=name,
                ecosystem="android",
                version=None,
                status=DependencyStatus.INFERRED,
                confidence=0.50,
                provenance=[pr],
                scope="runtime",
                relationship="embedded",
            )
        )
        result.inferences.append(
            _inference(
                target.name,
                "mobile_artifacts",
                name,
                "android",
                None,
                f"bundled DEX/JAR dependency: {path}",
                DependencyStatus.INFERRED.value,
                0.50,
            )
        )


def _parse_ipa(
    target: TargetConfig,
    registry: GlobalRegistry,
    result: DiscoveryResult,
    zf: zipfile.ZipFile,
    names: list[str],
    locator: str,
) -> None:
    plist_path = next((n for n in names if n.endswith(".app/Info.plist")), None)
    if plist_path is None:
        registry.add_gap(target.name, "mobile_artifacts", "unparseable", "Info.plist not found in IPA")
        result.failures.append("Info.plist not found in IPA")
        return

    try:
        plist_data = _safe_zip_read(zf, plist_path)
        plist = plistlib.loads(plist_data)
    except Exception as exc:
        registry.add_gap(target.name, "mobile_artifacts", "unparseable", f"Info.plist parsing failed: {exc}")
        result.failures.append(f"Info.plist parsing failed: {exc}")
        return

    bundle_id: str = plist.get("CFBundleIdentifier", "") or ""
    version: str = plist.get("CFBundleShortVersionString", "") or plist.get("CFBundleVersion", "") or ""
    min_os: str = plist.get("MinimumOSVersion", "") or ""

    if bundle_id:
        result.records.append(
            _record(
                target.name,
                bundle_id,
                "ios",
                version or None,
                DependencyStatus.CONFIRMED,
                0.85,
                "mobile_artifact",
                "mobile_artifacts",
                locator,
                f"CFBundleIdentifier={bundle_id}",
                "runtime",
            )
        )
        result.inferences.append(
            _inference(
                target.name,
                "mobile_artifacts",
                bundle_id,
                "ios",
                version or None,
                "bundle identifier extracted from Info.plist in IPA",
                DependencyStatus.CONFIRMED.value,
                0.85,
            )
        )
        if version:
            result.assumptions.append(f"IPA version={version} for bundle={bundle_id}")
        if min_os:
            result.assumptions.append(f"IPA minimumOSVersion={min_os} for bundle={bundle_id}")
    else:
        registry.add_gap(
            target.name, "mobile_artifacts", "collected_but_empty", "CFBundleIdentifier not found in Info.plist"
        )

    # Parse Package.resolved (Swift Package Manager)
    resolved_path = next((n for n in names if n.endswith("Package.resolved")), None)
    if resolved_path is not None:
        try:
            resolved = json.loads(_safe_zip_read(zf, resolved_path).decode("utf-8", errors="replace"))
            pins: list[dict[str, Any]] = resolved.get("pins", resolved.get("object", {}).get("pins", []))
            for pin in pins:
                dep_id: str = pin.get("identity", pin.get("package", ""))
                dep_version: str = pin.get("state", {}).get("version", "")
                if dep_id:
                    result.records.append(
                        _record(
                            target.name,
                            dep_id,
                            "swift",
                            dep_version or None,
                            DependencyStatus.CONFIRMED,
                            0.88,
                            "mobile_artifact",
                            "mobile_artifacts",
                            resolved_path,
                            f"SPM_dependency={dep_id}@{dep_version}",
                            "runtime",
                        )
                    )
                    result.inferences.append(
                        _inference(
                            target.name,
                            "mobile_artifacts",
                            dep_id,
                            "swift",
                            dep_version or None,
                            "dependency extracted from Package.resolved in IPA",
                            DependencyStatus.CONFIRMED.value,
                            0.88,
                        )
                    )
        except (json.JSONDecodeError, KeyError, AttributeError) as exc:
            registry.add_gap(target.name, "mobile_artifacts", "unparseable", f"Package.resolved parsing failed: {exc}")

    # Parse Podfile.lock (CocoaPods)
    if "Podfile.lock" in names:
        try:
            pod_text = _safe_zip_read(zf, "Podfile.lock").decode("utf-8", errors="replace")
            for match in re.finditer(r"^\s*-\s+(\S+)\s+\(([^)]+)\)", pod_text, re.MULTILINE):
                pod_name: str = match.group(1).split("/", 1)[0]
                pod_version: str = match.group(2)
                result.records.append(
                    _record(
                        target.name,
                        pod_name,
                        "cocoapods",
                        pod_version,
                        DependencyStatus.CONFIRMED,
                        0.88,
                        "mobile_artifact",
                        "mobile_artifacts",
                        "Podfile.lock",
                        f"CocoaPods_dependency={pod_name}@{pod_version}",
                        "runtime",
                    )
                )
                result.inferences.append(
                    _inference(
                        target.name,
                        "mobile_artifacts",
                        pod_name,
                        "cocoapods",
                        pod_version,
                        "dependency extracted from Podfile.lock in IPA",
                        DependencyStatus.CONFIRMED.value,
                        0.88,
                    )
                )
        except Exception as exc:
            registry.add_gap(target.name, "mobile_artifacts", "unparseable", f"Podfile.lock parsing failed: {exc}")

    # Identify .framework directories as dependency hints
    frameworks: set[str] = set()
    for n in names:
        parts = n.split("/")
        for part in parts:
            if part.endswith(".framework") and not part.startswith("."):
                frameworks.add(part.split(".framework")[0])
    for fw in sorted(frameworks):
        pr = Provenance(
            source_type="mobile_artifact",
            source_name="mobile_artifacts",
            locator=locator,
            evidence=f"framework_bundle={fw}.framework",
            fetch_method="GET",
            snippet=fw,
        )
        result.records.append(
            DependencyRecord(
                target_name=target.name,
                name=fw,
                ecosystem="ios",
                version=None,
                status=DependencyStatus.INFERRED,
                confidence=0.45,
                provenance=[pr],
                scope="runtime",
                relationship="embedded",
            )
        )
        result.inferences.append(
            _inference(
                target.name,
                "mobile_artifacts",
                fw,
                "ios",
                None,
                f"embedded framework: {fw}.framework",
                DependencyStatus.INFERRED.value,
                0.45,
            )
        )


class PublicPackageMetadataPlugin(DiscoveryPlugin):
    name = "public_package_metadata"

    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        result = DiscoveryResult()
        registry.add_assumption(
            target.name,
            self.name,
            "transitive dependency expansion is driven by confirmed manifests/SBOMs or fixtures; package registry crawling is not performed automatically",
        )
        registry.add_gap(target.name, self.name, "unverified", "public package metadata was not crawled automatically")
        return result


def default_plugins(offline: bool = False, http: HttpClient | None = None) -> list[DiscoveryPlugin]:
    return [
        GitHubRepositoryPlugin(offline=offline, http=http),
        JavaScriptBundlePlugin(offline=offline, http=http),
        SBOMPlugin(offline=offline, http=http),
        PackageHintsPlugin(offline=offline, http=http),
        ContainerImagePlugin(offline=offline, http=http),
        WaybackMachinePlugin(offline=offline, http=http),
        MobileArtifactPlugin(offline=offline, http=http),
        PublicPackageMetadataPlugin(offline=offline, http=http),
    ]


def _script_urls(base_url: str, html: str) -> list[str]:
    urls = []
    for match in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        urls.append(join_url(base_url, match.group(1)))
    return urls


def _add_candidates(result: DiscoveryResult, candidates: list[DependencyCandidate]) -> None:
    for candidate in candidates:
        record = candidate.to_record()
        result.records.append(record)
        result.inferences.append(
            candidate.to_inference(candidate.evidence_chain[0].plugin_name if candidate.evidence_chain else "unknown")
        )


def _add_candidate_conflicts(result: DiscoveryResult) -> None:
    by_package: dict[tuple[str, str], list[DependencyRecord]] = {}
    for record in result.records:
        by_package.setdefault((record.ecosystem.lower(), record.name.lower()), []).append(record)
    for (ecosystem, package), records in by_package.items():
        versions = sorted({record.version or "unknown" for record in records})
        if len(versions) <= 1:
            continue
        winner = max(records, key=lambda item: (item.status == DependencyStatus.CONFIRMED, item.confidence))
        result.conflicts.append(
            {
                "conflict_type": "js_html_dependency_version_claim",
                "package": package,
                "ecosystem": ecosystem,
                "winner": winner.key,
                "why_winner": "highest confidence candidate; exact/confirmed evidence preferred, but all claims are retained",
                "conflicting_claims": [
                    {
                        "dependency_key": record.key,
                        "version": record.version,
                        "status": record.status.value,
                        "confidence": record.confidence,
                        "evidence_chain": record.qualifiers.get("evidence_chain", []),
                    }
                    for record in records
                ],
                "confidence_penalty": 0.08,
            }
        )


def _owner_repo(repo: str) -> str | None:
    if repo.startswith("http"):
        parts = urllib.parse.urlparse(repo).path.strip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None
    if "/" in repo:
        return repo.strip("/")
    return None


def _manifest_records(target_name: str, text: str, path: str, locator: str, source_name: str) -> list[DependencyRecord]:
    parser_map = {
        "package.json": parse_package_json,
        "requirements.txt": parse_requirements,
        "pom.xml": parse_pom_xml,
        "go.mod": parse_go_mod,
        "Gemfile.lock": parse_gemfile_lock,
    }
    parser = parser_map[path]
    records = []
    for name, ecosystem, version, scope in parser(text):
        records.append(
            _record(
                target_name,
                name,
                ecosystem,
                version,
                DependencyStatus.CONFIRMED,
                0.88,
                "github_manifest",
                source_name,
                locator,
                f"dependency parsed from {path}",
                scope,
            )
        )
    return records


def _record(
    target_name: str,
    name: str,
    ecosystem: str,
    version: str | None,
    status: DependencyStatus,
    confidence: float,
    source_type: str,
    source_name: str,
    locator: str,
    evidence: str,
    scope: str,
) -> DependencyRecord:
    return DependencyRecord(
        target_name=target_name,
        name=name,
        ecosystem=normalize_ecosystem(ecosystem),
        version=version,
        status=status,
        confidence=confidence,
        provenance=[
            Provenance(
                source_type=source_type,
                source_name=source_name,
                locator=locator,
                evidence=evidence,
                snippet=evidence[:240],
            )
        ],
        scope=scope,
    )


def _observation(
    target_name: str, plugin: str, source_type: str, locator: str, method: str, content: str
) -> dict[str, str]:
    return {
        "target": target_name,
        "plugin": plugin,
        "source_type": source_type,
        "locator": locator,
        "fetch_method": method,
        "content_sha256": _sha256(content),
        "snippet": _snippet(content),
    }


def _inference(
    target_name: str,
    plugin: str,
    package_name: str,
    ecosystem: str,
    version: str | None,
    reasoning: str,
    status: str,
    confidence: float,
) -> dict[str, str | float | None]:
    return {
        "target": target_name,
        "plugin": plugin,
        "package_name": package_name,
        "ecosystem": ecosystem,
        "version": version,
        "status": status,
        "confidence": confidence,
        "reasoning": reasoning,
    }


def _sha256(content: str) -> str:
    return sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _snippet(content: str, needle: str | None = None) -> str:
    text = re.sub(r"\s+", " ", content)
    if needle and needle in text:
        index = max(0, text.find(needle) - 80)
        return text[index : index + 240]
    return text[:240]
