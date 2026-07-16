from __future__ import annotations

import json
import unittest
from typing import Any

from osintdepintel.discovery.plugins import ContainerImagePlugin
from osintdepintel.http import HttpError
from osintdepintel.models import DependencyStatus, DiscoveryResult, TargetConfig, TargetMode
from osintdepintel.registry import GlobalRegistry


class FakeHttp:
    def __init__(self, **kwargs: Any) -> None:
        self.responses: dict[str, str] = kwargs.get("responses", {})
        self.json_responses: dict[str, Any] = kwargs.get("json_responses", {})

    def fetch(self, url: str, headers: dict[str, str] | None = None) -> str:
        if url in self.responses:
            return self.responses[url]
        raise HttpError(f"not found: {url}")

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        if url in self.json_responses:
            return self.json_responses[url]
        raise HttpError(f"not found: {url}")


class ParseOciManifestTests(unittest.TestCase):
    def test_single_oci_manifest_returns_config_digest(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:abc123"},
            "layers": [{"digest": "sha256:def456"}],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertEqual(config_digest, "sha256:abc123")
        self.assertIsNone(child_digest)

    def test_single_docker_v2_manifest_returns_config_digest(self) -> None:
        manifest = {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": "sha256:def456"},
            "layers": [{"digest": "sha256:ghi789"}],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertEqual(config_digest, "sha256:def456")
        self.assertIsNone(child_digest)

    def test_oci_index_returns_child_digest(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"digest": "sha256:child123", "platform": {"os": "linux", "architecture": "amd64"}}],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertIsNone(config_digest)
        self.assertEqual(child_digest, "sha256:child123")

    def test_docker_manifest_list_returns_child_digest(self) -> None:
        manifest = {
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [{"digest": "sha256:child456"}],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertIsNone(config_digest)
        self.assertEqual(child_digest, "sha256:child456")

    def test_empty_index_returns_none(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertIsNone(config_digest)
        self.assertIsNone(child_digest)

    def test_manifest_without_config_returns_none(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [{"digest": "sha256:layer1"}],
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertIsNone(config_digest)
        self.assertIsNone(child_digest)

    def test_unknown_media_type_treated_as_single_manifest(self) -> None:
        manifest = {
            "mediaType": "application/vnd.custom",
            "config": {"digest": "sha256:xyz"},
        }
        config_digest, child_digest = ContainerImagePlugin._parse_oci_manifest(manifest)
        self.assertEqual(config_digest, "sha256:xyz")
        self.assertIsNone(child_digest)


class ParseImageRefTests(unittest.TestCase):
    def test_simple_name_defaults_to_docker_hub_library_latest(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("nginx")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "library/nginx")
        self.assertEqual(tag, "latest")

    def test_name_with_tag(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("nginx:1.25")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "library/nginx")
        self.assertEqual(tag, "1.25")

    def test_namespace_defaults_to_docker_hub(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("bitnami/nginx")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "bitnami/nginx")
        self.assertEqual(tag, "latest")

    def test_namespace_with_tag(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("bitnami/nginx:1.25")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "bitnami/nginx")
        self.assertEqual(tag, "1.25")

    def test_ghcr_io(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("ghcr.io/org/my-app:v2.0")
        self.assertEqual(reg, "ghcr.io")
        self.assertEqual(repo, "org/my-app")
        self.assertEqual(tag, "v2.0")

    def test_explicit_docker_io(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("docker.io/library/alpine:3.18")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "library/alpine")
        self.assertEqual(tag, "3.18")

    def test_with_digest(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("my-image@sha256:abcdef1234567890")
        self.assertEqual(reg, "docker.io")
        self.assertEqual(repo, "library/my-image")
        self.assertEqual(tag, "sha256:abcdef1234567890")

    def test_custom_registry_with_port(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("registry.example.com:5000/my/repo:v1")
        self.assertEqual(reg, "registry.example.com:5000")
        self.assertEqual(repo, "my/repo")
        self.assertEqual(tag, "v1")

    def test_custom_registry_no_port(self) -> None:
        reg, repo, tag = ContainerImagePlugin._parse_image_ref("registry.example.com/my/repo:v1")
        self.assertEqual(reg, "registry.example.com")
        self.assertEqual(repo, "my/repo")
        self.assertEqual(tag, "v1")


class EcosystemForEnvTests(unittest.TestCase):
    def test_node_returns_npm(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("NODE_VERSION"), "npm")

    def test_python_returns_pypi(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("PYTHON_VERSION"), "PyPI")

    def test_pypy_returns_pypi(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("PYPY_VERSION"), "PyPI")

    def test_ruby_returns_rubygems(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("RUBY_VERSION"), "RubyGems")

    def test_go_returns_go(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("GO_VERSION"), "Go")

    def test_golang_returns_go(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("GOLANG_VERSION"), "Go")

    def test_nginx_returns_deb(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("NGINX_VERSION"), "deb")

    def test_alpine_returns_apk(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("ALPINE_VERSION"), "apk")

    def test_apk_returns_apk(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("APK_VERSION"), "apk")

    def test_unknown_returns_runtime(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env("FOO_VERSION"), "runtime")

    def test_empty_returns_runtime(self) -> None:
        self.assertEqual(ContainerImagePlugin._ecosystem_for_env(""), "runtime")


class RegistryBaseTests(unittest.TestCase):
    def test_docker_io(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        self.assertEqual(plugin._registry_base("docker.io"), "https://registry-1.docker.io")

    def test_ghcr_io(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        self.assertEqual(plugin._registry_base("ghcr.io"), "https://ghcr.io")

    def test_custom_registry(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        self.assertEqual(plugin._registry_base("my-registry.example.com"), "https://my-registry.example.com")


class ExchangeTokenTests(unittest.TestCase):
    def test_docker_hub_token_url(self) -> None:
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnginx%3Apull": {
                    "token": "dummy-token"
                }
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        token = plugin._exchange_token("docker.io", "library/nginx")
        self.assertEqual(token, "dummy-token")

    def test_ghcr_token_url(self) -> None:
        http = FakeHttp(
            json_responses={"https://ghcr.io/token?scope=repository%3Aorg%2Frepo%3Apull": {"token": "ghcr-token"}}
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        token = plugin._exchange_token("ghcr.io", "org/repo")
        self.assertEqual(token, "ghcr-token")

    def test_access_token_fallback(self) -> None:
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fbusybox%3Apull": {
                    "access_token": "alt-token"
                }
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        token = plugin._exchange_token("docker.io", "library/busybox")
        self.assertEqual(token, "alt-token")

    def test_no_token_raises_http_error(self) -> None:
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Ffoo%3Apull": {}
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        with self.assertRaises(HttpError):
            plugin._exchange_token("docker.io", "library/foo")


class FetchManifestTests(unittest.TestCase):
    def test_fetch_single_manifest(self) -> None:
        manifest_data = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:abc"},
            "layers": [],
        }
        http = FakeHttp(
            responses={
                "https://registry-1.docker.io/v2/library/nginx/manifests/latest": json.dumps(manifest_data),
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin._fetch_manifest("docker.io", "library/nginx", "latest", "test-token")
        self.assertEqual(result, manifest_data)

    def test_fetch_with_digest_flag(self) -> None:
        http = FakeHttp(
            responses={
                "https://registry-1.docker.io/v2/library/nginx/manifests/sha256:abc": json.dumps(
                    {"config": {"digest": "sha256:def"}}
                ),
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin._fetch_manifest("docker.io", "library/nginx", "sha256:abc", "test-token", digest=True)
        self.assertEqual(result, {"config": {"digest": "sha256:def"}})

    def test_invalid_json_raises_http_error(self) -> None:
        http = FakeHttp(
            responses={
                "https://registry-1.docker.io/v2/library/nginx/manifests/latest": "not-json",
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        with self.assertRaises(HttpError):
            plugin._fetch_manifest("docker.io", "library/nginx", "latest", "test-token")

    def test_ghcr_fetch(self) -> None:
        manifest_data = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": "sha256:xyz"}}
        http = FakeHttp(
            responses={
                "https://ghcr.io/v2/org/app/manifests/v1": json.dumps(manifest_data),
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin._fetch_manifest("ghcr.io", "org/app", "v1", "ghcr-token")
        self.assertEqual(result, manifest_data)


class FetchBlobTests(unittest.TestCase):
    def test_fetch_config_blob(self) -> None:
        config = {"config": {"Env": ["NODE_VERSION=18.0.0"]}}
        http = FakeHttp(
            responses={
                "https://registry-1.docker.io/v2/library/nginx/blobs/sha256:cfg": json.dumps(config),
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin._fetch_blob("docker.io", "library/nginx", "sha256:cfg", "test-token")
        self.assertEqual(result, config)

    def test_invalid_blob_json_raises_http_error(self) -> None:
        http = FakeHttp(
            responses={
                "https://registry-1.docker.io/v2/library/nginx/blobs/sha256:bad": "corrupt",
            }
        )
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        with self.assertRaises(HttpError):
            plugin._fetch_blob("docker.io", "library/nginx", "sha256:bad", "test-token")


class ExtractBaseImageLabelTests(unittest.TestCase):
    def test_with_label_adds_record(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_base_image_label(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            {"org.opencontainers.image.base.name": "alpine:3.18"},
        )
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "alpine:3.18")
        self.assertEqual(result.records[0].ecosystem, "Docker")
        self.assertEqual(result.records[0].status, DependencyStatus.INFERRED)
        self.assertAlmostEqual(result.records[0].confidence, 0.7)

    def test_without_label_adds_nothing(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_base_image_label(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            {},
        )
        self.assertEqual(len(result.records), 0)

    def test_missing_base_label_ignores_other_labels(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_base_image_label(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            {"org.label-schema.build-date": "2024-01-01"},
        )
        self.assertEqual(len(result.records), 0)


class ExtractEnvVersionsTests(unittest.TestCase):
    def test_matching_env_vars_add_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_env_versions(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            ["NODE_VERSION=18.17.0", "PYTHON_VERSION=3.11.4"],
        )
        self.assertEqual(len(result.records), 2)
        records_by_name = {r.name: r for r in result.records}
        self.assertIn("node_version", records_by_name)
        self.assertIn("python_version", records_by_name)
        self.assertEqual(records_by_name["node_version"].version, "18.17.0")
        self.assertEqual(records_by_name["node_version"].ecosystem, "npm")
        self.assertEqual(records_by_name["python_version"].ecosystem, "PyPI")
        self.assertEqual(records_by_name["node_version"].status, DependencyStatus.INFERRED)
        self.assertAlmostEqual(records_by_name["node_version"].confidence, 0.65)

    def test_non_matching_env_vars_ignored(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_env_versions(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            ["PATH=/usr/bin", "HOME=/root"],
        )
        self.assertEqual(len(result.records), 0)

    def test_mixed_env_vars(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_env_versions(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            ["NODE_VERSION=20.0.0", "PATH=/usr/bin", "RUBY_VERSION=3.2.0"],
        )
        self.assertEqual(len(result.records), 2)
        names = {r.name for r in result.records}
        self.assertIn("node_version", names)
        self.assertIn("ruby_version", names)


class MatchInstallCommandTests(unittest.TestCase):
    def test_apt_get_install_adds_deb_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(
            result, "test", "/bin/sh -c apt-get install -y curl wget", "docker.io/test/image:latest"
        )
        names = {r.name for r in result.records}
        self.assertIn("curl", names)
        self.assertIn("wget", names)
        for r in result.records:
            self.assertEqual(r.ecosystem, "deb")
            self.assertEqual(r.status, DependencyStatus.INFERRED)
            self.assertAlmostEqual(r.confidence, 0.6)

    def test_apk_add_adds_apk_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(
            result, "test", "apk add --no-cache python3 py3-pip", "docker.io/test/image:latest"
        )
        names = {r.name for r in result.records}
        self.assertIn("python3", names)
        self.assertIn("py3-pip", names)
        for r in result.records:
            self.assertEqual(r.ecosystem, "apk")

    def test_npm_install_adds_npm_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "npm install express lodash", "docker.io/test/image:latest")
        names = {r.name for r in result.records}
        self.assertIn("express", names)
        self.assertIn("lodash", names)
        for r in result.records:
            self.assertEqual(r.ecosystem, "npm")

    def test_pip_install_adds_pip_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "pip install requests flask", "docker.io/test/image:latest")
        names = {r.name for r in result.records}
        self.assertIn("requests", names)
        self.assertIn("flask", names)
        for r in result.records:
            self.assertEqual(r.ecosystem, "pip")

    def test_pip3_install_adds_pip_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "pip3 install django", "docker.io/test/image:latest")
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "django")
        self.assertEqual(result.records[0].ecosystem, "pip")

    def test_gem_install_adds_gem_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "gem install rails bundler", "docker.io/test/image:latest")
        names = {r.name for r in result.records}
        self.assertIn("rails", names)
        self.assertIn("bundler", names)
        for r in result.records:
            self.assertEqual(r.ecosystem, "gem")

    def test_flags_are_skipped(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "apt-get install -y --no-install-recommends curl", "test-locator")
        names = {r.name for r in result.records}
        self.assertIn("curl", names)
        self.assertNotIn("-y", names)
        self.assertNotIn("--no-install-recommends", names)

    def test_non_matching_command_adds_no_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._match_install_command(result, "test", "echo hello world", "test-locator")
        self.assertEqual(len(result.records), 0)


class ExtractHistoryPackagesTests(unittest.TestCase):
    def test_multi_command_with_and_and_semicolon(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_history_packages(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            [
                {"created_by": "/bin/sh -c apt-get install -y curl && apt-get install -y wget"},
                {"created_by": "/bin/sh -c npm install express; pip install flask"},
            ],
        )
        names = {r.name for r in result.records}
        self.assertIn("curl", names)
        self.assertIn("wget", names)
        self.assertIn("express", names)
        self.assertIn("flask", names)

    def test_empty_history_adds_no_records(self) -> None:
        plugin = ContainerImagePlugin(offline=True)
        result = DiscoveryResult()
        plugin._extract_history_packages(
            result,
            TargetConfig("test", "https://example.test", TargetMode.LAB),
            "my-image:latest",
            "docker.io",
            "test/image",
            "latest",
            [],
        )
        self.assertEqual(len(result.records), 0)


class DiscoverIntegrationTests(unittest.TestCase):
    def test_no_images_returns_empty(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.LAB)
        registry = GlobalRegistry()
        result = ContainerImagePlugin(offline=False).discover(target, registry)
        self.assertEqual(len(result.records), 0)

    def test_offline_mode_returns_empty_with_assumptions(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["nginx:latest"])
        registry = GlobalRegistry()
        result = ContainerImagePlugin(offline=True).discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(len(result.assumptions) > 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("offline" in str(a).lower() for a in reg_dict.get("assumptions", [])))

    def test_token_failure_adds_failure_and_gap(self) -> None:
        http = FakeHttp()
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["nginx:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("token exchange failed" in f.lower() for f in result.failures))

    def test_manifest_fetch_failure_adds_failure_and_gap(self) -> None:
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnginx%3Apull": {
                    "token": "test-token"
                }
            }
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["nginx:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("manifest fetch failed" in f.lower() for f in result.failures))

    def test_full_oci_manifest_flow(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg123"},
            "layers": [{"digest": "sha256:layer1"}],
        }
        config = {
            "config": {
                "Env": ["NODE_VERSION=18.17.0"],
                "Labels": {},
            },
            "history": [
                {"created_by": "/bin/sh -c apt-get install -y curl"},
            ],
        }
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fnginx%3Apull": {
                    "token": "test-token"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/nginx/manifests/latest": json.dumps(manifest),
                "https://registry-1.docker.io/v2/library/nginx/blobs/sha256:cfg123": json.dumps(config),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["nginx:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertGreater(len(result.records), 0)
        names = {r.name for r in result.records}
        self.assertIn("node_version", names)
        self.assertIn("curl", names)
        self.assertEqual(len(result.observations), 2)

    def test_docker_manifest_list_resolves_child(self) -> None:
        index = {
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [{"digest": "sha256:child1", "platform": {"os": "linux", "architecture": "amd64"}}],
        }
        child = {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": "sha256:cfg456"},
            "layers": [],
        }
        config = {"config": {"Env": ["RUBY_VERSION=3.2.0"]}, "history": []}
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fruby%3Apull": {
                    "token": "test-token"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/ruby/manifests/latest": json.dumps(index),
                "https://registry-1.docker.io/v2/library/ruby/manifests/sha256:child1": json.dumps(child),
                "https://registry-1.docker.io/v2/library/ruby/blobs/sha256:cfg456": json.dumps(config),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["ruby:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertGreater(len(result.records), 0)
        names = {r.name for r in result.records}
        self.assertIn("ruby_version", names)
        # Should have 3 observations: manifest + child_manifest + config
        self.assertEqual(len(result.observations), 3)
        obs_types = [o["source_type"] for o in result.observations]
        self.assertIn("oci_manifest", obs_types)
        self.assertIn("oci_child_manifest", obs_types)
        self.assertIn("oci_config", obs_types)

    def test_child_manifest_fetch_failure(self) -> None:
        index = {
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests": [{"digest": "sha256:missing-child"}],
        }
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Ftest%3Apull": {
                    "token": "test-token"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/test/manifests/latest": json.dumps(index),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["test:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("child manifest fetch failed" in f.lower() for f in result.failures))

    def test_config_blob_fetch_failure(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:missing-cfg"},
            "layers": [],
        }
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Ftest%3Apull": {
                    "token": "test-token"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/test/manifests/latest": json.dumps(manifest),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["test:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("config blob fetch failed" in f.lower() for f in result.failures))

    def test_adds_plugin_event(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg"},
            "layers": [],
        }
        config = {"config": {"Env": ["NODE_VERSION=20.0.0"]}, "history": []}
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Ftest%3Apull": {
                    "token": "t"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/test/manifests/latest": json.dumps(manifest),
                "https://registry-1.docker.io/v2/library/test/blobs/sha256:cfg": json.dumps(config),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["test:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        plugin.discover(target, registry)
        reg_dict = registry.to_dict()
        events = reg_dict.get("plugin_events", [])
        self.assertTrue(any("loaded 1" in e.get("message", "") for e in events))

    def test_ghcr_full_flow(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg"},
            "layers": [],
        }
        config = {"config": {"Env": ["GO_VERSION=1.21.0"]}, "history": []}
        http = FakeHttp(
            json_responses={"https://ghcr.io/token?scope=repository%3Aorg%2Fapp%3Apull": {"token": "ghcr-token"}},
            responses={
                "https://ghcr.io/v2/org/app/manifests/v1.0": json.dumps(manifest),
                "https://ghcr.io/v2/org/app/blobs/sha256:cfg": json.dumps(config),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["ghcr.io/org/app:v1.0"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertGreater(len(result.records), 0)
        self.assertEqual(result.records[0].name, "go_version")
        self.assertEqual(result.records[0].ecosystem, "Go")

    def test_missing_config_digest_adds_gap(self) -> None:
        manifest = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [],
        }
        http = FakeHttp(
            json_responses={
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Ftest%3Apull": {
                    "token": "t"
                }
            },
            responses={
                "https://registry-1.docker.io/v2/library/test/manifests/latest": json.dumps(manifest),
            },
        )
        target = TargetConfig("test", "https://example.test", TargetMode.LAB, container_images=["test:latest"])
        registry = GlobalRegistry()
        plugin = ContainerImagePlugin(http=http, offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)
        self.assertEqual(len(result.records), 0)
        self.assertFalse(any("config blob fetch failed" in f.lower() for f in result.failures))


if __name__ == "__main__":
    unittest.main()
