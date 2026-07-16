from __future__ import annotations

import unittest

from osintdepintel.discovery.plugins import GitHubRepositoryPlugin
from osintdepintel.http import HttpError
from osintdepintel.models import DependencyStatus, TargetConfig, TargetMode
from osintdepintel.registry import GlobalRegistry


class FakeHttp:
    def __init__(self, responses: dict[str, str]) -> None:
        self.responses = responses

    def fetch(self, url: str) -> str:
        if url in self.responses:
            return self.responses[url]
        raise HttpError(f"not found: {url}")


class GitHubRepositoryPluginTests(unittest.TestCase):
    def test_no_repos_returns_empty_and_adds_assumption_and_gap(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=[])
        registry = GlobalRegistry()
        plugin = GitHubRepositoryPlugin(offline=False)
        result = plugin.discover(target, registry)

        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("no github repository" in str(a).lower() for a in reg_dict.get("assumptions", [])))
        self.assertTrue(any("no github repository" in str(g).lower() for g in reg_dict.get("collection_gaps", [])))

    def test_offline_skips_and_adds_assumption_and_gap(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        registry = GlobalRegistry()
        plugin = GitHubRepositoryPlugin(offline=True)
        result = plugin.discover(target, registry)

        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("offline" in str(a).lower() for a in reg_dict.get("assumptions", [])))
        self.assertTrue(any("offline" in str(g).lower() for g in reg_dict.get("collection_gaps", [])))

    def test_invalid_repo_url_adds_failure(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["not-valid"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp({}), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 0)
        self.assertTrue(any("unsupported" in f.lower() for f in result.failures))

    def test_fetches_package_json_from_github_main(self) -> None:
        main_url = "https://raw.githubusercontent.com/org/repo/main/package.json"
        responses = {
            main_url: '{"name": "test-pkg", "dependencies": {"react": "^18.2.0", "lodash": "^4.17.21"}}',
        }
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 2)
        records_by_name = {r.name: r for r in result.records}
        self.assertIn("react", records_by_name)
        self.assertIn("lodash", records_by_name)
        self.assertEqual(records_by_name["react"].version, "18.2.0")
        self.assertEqual(records_by_name["react"].status, DependencyStatus.CONFIRMED)
        self.assertAlmostEqual(records_by_name["react"].confidence, 0.88)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(len(result.inferences), 2)

    def test_falls_back_to_master_when_main_missing(self) -> None:
        master_url = "https://raw.githubusercontent.com/org/repo/master/package.json"
        responses = {
            master_url: '{"name": "test-pkg", "dependencies": {"react": "^18.2.0"}}',
        }
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "react")

    def test_skips_http_error_gracefully(self) -> None:
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        registry = GlobalRegistry()
        plugin = GitHubRepositoryPlugin(http=FakeHttp({}), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, registry)

        self.assertEqual(len(result.records), 0)
        reg_dict = registry.to_dict()
        self.assertTrue(any("collected_but_empty" in str(g).lower() for g in reg_dict.get("collection_gaps", [])))

    def test_parses_requirements_txt(self) -> None:
        main_url = "https://raw.githubusercontent.com/org/repo/main/requirements.txt"
        responses = {
            main_url: "requests==2.28.0\nflask==2.2.0\n",
        }
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 2)
        records_by_name = {r.name: r for r in result.records}
        self.assertIn("requests", records_by_name)
        self.assertIn("flask", records_by_name)

    def test_both_manifests_on_main_are_processed_before_master_skipped(self) -> None:
        main_pkg = "https://raw.githubusercontent.com/org/repo/main/package.json"
        main_req = "https://raw.githubusercontent.com/org/repo/main/requirements.txt"
        master_pkg = "https://raw.githubusercontent.com/org/repo/master/package.json"
        responses = {
            main_pkg: '{"name": "test-pkg", "dependencies": {"react": "^18.2.0"}}',
            main_req: "requests==2.28.0\n",
            master_pkg: '{"dependencies": {"should-not-reach": "1.0.0"}}',
        }
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 2)
        names = {r.name for r in result.records}
        self.assertIn("react", names)
        self.assertIn("requests", names)

    def test_multiple_repos_both_processed(self) -> None:
        repo1_pkg = "https://raw.githubusercontent.com/org/repo1/main/package.json"
        repo2_req = "https://raw.githubusercontent.com/org/repo2/main/requirements.txt"
        responses = {
            repo1_pkg: '{"dependencies": {"react": "^18.2.0"}}',
            repo2_req: "flask==2.2.0\n",
        }
        target = TargetConfig(
            "test",
            "https://example.test",
            TargetMode.PUBLIC,
            github_repos=["org/repo1", "org/repo2"],
        )
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 2)
        names = {r.name for r in result.records}
        self.assertIn("react", names)
        self.assertIn("flask", names)

    def test_https_github_url_repo_format(self) -> None:
        main_url = "https://raw.githubusercontent.com/org/repo/main/package.json"
        responses = {
            main_url: '{"dependencies": {"react": "^18.2.0"}}',
        }
        target = TargetConfig(
            "test",
            "https://example.test",
            TargetMode.PUBLIC,
            github_repos=["https://github.com/org/repo"],
        )
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].name, "react")

    def test_adds_plugin_event_with_record_count(self) -> None:
        main_url = "https://raw.githubusercontent.com/org/repo/main/package.json"
        responses = {
            main_url: '{"dependencies": {"react": "^18.2.0"}}',
        }
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        registry = GlobalRegistry()
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        plugin.discover(target, registry)

        reg_dict = registry.to_dict()
        events = reg_dict.get("plugin_events", [])
        self.assertTrue(any("loaded 1" in e.get("message", "") for e in events))

    def test_observation_contains_sha256_and_snippet(self) -> None:
        main_url = "https://raw.githubusercontent.com/org/repo/main/package.json"
        content = '{"dependencies": {"react": "^18.2.0"}}'
        responses = {main_url: content}
        target = TargetConfig("test", "https://example.test", TargetMode.PUBLIC, github_repos=["org/repo"])
        plugin = GitHubRepositoryPlugin(http=FakeHttp(responses), offline=False)  # type: ignore[arg-type]
        result = plugin.discover(target, GlobalRegistry())

        self.assertEqual(len(result.observations), 1)
        obs = result.observations[0]
        self.assertEqual(obs["source_type"], "github_manifest")
        self.assertEqual(obs["locator"], main_url)
        self.assertIn("content_sha256", obs)
        self.assertIn("snippet", obs)


if __name__ == "__main__":
    unittest.main()
