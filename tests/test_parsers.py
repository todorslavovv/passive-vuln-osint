from __future__ import annotations

import json
import unittest
from pathlib import Path

from osintdepintel.parsers import (
    _ecosystem_from_purl,
    _looks_like_package,
    extract_js_dependency_hints,
    normalize_ecosystem,
    parse_cyclonedx_sbom,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements,
    parse_spdx_sbom,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


class NormalizeEcosystemTests(unittest.TestCase):
    def test_npm(self) -> None:
        self.assertEqual(normalize_ecosystem("npm"), "npm")

    def test_pypi(self) -> None:
        self.assertEqual(normalize_ecosystem("pypi"), "PyPI")

    def test_maven(self) -> None:
        self.assertEqual(normalize_ecosystem("maven"), "Maven")

    def test_rubygems(self) -> None:
        self.assertEqual(normalize_ecosystem("rubygems"), "RubyGems")

    def test_go(self) -> None:
        self.assertEqual(normalize_ecosystem("go"), "Go")

    def test_gomod_alias(self) -> None:
        self.assertEqual(normalize_ecosystem("gomod"), "Go")

    def test_docker(self) -> None:
        self.assertEqual(normalize_ecosystem("docker"), "Docker")

    def test_oci(self) -> None:
        self.assertEqual(normalize_ecosystem("oci"), "Docker")

    def test_case_insensitive(self) -> None:
        self.assertEqual(normalize_ecosystem("NPM"), "npm")

    def test_unknown_returns_as_is(self) -> None:
        self.assertEqual(normalize_ecosystem("nuget"), "nuget")


class ParsePackageJsonTests(unittest.TestCase):
    def test_dependencies(self) -> None:
        deps = parse_package_json('{"dependencies": {"express": "^4.17.1"}, "devDependencies": {"jest": "29.0.0"}}')
        self.assertIn(("express", "npm", "4.17.1", "runtime"), deps)
        self.assertIn(("jest", "npm", "29.0.0", "development"), deps)

    def test_minimal_no_deps(self) -> None:
        deps = parse_package_json('{"name": "test-pkg"}')
        self.assertEqual(deps, [])

    def test_malformed_json_raises(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            parse_package_json("{invalid")

    def test_peer_and_optional_deps(self) -> None:
        deps = parse_package_json(
            '{"peerDependencies": {"react": "18.0.0"}, "optionalDependencies": {"lodash": "4.17.15"}}'
        )
        self.assertIn(("react", "npm", "18.0.0", "runtime"), deps)
        self.assertIn(("lodash", "npm", "4.17.15", "runtime"), deps)

    def test_empty_deps_object(self) -> None:
        deps = parse_package_json('{"dependencies": {}}')
        self.assertEqual(deps, [])


class ParseRequirementsTests(unittest.TestCase):
    def test_typical(self) -> None:
        deps = parse_requirements("requests==2.31.0\n# comment\npytest>=7.0\n")
        self.assertIn(("requests", "PyPI", "2.31.0", "runtime"), deps)
        self.assertIn(("pytest", "PyPI", "7.0", "runtime"), deps)

    def test_empty_text(self) -> None:
        self.assertEqual(parse_requirements(""), [])

    def test_only_comments_and_flags(self) -> None:
        self.assertEqual(parse_requirements("# comment\n--index-url https://example.com\n"), [])

    def test_various_operators(self) -> None:
        deps = parse_requirements("flask>=2.0\nclick<=8.0\ndjango~=4.2\ncelery>5.0\nnumpy!=1.19\n")
        self.assertIn(("flask", "PyPI", "2.0", "runtime"), deps)
        self.assertIn(("click", "PyPI", "8.0", "runtime"), deps)
        self.assertIn(("django", "PyPI", "4.2", "runtime"), deps)
        self.assertIn(("celery", "PyPI", "5.0", "runtime"), deps)
        self.assertIn(("numpy", "PyPI", "1.19", "runtime"), deps)

    def test_package_with_underscores_and_dots(self) -> None:
        deps = parse_requirements("my_pkg==1.0\ntest.pkg==2.0\n")
        self.assertIn(("my_pkg", "PyPI", "1.0", "runtime"), deps)
        self.assertIn(("test.pkg", "PyPI", "2.0", "runtime"), deps)

    def test_no_version(self) -> None:
        deps = parse_requirements("requests\n")
        self.assertIn(("requests", "PyPI", None, "runtime"), deps)


class ParsePomXmlTests(unittest.TestCase):
    def test_single_dependency(self) -> None:
        xml = """<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>my-lib</artifactId>
      <version>1.2.3</version>
    </dependency>
  </dependencies>
</project>"""
        deps = parse_pom_xml(xml)
        self.assertIn(("com.example:my-lib", "Maven", "1.2.3", "runtime"), deps)

    def test_with_scope(self) -> None:
        xml = """<dependency>
      <groupId>org.test</groupId>
      <artifactId>test-lib</artifactId>
      <version>2.0</version>
      <scope>test</scope>
    </dependency>"""
        deps = parse_pom_xml(xml)
        self.assertIn(("org.test:test-lib", "Maven", "2.0", "test"), deps)

    def test_multiple_dependencies(self) -> None:
        xml = """<dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency>
<dependency><groupId>c</groupId><artifactId>d</artifactId><version>2</version></dependency>"""
        deps = parse_pom_xml(xml)
        self.assertEqual(len(deps), 2)

    def test_no_dependencies(self) -> None:
        self.assertEqual(parse_pom_xml("<project></project>"), [])

    def test_missing_group_or_artifact(self) -> None:
        xml = "<dependency><version>1.0</version></dependency>"
        self.assertEqual(parse_pom_xml(xml), [])


class ParseGoModTests(unittest.TestCase):
    def test_require_directive(self) -> None:
        mod = "module example.com/my/module\n\ngo 1.21\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.5.0\n)\n"
        deps = parse_go_mod(mod)
        self.assertIn(("github.com/foo/bar", "Go", "1.2.3", "runtime"), deps)
        self.assertIn(("github.com/baz/qux", "Go", "0.5.0", "runtime"), deps)

    def test_inline_require(self) -> None:
        mod = "module example.com/m\ngithub.com/pkg/errors v0.9.1\n"
        deps = parse_go_mod(mod)
        self.assertIn(("github.com/pkg/errors", "Go", "0.9.1", "runtime"), deps)

    def test_empty_text(self) -> None:
        self.assertEqual(parse_go_mod(""), [])

    def test_comments_and_module_line_only(self) -> None:
        mod = "// this is a comment\nmodule example.com/m\n"
        self.assertEqual(parse_go_mod(mod), [])


class ParseGemfileLockTests(unittest.TestCase):
    def test_single_gem(self) -> None:
        lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n"
        deps = parse_gemfile_lock(lock)
        self.assertIn(("rails", "RubyGems", "7.0.4", "runtime"), deps)

    def test_multiple_gems(self) -> None:
        lock = "GEM\n  specs:\n    rack (2.2.4)\n    sinatra (2.1.0)\n"
        deps = parse_gemfile_lock(lock)
        self.assertIn(("rack", "RubyGems", "2.2.4", "runtime"), deps)
        self.assertIn(("sinatra", "RubyGems", "2.1.0", "runtime"), deps)

    def test_empty_text(self) -> None:
        self.assertEqual(parse_gemfile_lock(""), [])

    def test_no_gems(self) -> None:
        self.assertEqual(parse_gemfile_lock("GEM\n  specs:\n"), [])


class ParseCyclonedxSbomTests(unittest.TestCase):
    def test_single_component(self) -> None:
        raw = {"components": [{"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]}
        self.assertEqual(parse_cyclonedx_sbom(raw), [("lodash", "npm", "4.17.15", "runtime")])

    def test_missing_components_key(self) -> None:
        self.assertEqual(parse_cyclonedx_sbom({}), [])

    def test_missing_name_skipped(self) -> None:
        raw = {"components": [{"version": "1.0", "purl": "pkg:npm/test@1.0"}]}
        self.assertEqual(parse_cyclonedx_sbom(raw), [])

    def test_missing_version(self) -> None:
        raw = {"components": [{"name": "test", "purl": "pkg:npm/test@1.0"}]}
        self.assertEqual(parse_cyclonedx_sbom(raw), [("test", "npm", None, "runtime")])

    def test_missing_purl(self) -> None:
        raw = {"components": [{"name": "test", "version": "1.0"}]}
        self.assertEqual(parse_cyclonedx_sbom(raw), [("test", "unknown", "1.0", "runtime")])


class ParseSpdxSbomTests(unittest.TestCase):
    def test_single_package(self) -> None:
        raw = {
            "packages": [
                {
                    "name": "flask",
                    "versionInfo": "2.0.0",
                    "externalRefs": [{"referenceLocator": "pkg:pypi/flask@2.0.0"}],
                }
            ]
        }
        self.assertEqual(parse_spdx_sbom(raw), [("flask", "PyPI", "2.0.0", "runtime")])

    def test_missing_packages_key(self) -> None:
        self.assertEqual(parse_spdx_sbom({}), [])

    def test_missing_name_skipped(self) -> None:
        raw = {"packages": [{"versionInfo": "1.0"}]}
        self.assertEqual(parse_spdx_sbom(raw), [])

    def test_no_external_refs(self) -> None:
        raw = {"packages": [{"name": "test", "versionInfo": "1.0"}]}
        self.assertEqual(parse_spdx_sbom(raw), [("test", "unknown", "1.0", "runtime")])

    def test_empty_external_refs(self) -> None:
        raw = {"packages": [{"name": "test", "versionInfo": "1.0", "externalRefs": []}]}
        self.assertEqual(parse_spdx_sbom(raw), [("test", "unknown", "1.0", "runtime")])

    def test_external_refs_not_a_list(self) -> None:
        raw = {"packages": [{"name": "test", "versionInfo": "1.0", "externalRefs": "invalid"}]}
        self.assertEqual(parse_spdx_sbom(raw), [("test", "unknown", "1.0", "runtime")])


class ExtractJsDependencyHintsTests(unittest.TestCase):
    def test_comment_hint(self) -> None:
        hints = extract_js_dependency_hints("/*! lodash@4.17.15 */ webpack:///node_modules/@scope/pkg/index.js")
        self.assertIn(("lodash", "npm", "4.17.15", "runtime"), hints)
        self.assertIn(("@scope/pkg", "npm", None, "runtime"), hints)

    def test_name_version_json_pattern(self) -> None:
        hints = extract_js_dependency_hints('"name": "react", "version": "18.0.0"')
        self.assertIn(("react", "npm", "18.0.0", "runtime"), hints)

    def test_webpack_path(self) -> None:
        hints = extract_js_dependency_hints("webpack:///./node_modules/express/index.js")
        self.assertIn(("express", "npm", None, "runtime"), hints)

    def test_empty_text(self) -> None:
        self.assertEqual(extract_js_dependency_hints(""), [])

    def test_short_name_skipped(self) -> None:
        hints = extract_js_dependency_hints("/*! a@1.0.0 */")
        self.assertNotIn(("a", "npm", "1.0.0", "runtime"), hints)

    def test_http_prefix_skipped(self) -> None:
        hints = extract_js_dependency_hints("/*! http@1.0.0 */")
        self.assertNotIn(("http", "npm", "1.0.0", "runtime"), hints)

    def test_www_prefix_skipped(self) -> None:
        hints = extract_js_dependency_hints("/*! www.example.com@1.0.0 */")
        self.assertNotIn(("www.example.com", "npm", "1.0.0", "runtime"), hints)


class InternalHelperTests(unittest.TestCase):
    def test_ecosystem_from_purl_valid(self) -> None:
        self.assertEqual(_ecosystem_from_purl("pkg:npm/lodash@4.17.15"), "npm")

    def test_ecosystem_from_purl_pypi(self) -> None:
        self.assertEqual(_ecosystem_from_purl("pkg:pypi/requests@2.31.0"), "PyPI")

    def test_ecosystem_from_purl_none(self) -> None:
        self.assertIsNone(_ecosystem_from_purl(None))

    def test_ecosystem_from_purl_non_pkg(self) -> None:
        self.assertIsNone(_ecosystem_from_purl("http://example.com"))

    def test_looks_like_package_valid(self) -> None:
        self.assertTrue(_looks_like_package("lodash"))

    def test_looks_like_package_short(self) -> None:
        self.assertFalse(_looks_like_package("a"))

    def test_looks_like_package_http(self) -> None:
        self.assertFalse(_looks_like_package("http://example.com"))

    def test_looks_like_package_www(self) -> None:
        self.assertFalse(_looks_like_package("www.example.com"))


if __name__ == "__main__":
    unittest.main()
