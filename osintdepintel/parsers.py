from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from .versioning import normalize_version

ECOSYSTEM_ALIASES = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "go": "Go",
    "gomod": "Go",
    "docker": "Docker",
    "oci": "Docker",
}


def normalize_ecosystem(value: str) -> str:
    return ECOSYSTEM_ALIASES.get(value.lower(), value)


def parse_package_json(text: str) -> list[tuple[str, str, str | None, str]]:
    raw = json.loads(text)
    results: list[tuple[str, str, str | None, str]] = []
    for field, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("peerDependencies", "runtime"),
        ("optionalDependencies", "runtime"),
    ):
        for name, version in raw.get(field, {}).items():
            results.append((name, "npm", normalize_version(str(version)), scope))
    return results


def parse_requirements(text: str) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-"):
            continue
        no_markers = stripped.split(";", 1)[0]
        no_comments = no_markers.split("#", 1)[0].strip()
        clean_line = re.sub(r"\[.*?\]", "", no_comments).strip()
        if not clean_line:
            continue
        match = re.match(
            r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|>|<|!=|=)?\s*([^;#\s]+)?",
            clean_line,
        )
        if match:
            results.append((match.group(1), "PyPI", normalize_version(match.group(2)), "runtime"))
    return results


def parse_pom_xml(text: str) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        wrapped = f"<root>{text}</root>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            return results
    try:
        for dep in root.iter("{*}dependency") if root.tag.startswith("{") else root.iter("dependency"):
            ns = root.tag[: root.tag.index("}") + 1] if root.tag.startswith("{") else ""
            group_el = dep.find(f"{ns}groupId") if ns else dep.find("groupId")
            artifact_el = dep.find(f"{ns}artifactId") if ns else dep.find("artifactId")
            version_el = dep.find(f"{ns}version") if ns else dep.find("version")
            scope_el = dep.find(f"{ns}scope") if ns else dep.find("scope")
            if group_el is not None and artifact_el is not None:
                group = group_el.text.strip() if group_el.text else ""
                artifact = artifact_el.text.strip() if artifact_el.text else ""
                if group and artifact:
                    version = version_el.text.strip() if version_el is not None and version_el.text else None
                    scope = scope_el.text.strip() if scope_el is not None and scope_el.text else "runtime"
                    results.append((f"{group}:{artifact}", "Maven", normalize_version(version), scope))
    except ET.ParseError:
        pass
    return results


def parse_go_mod(text: str) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("module "):
            continue
        match = re.match(r"([A-Za-z0-9_.\-/]+)\s+v?([0-9][^\s]*)", stripped)
        if match:
            results.append((match.group(1), "Go", normalize_version(match.group(2)), "runtime"))
    return results


def parse_gemfile_lock(text: str) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    for line in text.splitlines():
        match = re.match(r"\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)", line)
        if match:
            results.append((match.group(1), "RubyGems", normalize_version(match.group(2)), "runtime"))
    return results


def parse_cyclonedx_sbom(raw: dict[str, Any]) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    for component in raw.get("components", []):
        name = component.get("name")
        version = component.get("version")
        ecosystem = _ecosystem_from_purl(component.get("purl")) or component.get("type") or "unknown"
        if name:
            results.append((name, normalize_ecosystem(ecosystem), normalize_version(version), "runtime"))
    return results


def parse_spdx_sbom(raw: dict[str, Any]) -> list[tuple[str, str, str | None, str]]:
    results: list[tuple[str, str, str | None, str]] = []
    for package in raw.get("packages", []):
        name = package.get("name")
        version = package.get("versionInfo")
        refs = package.get("externalRefs")
        purl = (
            refs[0].get("referenceLocator", "")
            if isinstance(refs, list) and len(refs) > 0 and isinstance(refs[0], dict)
            else ""
        )
        ecosystem = _ecosystem_from_purl(purl)
        if name:
            results.append((name, normalize_ecosystem(ecosystem or "unknown"), normalize_version(version), "runtime"))
    return results


def extract_js_dependency_hints(text: str) -> list[tuple[str, str, str | None, str]]:
    hints: list[tuple[str, str, str | None, str]] = []
    patterns = [
        r"([@A-Za-z0-9_\-/]+)@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r'"name"\s*:\s*"([^"]+)"\s*,\s*"version"\s*:\s*"([^"]+)"',
        r"webpack:///(?:\./)?node_modules/([^/@\s]+|@[^/\s]+/[^/\s]+)/",
    ]
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            if pattern.startswith("webpack"):
                name, version = match.group(1), None
            else:
                name, version = match.group(1), match.group(2)
            key = (name, version)
            if key not in seen and _looks_like_package(name):
                seen.add(key)
                hints.append((name, "npm", normalize_version(version), "runtime"))
    return hints


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    value = purl.split("/", 1)[0].replace("pkg:", "")
    return normalize_ecosystem(value)


def _looks_like_package(name: str) -> bool:
    if len(name) < 2:
        return False
    return not name.startswith(("http", "www."))
