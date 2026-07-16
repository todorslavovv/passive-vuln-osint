from __future__ import annotations

import base64
import json
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any

from .http import join_url
from .models import DependencyRecord, DependencyStatus, Provenance, utc_now
from .versioning import normalize_version

KNOWN_BROWSER_PACKAGES = {
    "jquery",
    "bootstrap",
    "lodash",
    "moment",
    "react",
    "react-dom",
    "next",
    "webpack",
    "vue",
    "angular",
    "@angular/core",
    "zone.js",
    "core-js",
    "axios",
}

CONFIG_DEPENDENCY_FIELDS = {
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "packages",
    "libraries",
    "frameworks",
}

VERSIONED_ASSET_PATTERNS = [
    (r"(jquery)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "jquery"),
    (r"(bootstrap)(?:\.bundle)?(?:\.min)?[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "bootstrap"),
    (r"(lodash)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "lodash"),
    (r"(moment)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "moment"),
    (r"(react(?:-dom)?)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", None),
    (r"(vue)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "vue"),
    (r"(angular)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "angular"),
    (r"(axios)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "axios"),
    (r"(core-js)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "core-js"),
]


@dataclass
class EvidenceItem:
    source_url: str
    fetch_method: str
    collected_at: str
    content_sha256: str
    snippet: str
    plugin_name: str
    reasoning: str
    directness: str
    source_type: str
    extracted_token: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyCandidate:
    target_name: str
    name: str
    ecosystem: str
    version: str | None
    confidence: float
    status: DependencyStatus
    relationship: str
    scope: str
    reasoning: str
    evidence_chain: list[EvidenceItem] = field(default_factory=list)
    conflict_notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.ecosystem.lower()}:{self.name.lower()}@{self.version or 'unknown'}"

    def to_record(self) -> DependencyRecord:
        provenance = [
            Provenance(
                source_type=item.source_type,
                source_name=item.plugin_name,
                locator=item.source_url,
                collected_at=item.collected_at,
                evidence=item.reasoning,
                fetch_method=item.fetch_method,
                content_sha256=item.content_sha256,
                snippet=item.snippet,
            )
            for item in self.evidence_chain
        ]
        return DependencyRecord(
            target_name=self.target_name,
            name=self.name,
            ecosystem=self.ecosystem,
            version=self.version,
            status=self.status,
            confidence=self.confidence,
            provenance=provenance,
            relationship=self.relationship,
            scope=self.scope,
            qualifiers={
                "reasoning": self.reasoning,
                "evidence_chain": [item.to_dict() for item in self.evidence_chain],
                "conflict_notes": self.conflict_notes,
            },
        )

    def to_inference(self, plugin_name: str) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "plugin": plugin_name,
            "package_name": self.name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "status": self.status.value,
            "confidence": self.confidence,
            "relationship": self.relationship,
            "scope": self.scope,
            "reasoning": self.reasoning,
            "evidence_chain": [item.to_dict() for item in self.evidence_chain],
            "conflict_notes": self.conflict_notes,
        }


def infer_from_html(target_name: str, html: str, url: str, plugin_name: str) -> list[DependencyCandidate]:
    candidates: list[DependencyCandidate] = []
    for script_url in extract_script_urls(url, html):
        candidates.extend(_infer_from_asset_url(target_name, script_url, html, url, plugin_name, "html_script_tag"))
    for inline in extract_inline_scripts(html):
        candidates.extend(
            _infer_from_text(target_name, inline, url, plugin_name, "inline_runtime_config", 0.5, "direct")
        )
        candidates.extend(
            _infer_from_dependency_config(target_name, inline, url, plugin_name, "inline_runtime_config", 0.5, "direct")
        )
    if "/_next/static/" in html or "__NEXT_DATA__" in html:
        candidates.append(
            _candidate(
                target_name,
                "next",
                None,
                0.38,
                "Next.js public build artifact or runtime marker in HTML; no version was exposed",
                _evidence(
                    url, "GET", html, plugin_name, "next", "heuristic framework fingerprint", "indirect", "target_html"
                ),
            )
        )
    if "webpackJsonp" in html or "__webpack_require__" in html:
        candidates.append(
            _candidate(
                target_name,
                "webpack",
                None,
                0.32,
                "Webpack runtime marker in HTML or inline script; no package version was exposed",
                _evidence(
                    url, "GET", html, plugin_name, "webpack", "heuristic bundler fingerprint", "indirect", "target_html"
                ),
            )
        )
    if "_spPageContextInfo" in html or "/_layouts/15/" in html:
        candidates.append(
            _candidate(
                target_name,
                "sharepoint",
                None,
                0.35,
                "SharePoint public page marker observed; dependency package/version is not directly exposed",
                _evidence(
                    url,
                    "GET",
                    html,
                    plugin_name,
                    "SharePoint",
                    "framework fingerprint",
                    "indirect",
                    "target_html",
                    ecosystem="web-framework",
                ),
                ecosystem="web-framework",
            )
        )
    return consolidate_candidates(candidates)


def infer_from_js(
    target_name: str, text: str, url: str, plugin_name: str, source_type: str = "public_js_bundle"
) -> list[DependencyCandidate]:
    candidates = _infer_from_text(target_name, text, url, plugin_name, source_type, 0.56, "indirect")
    candidates.extend(_infer_from_dependency_config(target_name, text, url, plugin_name, source_type, 0.56, "indirect"))
    return consolidate_candidates(candidates)


def infer_from_source_map(target_name: str, text: str, url: str, plugin_name: str) -> list[DependencyCandidate]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return []
    candidates: list[DependencyCandidate] = []
    candidates.extend(
        _infer_from_dependency_config(target_name, text, url, plugin_name, "source_map", 0.58, "indirect")
    )
    sources = list(raw.get("sources", []))
    contents = list(raw.get("sourcesContent", []))
    for index, source in enumerate(sources):
        package_name = package_from_node_modules_path(source)
        if package_name:
            candidates.append(
                _candidate(
                    target_name,
                    package_name,
                    None,
                    0.42,
                    "source map path referenced node_modules package but did not expose a version",
                    _evidence(
                        url,
                        "GET",
                        text,
                        plugin_name,
                        source,
                        "node_modules path in source map",
                        "indirect",
                        "source_map",
                    ),
                )
            )
        if index < len(contents):
            content = contents[index] or ""
            if source.endswith("package.json"):
                candidates.extend(
                    _infer_package_json_metadata(target_name, content, url, plugin_name, "source_map_package_metadata")
                )
            else:
                candidates.extend(
                    _infer_from_text(target_name, content, url, plugin_name, "source_map_content", 0.58, "indirect")
                )
                candidates.extend(
                    _infer_from_dependency_config(
                        target_name, content, url, plugin_name, "source_map_content", 0.58, "indirect"
                    )
                )
    return consolidate_candidates(candidates)


def extract_script_urls(base_url: str, html: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        urls.append(join_url(base_url, match.group(1)))
    return urls


def extract_inline_scripts(html: str) -> list[str]:
    scripts: list[str] = []
    for match in re.finditer(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL):
        body = match.group(1).strip()
        if body:
            scripts.append(body)
    return scripts


def extract_source_map_urls(bundle_url: str, text: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"sourceMappingURL\s*=\s*([^\s*]+)", text):
        locator = match.group(1).strip().strip("\"'")
        if locator.startswith("data:application/json"):
            urls.append(locator)
        else:
            urls.append(join_url(bundle_url, locator))
    return urls


def decode_inline_source_map(locator: str) -> str | None:
    if not locator.startswith("data:application/json"):
        return None
    if ";base64," in locator:
        encoded = locator.split(";base64,", 1)[1]
        try:
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except ValueError:
            return None
    if "," in locator:
        return urllib.parse.unquote(locator.split(",", 1)[1])
    return None


def package_from_node_modules_path(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    marker = "node_modules/"
    if marker not in normalized:
        return None
    after = normalized.split(marker, 1)[1].lstrip("/")
    parts = after.split("/")
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _infer_from_dependency_config(
    target_name: str,
    text: str,
    url: str,
    plugin_name: str,
    source_type: str,
    base_confidence: float,
    directness: str,
) -> list[DependencyCandidate]:
    candidates: list[DependencyCandidate] = []
    for config_field, body in _dependency_config_blocks(text):
        for name, version, token in _dependency_entries_from_block(body):
            if not _looks_like_version(version):
                continue
            candidates.append(
                _candidate(
                    target_name,
                    name,
                    normalize_version(version),
                    base_confidence + 0.12,
                    f"inline runtime config {config_field} block declared dependency",
                    _evidence(
                        url,
                        "GET",
                        text,
                        plugin_name,
                        token,
                        "runtime config dependency declaration",
                        directness,
                        source_type,
                    ),
                )
            )
    return candidates


def _dependency_config_blocks(text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for match in re.finditer(
        r'["\']?(?P<field>dependencies|devDependencies|peerDependencies|optionalDependencies|packages|libraries|frameworks)["\']?\s*:\s*(?P<opener>\{|\[)',
        text,
        flags=re.IGNORECASE,
    ):
        body = _extract_balanced(text, match.start("opener"))
        if body is not None and match.group("field").lower() in CONFIG_DEPENDENCY_FIELDS:
            blocks.append((match.group("field").lower(), body))
    return blocks


def _extract_balanced(text: str, opener_index: int) -> str | None:
    opener = text[opener_index]
    closer = "}" if opener == "{" else "]"
    depth = 0
    quote: str | None = None
    for index in range(opener_index, len(text)):
        char = text[index]
        if quote:
            backslash_count = 0
            j = index - 1
            while j >= 0 and text[j] == "\\":
                backslash_count += 1
                j -= 1
            if char == quote and backslash_count % 2 == 0:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[opener_index + 1 : index]
    return None


def _dependency_entries_from_block(body: str) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in re.finditer(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']+)["\']', body):
        name, version = match.group(1), match.group(2)
        if _looks_like_npm_package(name):
            _append_entry(entries, seen, name, version, match.group(0))
    for match in re.finditer(
        r'["\']name["\']\s*:\s*["\']([^"\']+)["\'][^"\']{0,160}?["\']version["\']\s*:\s*["\']([^"\']+)["\']', body
    ):
        _append_entry(entries, seen, match.group(1), match.group(2), match.group(0))
    for match in re.finditer(
        r'["\']version["\']\s*:\s*["\']([^"\']+)["\'][^"\']{0,160}?["\']name["\']\s*:\s*["\']([^"\']+)["\']', body
    ):
        _append_entry(entries, seen, match.group(2), match.group(1), match.group(0))
    for match in re.finditer(
        r'["\']([^"\']+)["\']\s*:\s*\{[^{}]*["\']version["\']\s*:\s*["\']([^"\']+)["\'][^{}]*\}', body
    ):
        _append_entry(entries, seen, match.group(1), match.group(2), match.group(0))
    return entries


def _append_entry(
    entries: list[tuple[str, str, str]], seen: set[tuple[str, str]], name: str, version: str, token: str
) -> None:
    key = (name.lower(), version.lower())
    if key in seen:
        return
    seen.add(key)
    entries.append((name, version, token))


def consolidate_candidates(candidates: Iterable[DependencyCandidate]) -> list[DependencyCandidate]:
    candidate_list = [candidate for candidate in candidates if _allowed_candidate(candidate)]
    packages_with_exact_versions = {
        (candidate.ecosystem.lower(), candidate.name.lower()) for candidate in candidate_list if candidate.version
    }
    candidate_list = [
        candidate
        for candidate in candidate_list
        if candidate.version
        or (candidate.ecosystem.lower(), candidate.name.lower()) not in packages_with_exact_versions
    ]
    grouped: dict[str, DependencyCandidate] = {}
    by_package: dict[tuple[str, str], list[DependencyCandidate]] = {}
    for candidate in candidate_list:
        key = candidate.key
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = candidate
        else:
            existing.evidence_chain.extend(candidate.evidence_chain)
            existing.confidence = _combined_confidence(
                existing.confidence, candidate.confidence, len({item.source_url for item in existing.evidence_chain})
            )
            if candidate.status == DependencyStatus.CONFIRMED:
                existing.status = DependencyStatus.CONFIRMED
            if candidate.reasoning not in existing.reasoning:
                existing.reasoning = f"{existing.reasoning}; {candidate.reasoning}"
        by_package.setdefault((candidate.ecosystem.lower(), candidate.name.lower()), []).append(candidate)
    for (_ecosystem, _name), package_candidates in by_package.items():
        versions = sorted({candidate.version or "unknown" for candidate in package_candidates})
        if len(versions) <= 1:
            continue
        sorted_candidates = sorted(package_candidates, key=lambda c: c.confidence, reverse=True)
        note = f"competing version claims retained: {', '.join(versions)}"
        for i, candidate in enumerate(sorted_candidates):
            entry = grouped[candidate.key]
            if i > 0:
                entry.conflict_notes.append(note)
            entry.confidence = max(0.1, round(entry.confidence - 0.08, 3))
    return sorted(grouped.values(), key=lambda item: (item.name, item.version or ""))


def _infer_from_text(
    target_name: str,
    text: str,
    url: str,
    plugin_name: str,
    source_type: str,
    base_confidence: float,
    directness: str,
) -> list[DependencyCandidate]:
    candidates: list[DependencyCandidate] = []
    for name, version, token, reasoning in _versioned_tokens(text):
        candidates.append(
            _candidate(
                target_name,
                name,
                version,
                base_confidence + 0.08,
                reasoning,
                _evidence(url, "GET", text, plugin_name, token, reasoning, directness, source_type),
            )
        )
    for package_name in _node_module_tokens(text):
        candidates.append(
            _candidate(
                target_name,
                package_name,
                None,
                max(0.28, base_confidence - 0.18),
                "node_modules package path observed without exposed version",
                _evidence(
                    url, "GET", text, plugin_name, package_name, "node_modules package path", "indirect", source_type
                ),
            )
        )
    if "React.version" in text:
        for match in re.finditer(r"React\.version\s*=\s*[\"']([0-9][^\"']+)[\"']", text):
            candidates.append(
                _candidate(
                    target_name,
                    "react",
                    normalize_version(match.group(1)),
                    base_confidence + 0.12,
                    "React.version assignment exposed an exact runtime version",
                    _evidence(
                        url, "GET", text, plugin_name, match.group(0), "runtime version token", "direct", source_type
                    ),
                )
            )
    return candidates


def _infer_from_asset_url(
    target_name: str, asset_url: str, html: str, page_url: str, plugin_name: str, source_type: str
) -> list[DependencyCandidate]:
    basename = urllib.parse.urlparse(asset_url).path.rsplit("/", 1)[-1]
    candidates: list[DependencyCandidate] = []
    patterns = VERSIONED_ASSET_PATTERNS
    for pattern, fixed_name in patterns:
        match = re.search(pattern, basename, flags=re.IGNORECASE)
        if match:
            name = fixed_name or match.group(1).lower()
            version = normalize_version(match.group(2))
            candidates.append(
                _candidate(
                    target_name,
                    name,
                    version,
                    0.68,
                    "script URL filename exposed package-like name and exact version",
                    _evidence(
                        page_url,
                        "GET",
                        html,
                        plugin_name,
                        basename,
                        "versioned script tag asset reference",
                        "indirect",
                        source_type,
                    ),
                )
            )
    if "/_next/static/" in asset_url:
        candidates.append(
            _candidate(
                target_name,
                "next",
                None,
                0.38,
                "Next.js build asset path observed without exposed package version",
                _evidence(
                    page_url,
                    "GET",
                    html,
                    plugin_name,
                    asset_url,
                    "Next.js script asset reference",
                    "indirect",
                    source_type,
                ),
            )
        )
    return candidates


def _infer_package_json_metadata(
    target_name: str, text: str, url: str, plugin_name: str, source_type: str
) -> list[DependencyCandidate]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return []
    name = raw.get("name")
    version = normalize_version(str(raw.get("version"))) if raw.get("version") else None
    if not name or not version:
        return []
    return [
        _candidate(
            target_name,
            name,
            version,
            0.9,
            "package metadata embedded in source map exposed exact package name and version",
            _evidence(url, "GET", text, plugin_name, name, "source map package.json metadata", "direct", source_type),
            status=DependencyStatus.CONFIRMED,
        )
    ]


def _versioned_tokens(text: str) -> list[tuple[str, str | None, str, str]]:
    tokens: list[tuple[str, str | None, str, str]] = []
    patterns = [
        (
            r"(?<![\w/@.-])((?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+)@([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9_.-]+)?)",
            "package@version token",
        ),
        (
            r"[\"']name[\"']\s*:\s*[\"']([^\"']+)[\"']\s*,\s*[\"']version[\"']\s*:\s*[\"']([^\"']+)[\"']",
            "embedded name/version metadata",
        ),
        (
            r"[\"']version[\"']\s*:\s*[\"']([^\"']+)[\"']\s*,\s*[\"']name[\"']\s*:\s*[\"']([^\"']+)[\"']",
            "embedded version/name metadata",
        ),
    ]
    for pattern, reason in patterns:
        for match in re.finditer(pattern, text):
            if reason == "embedded version/name metadata":
                version, name = match.group(1), match.group(2)
            else:
                name, version = match.group(1), match.group(2)
            name = name.strip()
            version = normalize_version(version)
            if _looks_like_npm_package(name):
                tokens.append((name, version, match.group(0), reason))
    return tokens


def _node_module_tokens(text: str) -> list[str]:
    names = set()
    for match in re.finditer(r"(?:webpack:///(?:\./)?|/)?node_modules/((?:@[^/\s\"']+/)?[^/\s\"']+)", text):
        name = match.group(1)
        if _looks_like_npm_package(name):
            names.add(name)
    return sorted(names)


def _candidate(
    target_name: str,
    name: str,
    version: str | None,
    confidence: float,
    reasoning: str,
    evidence: EvidenceItem,
    ecosystem: str = "npm",
    status: DependencyStatus = DependencyStatus.INFERRED,
) -> DependencyCandidate:
    if version is None and confidence > 0.58:
        confidence = 0.58
    return DependencyCandidate(
        target_name=target_name,
        name=name,
        ecosystem=ecosystem,
        version=version,
        confidence=round(min(confidence, 0.95), 3),
        status=status,
        relationship="direct" if evidence.directness == "direct" else "transitive",
        scope="runtime",
        reasoning=reasoning,
        evidence_chain=[evidence],
    )


def _evidence(
    url: str,
    method: str,
    content: str,
    plugin_name: str,
    token: str,
    reasoning: str,
    directness: str,
    source_type: str,
    ecosystem: str = "npm",
) -> EvidenceItem:
    return EvidenceItem(
        source_url=url,
        fetch_method=method,
        collected_at=utc_now(),
        content_sha256=sha256(content.encode("utf-8", errors="replace")).hexdigest(),
        snippet=_snippet(content, token),
        plugin_name=plugin_name,
        reasoning=reasoning,
        directness=directness,
        source_type=source_type,
        extracted_token=token,
    )


def _snippet(content: str, token: str) -> str:
    compact = re.sub(r"\s+", " ", content)
    needle = token if token in compact else token.split("@", 1)[0]
    index = compact.find(needle)
    if index < 0:
        return compact[:240]
    return compact[max(0, index - 80) : index + 160]


def _combined_confidence(left: float, right: float, source_count: int) -> float:
    return round(min(0.95, max(left, right) + min(0.18, max(0, source_count - 1) * 0.06)), 3)


def _allowed_candidate(candidate: DependencyCandidate) -> bool:
    if candidate.ecosystem != "npm":
        return True
    if candidate.name in KNOWN_BROWSER_PACKAGES:
        return True
    if candidate.name.startswith("@"):
        return True
    return bool(candidate.version and re.match(r"^[A-Za-z0-9_.-]+$", candidate.name))


def _looks_like_version(value: str) -> bool:
    cleaned = normalize_version(value)
    if not cleaned:
        return False
    return bool(re.match(r"(?:v?\d|\*|latest)", cleaned, flags=re.IGNORECASE))


def _looks_like_npm_package(name: str) -> bool:
    if not name or len(name) < 2:
        return False
    if name.startswith(("http", "www.", ".", "/", "-")):
        return False
    if name.endswith((".js", ".min.js", ".css", ".min.css", ".map")):
        return False
    dot_count = name.count(".")
    if dot_count >= 2 and not name.startswith("@"):
        return False
    return bool(re.match(r"^(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+$", name))
