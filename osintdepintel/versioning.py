from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cmp_to_key


def normalize_version(version: str | None) -> str | None:
    if not version:
        return None
    cleaned = version.strip()
    cleaned = cleaned.lstrip("v=~^<> ")
    return cleaned or None


def version_tuple(version: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", version)
    return tuple(int(part) for part in numbers[:4]) if numbers else (0,)


def compare_versions(left: str, right: str) -> int:
    a = version_tuple(left)
    b = version_tuple(right)
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return (a > b) - (a < b)


def satisfies(version: str | None, ranges: Iterable[str]) -> bool:
    if not version:
        return False
    normalized = normalize_version(version)
    if not normalized:
        return False
    return any(_range_matches(normalized, range_expr) for range_expr in ranges)


def _range_matches(version: str, range_expr: str) -> bool:
    expr = range_expr.strip()
    if not expr or expr == "*":
        return True
    if expr.startswith("introduced:") or expr.startswith("fixed:") or "introduced:" in expr or "fixed:" in expr:
        clauses = re.split(r"\s*,\s*|\s+", expr)
        introduced_ver = None
        fixed_ver = None
        for clause in clauses:
            if clause.startswith("introduced:"):
                introduced_ver = clause.split(":", 1)[1].strip()
            elif clause.startswith("fixed:"):
                fixed_ver = clause.split(":", 1)[1].strip()
        return not (
            introduced_ver and introduced_ver != "0" and compare_versions(version, introduced_ver) < 0
        ) and not (fixed_ver and compare_versions(version, fixed_ver) >= 0)

    clauses = re.split(r"\s*,\s*|\s+", expr)
    saw_operator = False
    for clause in [c for c in clauses if c]:
        match = re.match(r"(<=|>=|<|>|==|=|~=|\^|~)?\s*v?([0-9][A-Za-z0-9.\-+]*)", clause)
        if not match:
            continue
        saw_operator = True
        op = match.group(1) or "=="
        other = match.group(2)
        cmp_value = compare_versions(version, other)
        if op in ("=", "==") and cmp_value != 0:
            return False
        if op == "<" and cmp_value >= 0:
            return False
        if op == "<=" and cmp_value > 0:
            return False
        if op == ">" and cmp_value <= 0:
            return False
        if op == ">=" and cmp_value < 0:
            return False
        if op in ("~", "~="):
            if cmp_value < 0:
                return False
            other_parts = version_tuple(other)
            upper = f"{other_parts[0]}.{other_parts[1] + 1}.0" if len(other_parts) >= 2 else f"{other_parts[0]}.1.0"
            if compare_versions(version, upper) >= 0:
                return False
        if op == "^":
            if cmp_value < 0:
                return False
            other_parts = version_tuple(other)
            if len(other_parts) > 0:
                if other_parts[0] > 0:
                    upper = f"{other_parts[0] + 1}.0.0"
                elif len(other_parts) >= 2 and other_parts[1] > 0:
                    upper = f"0.{other_parts[1] + 1}.0"
                elif len(other_parts) >= 3:
                    upper = f"0.0.{other_parts[2] + 1}"
                else:
                    upper = "1.0.0"
            else:
                upper = "1.0.0"
            if compare_versions(version, upper) >= 0:
                return False
    if saw_operator:
        return True
    return compare_versions(version, expr) == 0


def newest(versions: list[str]) -> str | None:
    if not versions:
        return None
    return sorted(versions, key=cmp_to_key(compare_versions))[-1]
