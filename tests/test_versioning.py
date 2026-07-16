from __future__ import annotations

import unittest

from osintdepintel.versioning import (
    _range_matches,
    compare_versions,
    newest,
    normalize_version,
    satisfies,
    version_tuple,
)


class NormalizeVersionTests(unittest.TestCase):
    def test_none_returns_none(self) -> None:
        self.assertIsNone(normalize_version(None))

    def test_empty_returns_none(self) -> None:
        self.assertIsNone(normalize_version(""))

    def test_strips_v_prefix(self) -> None:
        self.assertEqual(normalize_version("v1.2.3"), "1.2.3")

    def test_strips_tilde_prefix(self) -> None:
        self.assertEqual(normalize_version("~1.2.3"), "1.2.3")

    def test_strips_caret_prefix(self) -> None:
        self.assertEqual(normalize_version("^1.2.3"), "1.2.3")

    def test_strips_less_than_prefix(self) -> None:
        self.assertEqual(normalize_version("<1.2.3"), "1.2.3")

    def test_strips_greater_than_prefix(self) -> None:
        self.assertEqual(normalize_version(">1.2.3"), "1.2.3")

    def test_strips_equals_prefix(self) -> None:
        self.assertEqual(normalize_version("=1.2.3"), "1.2.3")

    def test_strips_multiple_prefixes(self) -> None:
        self.assertEqual(normalize_version("v~^1.2.3"), "1.2.3")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(normalize_version("  1.2.3  "), "1.2.3")

    def test_already_clean(self) -> None:
        self.assertEqual(normalize_version("1.2.3"), "1.2.3")

    def test_prerelease_preserved(self) -> None:
        self.assertEqual(normalize_version("1.0.0-alpha.1"), "1.0.0-alpha.1")


class VersionTupleTests(unittest.TestCase):
    def test_full_semver(self) -> None:
        self.assertEqual(version_tuple("1.2.3"), (1, 2, 3))

    def test_major_only(self) -> None:
        self.assertEqual(version_tuple("1"), (1,))

    def test_major_minor(self) -> None:
        self.assertEqual(version_tuple("1.2"), (1, 2))

    def test_with_prerelease(self) -> None:
        self.assertEqual(version_tuple("1.0.0-alpha.1"), (1, 0, 0, 1))

    def test_no_numbers_returns_zero(self) -> None:
        self.assertEqual(version_tuple("abc"), (0,))

    def test_mixed_content(self) -> None:
        self.assertEqual(version_tuple("1.2.3-beta+001"), (1, 2, 3, 1))


class CompareVersionsTests(unittest.TestCase):
    def test_equal(self) -> None:
        self.assertEqual(compare_versions("1.2.3", "1.2.3"), 0)

    def test_left_greater(self) -> None:
        self.assertEqual(compare_versions("2.0.0", "1.9.9"), 1)

    def test_left_less(self) -> None:
        self.assertEqual(compare_versions("1.0.0", "1.0.1"), -1)

    def test_different_lengths(self) -> None:
        self.assertEqual(compare_versions("1.2", "1.2.0"), 0)

    def test_major_version_greater(self) -> None:
        self.assertEqual(compare_versions("2.0.0", "1.99.99"), 1)


class RangeMatchesTests(unittest.TestCase):
    def test_wildcard_star(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "*"))

    def test_empty_expr(self) -> None:
        self.assertTrue(_range_matches("1.2.3", ""))

    def test_exact_match_default(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "1.2.3"))

    def test_exact_with_equals(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "=1.2.3"))

    def test_exact_with_double_equals(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "==1.2.3"))

    def test_exact_mismatch(self) -> None:
        self.assertFalse(_range_matches("1.2.4", "1.2.3"))

    def test_less_than_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "<1.2.4"))

    def test_less_than_not_satisfied(self) -> None:
        self.assertFalse(_range_matches("1.2.4", "<1.2.4"))

    def test_less_than_equal_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.2.4", "<=1.2.4"))

    def test_less_than_equal_not_satisfied(self) -> None:
        self.assertFalse(_range_matches("1.2.5", "<=1.2.4"))

    def test_greater_than_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.2.4", ">1.2.3"))

    def test_greater_than_not_satisfied(self) -> None:
        self.assertFalse(_range_matches("1.2.3", ">1.2.3"))

    def test_greater_than_equal_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.2.3", ">=1.2.3"))

    def test_greater_than_equal_not_satisfied(self) -> None:
        self.assertFalse(_range_matches("1.2.2", ">=1.2.3"))

    def test_tilde_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "~1.2.0"))

    def test_tilde_below_base(self) -> None:
        self.assertFalse(_range_matches("1.1.0", "~1.2.0"))

    def test_tilde_upper_bound_excluded(self) -> None:
        self.assertFalse(_range_matches("1.3.0", "~1.2.0"))

    def test_caret_major_nonzero_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.8.9", "^1.2.3"))

    def test_caret_below_base(self) -> None:
        self.assertFalse(_range_matches("1.0.0", "^1.2.3"))

    def test_caret_major_nonzero_upper_bound_excluded(self) -> None:
        self.assertFalse(_range_matches("2.0.0", "^1.2.3"))

    def test_caret_major_zero_minor_nonzero(self) -> None:
        self.assertTrue(_range_matches("0.2.5", "^0.2.0"))

    def test_caret_major_zero_minor_nonzero_upper_bound_excluded(self) -> None:
        self.assertFalse(_range_matches("0.4.0", "^0.2.0"))

    def test_caret_major_zero_minor_zero_patch(self) -> None:
        self.assertTrue(_range_matches("0.0.5", "^0.0.5"))

    def test_caret_major_zero_single_component(self) -> None:
        self.assertTrue(_range_matches("0.0.5", "^0"))

    def test_caret_major_zero_minor_zero_patch_upper_bound_excluded(self) -> None:
        self.assertFalse(_range_matches("0.0.6", "^0.0.5"))

    def test_compound_range_satisfies_both(self) -> None:
        self.assertTrue(_range_matches("1.5.0", ">1.0.0 <2.0.0"))

    def test_compound_range_fails_lower(self) -> None:
        self.assertFalse(_range_matches("0.5.0", ">1.0.0 <2.0.0"))

    def test_compound_range_fails_upper(self) -> None:
        self.assertFalse(_range_matches("2.0.0", ">1.0.0 <2.0.0"))

    def test_compound_range_equals_lower(self) -> None:
        self.assertTrue(_range_matches("1.0.0", ">=1.0.0 <2.0.0"))

    def test_introduced_fixed_satisfied(self) -> None:
        self.assertTrue(_range_matches("1.5.0", "introduced:1.0.0, fixed:2.0.0"))

    def test_introduced_not_reached(self) -> None:
        self.assertFalse(_range_matches("0.5.0", "introduced:1.0.0, fixed:2.0.0"))

    def test_fixed_reached(self) -> None:
        self.assertFalse(_range_matches("2.0.0", "introduced:1.0.0, fixed:2.0.0"))

    def test_introduced_zero_no_lower_bound(self) -> None:
        self.assertTrue(_range_matches("0.1.0", "introduced:0, fixed:2.0.0"))

    def test_no_introduced_only_fixed(self) -> None:
        self.assertTrue(_range_matches("1.0.0", "fixed:2.0.0"))

    def test_invalid_range_graceful(self) -> None:
        _range_matches("1.2.3", "not-a-range")

    def test_empty_range_graceful(self) -> None:
        self.assertTrue(_range_matches("1.2.3", "   "))


class SatisfiesTests(unittest.TestCase):
    def test_none_version_returns_false(self) -> None:
        self.assertFalse(satisfies(None, [">=1.0.0"]))

    def test_empty_version_returns_false(self) -> None:
        self.assertFalse(satisfies("", [">=1.0.0"]))

    def test_whitespace_version_returns_false(self) -> None:
        self.assertFalse(satisfies("   ", [">=1.0.0"]))

    def test_empty_ranges_returns_false(self) -> None:
        self.assertFalse(satisfies("1.2.3", []))

    def test_any_range_match_returns_true(self) -> None:
        self.assertTrue(satisfies("1.2.3", ["<1.0.0", ">1.0.0"]))

    def test_no_range_match_returns_false(self) -> None:
        self.assertFalse(satisfies("1.0.0", ["<1.0.0", ">1.0.0"]))

    def test_single_range_match(self) -> None:
        self.assertTrue(satisfies("1.2.3", [">=1.0.0 <2.0.0"]))

    def test_single_range_no_match(self) -> None:
        self.assertFalse(satisfies("2.0.0", [">=1.0.0 <2.0.0"]))


class NewestTests(unittest.TestCase):
    def test_returns_highest(self) -> None:
        self.assertEqual(newest(["1.0.0", "2.0.0", "1.9.9"]), "2.0.0")

    def test_single_version(self) -> None:
        self.assertEqual(newest(["1.0.0"]), "1.0.0")

    def test_empty_list_returns_none(self) -> None:
        self.assertIsNone(newest([]))

    def test_unsorted_input(self) -> None:
        self.assertEqual(newest(["1.0.0", "3.0.0", "2.0.0"]), "3.0.0")


if __name__ == "__main__":
    unittest.main()
