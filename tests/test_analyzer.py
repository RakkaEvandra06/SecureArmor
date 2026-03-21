"""
tests/test_analyzer.py — Unit tests for PassCheck (stdlib unittest).

Run with:  python3 -m pytest tests/ -v
       or:  python3 tests/test_analyzer.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow running directly from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from passcheck.analyzer import PasswordAnalyzer
from passcheck.constants import LENGTH_EXCELLENT, LENGTH_GOOD, LENGTH_MINIMUM, SCORE_WEIGHTS
from passcheck.models import PasswordAnalysis
from passcheck.scoring import criteria_summary, score_bar, score_to_label


class TestAnalyzeContract(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = PasswordAnalyzer()

    def test_returns_password_analysis(self) -> None:
        result = self.analyzer.analyze("Hello123!")
        self.assertIsInstance(result, PasswordAnalysis)

    def test_score_within_range(self) -> None:
        for pw in ["a", "abc", "Hello123!", "P@ssw0rd!ExtraLong#2024"]:
            result = self.analyzer.analyze(pw)
            self.assertGreaterEqual(result.score, 0, f"Score negative for {pw!r}")
            self.assertLessEqual(result.score, 100, f"Score > 100 for {pw!r}")

    def test_empty_password_does_not_crash(self) -> None:
        # Empty password passes "not a common password" and "no keyboard patterns" → score > 0
        result = self.analyzer.analyze("")
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 30)  # still very low

    def test_criteria_list_non_empty(self) -> None:
        result = self.analyzer.analyze("test")
        self.assertGreater(len(result.criteria), 0)

    def test_suggestions_are_strings(self) -> None:
        result = self.analyzer.analyze("abc")
        for s in result.suggestions:
            self.assertIsInstance(s, str)


class TestLengthCriteria(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _crit(self, pw: str, name: str):
        return next(c for c in self.a.analyze(pw).criteria if c.name == name)

    def test_below_minimum_fails(self) -> None:
        crit = self._crit("a" * (LENGTH_MINIMUM - 1), "Minimum length")
        self.assertFalse(crit.passed)

    def test_at_minimum_passes(self) -> None:
        crit = self._crit("a" * LENGTH_MINIMUM, "Minimum length")
        self.assertTrue(crit.passed)

    def test_below_good_fails_good_check(self) -> None:
        crit = self._crit("a" * (LENGTH_GOOD - 1), "Recommended length")
        self.assertFalse(crit.passed)

    def test_excellent_length_gives_bonus(self) -> None:
        crit = self._crit("a" * LENGTH_EXCELLENT, "Excellent length")
        self.assertTrue(crit.passed)
        self.assertEqual(crit.score, SCORE_WEIGHTS["length_excellent"])


class TestCharacterClasses(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _crit(self, pw: str, name: str):
        return next(c for c in self.a.analyze(pw).criteria if c.name == name)

    def test_uppercase_detected(self) -> None:
        self.assertTrue(self._crit("Abcdefgh", "Uppercase letters").passed)

    def test_no_uppercase_fails(self) -> None:
        self.assertFalse(self._crit("abcdefgh", "Uppercase letters").passed)

    def test_digit_detected(self) -> None:
        self.assertTrue(self._crit("abc123", "Digits").passed)

    def test_no_digit_fails(self) -> None:
        self.assertFalse(self._crit("abcdefgh", "Digits").passed)

    def test_special_char_detected(self) -> None:
        self.assertTrue(self._crit("abc!defgh", "Special characters").passed)

    def test_no_special_char_fails(self) -> None:
        self.assertFalse(self._crit("abcdefgh123", "Special characters").passed)

    def test_char_variety_three_classes(self) -> None:
        self.assertTrue(self._crit("Abcdef123", "Character variety").passed)

    def test_char_variety_one_class_fails(self) -> None:
        self.assertFalse(self._crit("abcdefgh", "Character variety").passed)


class TestCommonPasswordDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _crit(self, pw: str):
        return next(c for c in self.a.analyze(pw).criteria if c.name == "Not a common password")

    def test_common_password_fails(self) -> None:
        self.assertFalse(self._crit("password").passed)

    def test_common_password_case_insensitive(self) -> None:
        self.assertFalse(self._crit("PASSWORD").passed)

    def test_uncommon_password_passes(self) -> None:
        self.assertTrue(self._crit("Xk9!mN#vLq2@").passed)


class TestKeyboardPatternDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _crit(self, pw: str):
        return next(c for c in self.a.analyze(pw).criteria if c.name == "No keyboard patterns")

    def test_qwerty_detected(self) -> None:
        self.assertFalse(self._crit("qwerty123").passed)

    def test_numeric_sequence_detected(self) -> None:
        self.assertFalse(self._crit("abc123456").passed)

    def test_no_pattern_passes(self) -> None:
        self.assertTrue(self._crit("Xk9!mN#vLq2@").passed)


class TestRepeatedCharacters(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _crit(self, pw: str):
        return next(c for c in self.a.analyze(pw).criteria if c.name == "No excessive repetition")

    def test_heavy_repetition_fails(self) -> None:
        self.assertFalse(self._crit("aaaaaabcd").passed)  # 'a' is 67%

    def test_low_repetition_passes(self) -> None:
        self.assertTrue(self._crit("Xk9!mN#vLq").passed)


class TestEntropy(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_short_simple_low_entropy(self) -> None:
        self.assertLess(self.a.analyze("abc").entropy_bits, 50)

    def test_long_complex_high_entropy(self) -> None:
        self.assertGreater(self.a.analyze("P@ssw0rd!ExtraLong#2024$").entropy_bits, 50)

    def test_empty_zero_entropy(self) -> None:
        self.assertEqual(PasswordAnalyzer._calculate_entropy(""), 0.0)


class TestStrengthOrdering(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_complex_beats_simple(self) -> None:
        weak = self.a.analyze("abc")
        strong = self.a.analyze("P@ssw0rd!ExtraLong#2024$X")
        self.assertGreater(strong.score, weak.score)

    def test_very_weak_label(self) -> None:
        # Single char: only lowercase + no-common + no-pattern pass → score=30 → "Weak"
        result = self.a.analyze("a")
        self.assertIn(result.strength_label, ("Very Weak", "Weak"))

    def test_truly_very_weak(self) -> None:
        # Empty string: score is well below 20
        result = self.a.analyze("")
        self.assertLess(result.score, 25)

    def test_strong_label_on_complex(self) -> None:
        result = self.a.analyze("P@ssw0rd!ExtraLong#2024$X")
        self.assertIn(result.strength_label, ("Strong", "Very Strong"))


class TestScoringUtilities(unittest.TestCase):
    def test_score_bar_full(self) -> None:
        self.assertEqual(score_bar(100, width=10), "█" * 10)

    def test_score_bar_empty(self) -> None:
        self.assertEqual(score_bar(0, width=10), "░" * 10)

    def test_score_bar_half(self) -> None:
        self.assertEqual(score_bar(50, width=10), "█" * 5 + "░" * 5)

    def test_score_to_label_80(self) -> None:
        label, _ = score_to_label(80)
        self.assertEqual(label, "Very Strong")

    def test_score_to_label_0(self) -> None:
        label, _ = score_to_label(0)
        self.assertEqual(label, "Very Weak")

    def test_criteria_summary_keys(self) -> None:
        analyzer = PasswordAnalyzer()
        summary = criteria_summary(analyzer.analyze("Hello123!"))
        for key in ("score", "strength", "entropy_bits", "passed", "total", "suggestions", "criteria"):
            self.assertIn(key, summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
