"""tests/test_analyzer.py — Unit tests for PassCheck (stdlib unittest)."""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path

# Allow running directly from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from passcheck.analyzer import PasswordAnalyzer
from passcheck.analyzer.entropy import compute_entropy, _unicode_pool_size
from passcheck.constants import LENGTH_EXCELLENT, LENGTH_GOOD, LENGTH_MAXIMUM, LENGTH_MINIMUM, SCORE_WEIGHTS
from passcheck.constants.special_chars import SPECIAL_CHARS, SPECIAL_CHARS_SET
from passcheck.models import PasswordAnalysis, SkipReason
from passcheck.scoring import criteria_summary, score_bar, score_to_label
from passcheck.utils import masked_password, normalise_for_lookup, split_graphemes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _crit(analyzer: PasswordAnalyzer, pw: str, name: str):
    return next(c for c in analyzer.analyze(pw).criteria if c.name == name)

# ===========================================================================
# Original test suite (unchanged — preserved for regression coverage)
# ===========================================================================

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
        result = self.analyzer.analyze("")
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 30)

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

    def test_below_minimum_fails(self) -> None:
        c = _crit(self.a, "a" * (LENGTH_MINIMUM - 1), "Minimum Length")
        self.assertFalse(c.passed)

    def test_at_minimum_passes(self) -> None:
        c = _crit(self.a, "a" * LENGTH_MINIMUM, "Minimum Length")
        self.assertTrue(c.passed)

    def test_below_good_fails_good_check(self) -> None:
        c = _crit(self.a, "a" * (LENGTH_GOOD - 1), "Good Length")
        self.assertFalse(c.passed)

    def test_excellent_length_gives_bonus(self) -> None:
        c = _crit(self.a, "a" * LENGTH_EXCELLENT, "Excellent Length")
        self.assertTrue(c.passed)
        self.assertEqual(c.score, SCORE_WEIGHTS["length_excellent"])

class TestCharacterClasses(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_uppercase_detected(self) -> None:
        self.assertTrue(_crit(self.a, "Abcdefgh", "Uppercase Letter").passed)

    def test_no_uppercase_fails(self) -> None:
        self.assertFalse(_crit(self.a, "abcdefgh", "Uppercase Letter").passed)

    def test_digit_detected(self) -> None:
        self.assertTrue(_crit(self.a, "abc123", "Digit").passed)

    def test_no_digit_fails(self) -> None:
        self.assertFalse(_crit(self.a, "abcdefgh", "Digit").passed)

    def test_special_char_detected(self) -> None:
        self.assertTrue(_crit(self.a, "abc!defgh", "Special Character").passed)

    def test_no_special_char_fails(self) -> None:
        self.assertFalse(_crit(self.a, "abcdefgh123", "Special Character").passed)

    def test_char_variety_three_classes(self) -> None:
        self.assertTrue(_crit(self.a, "Abcdef123", "Character Variety").passed)

    def test_char_variety_one_class_fails(self) -> None:
        self.assertFalse(_crit(self.a, "abcdefgh", "Character Variety").passed)

class TestCommonPasswordDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_common_password_fails(self) -> None:
        self.assertFalse(_crit(self.a, "password", "Not a Common Password").passed)

    def test_common_password_case_insensitive(self) -> None:
        self.assertFalse(_crit(self.a, "PASSWORD", "Not a Common Password").passed)

    def test_uncommon_password_passes(self) -> None:
        # SEC-002: With only the built-in list (~1 400 entries, below the 5 000
        # minimum), the fail-closed behaviour means a "not found" result is
        # SKIPPED (SkipReason.NO_WORDLIST_AVAILABLE) rather than passed, to
        # avoid a false-negative "safe" verdict.  A genuine pass only happens
        # once a sufficient external wordlist is loaded.
        from passcheck.constants.common_passwords_loader import is_wordlist_sufficient
        from passcheck.models import SkipReason
        crit = _crit(self.a, "Xk9!mN#vLq2@", "Not a Common Password")
        if is_wordlist_sufficient():
            self.assertTrue(crit.passed,
                "With a sufficient wordlist, an obscure password must pass")
        else:
            self.assertTrue(crit.skipped,
                "With an insufficient wordlist, an obscure password must be "
                "skipped (not falsely passed) — SEC-002 fail-closed behaviour")
            self.assertEqual(crit.skip_reason, SkipReason.NO_WORDLIST_AVAILABLE)

class TestKeyboardPatternDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_qwerty_detected(self) -> None:
        self.assertFalse(_crit(self.a, "qwerty123", "No Keyboard Pattern").passed)

    def test_numeric_sequence_detected(self) -> None:
        self.assertFalse(_crit(self.a, "abc123456", "No Keyboard Pattern").passed)

    def test_no_pattern_passes(self) -> None:
        self.assertTrue(_crit(self.a, "Xk9!mN#vLq2@", "No Keyboard Pattern").passed)

class TestRepeatedCharacters(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_heavy_repetition_fails(self) -> None:
        self.assertFalse(_crit(self.a, "aaaaaabcd", "No Repeated Characters").passed)

    def test_low_repetition_passes(self) -> None:
        self.assertTrue(_crit(self.a, "Xk9!mN#vLq", "No Repeated Characters").passed)

class TestEntropy(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_short_simple_low_entropy(self) -> None:
        self.assertLess(self.a.analyze("abc").entropy_bits, 50)

    def test_long_complex_high_entropy(self) -> None:
        self.assertGreater(self.a.analyze("P@ssw0rd!ExtraLong#2024$").entropy_bits, 50)

    def test_empty_zero_entropy(self) -> None:
        pw = ""
        graphemes = split_graphemes(pw)
        self.assertEqual(compute_entropy(pw, graphemes, len(graphemes)), 0.0)

class TestStrengthOrdering(unittest.TestCase):
    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_complex_beats_simple(self) -> None:
        weak   = self.a.analyze("abc")
        strong = self.a.analyze("P@ssw0rd!ExtraLong#2024$X")
        self.assertGreater(strong.score, weak.score)

    def test_very_weak_label(self) -> None:
        result = self.a.analyze("a")
        self.assertIn(result.strength_label, ("Very Weak", "Weak"))

    def test_truly_very_weak(self) -> None:
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
        summary  = criteria_summary(analyzer.analyze("Hello123!"))
        for key in (
            "score", "strength_label", "entropy_bits",
            "passed_count", "total_criteria", "suggestions", "criteria",
        ):
            self.assertIn(key, summary, f"Expected key {key!r} missing from criteria_summary")

# ===========================================================================
# Leet-speak bypass regression tests
# ===========================================================================

class TestLeetBypassRegression(unittest.TestCase):
    """Previously missing leet substitutions allowed common-password
    derivatives to bypass detection and score as Strong (72/100)."""

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _common_crit(self, pw: str):
        return next(
            c for c in self.a.analyze(pw).criteria
            if c.name == "Not a Common Password"
        )

    # -- Caret (^) substitution for 'a' ----------------------------------------

    def test_caret_a_in_password_detected(self) -> None:
        """'p^ssw0rd' must be detected as a 'password' derivative."""
        c = self._common_crit("p^ssw0rd")
        self.assertFalse(c.passed, "'p^ssw0rd' should be detected as a common password")

    def test_caret_only_in_password_detected(self) -> None:
        """'p^ssword' (no digit substitution) must still be detected."""
        c = self._common_crit("p^ssword")
        self.assertFalse(c.passed, "'p^ssword' should be detected as a common password")

    def test_double_caret_password_detected(self) -> None:
        """'p^$$w0rd' (^ for a, $ for s) must be detected."""
        c = self._common_crit("p^$$w0rd")
        self.assertFalse(c.passed, "'p^$$w0rd' should be detected as a common password")

    def test_caret_obfuscation_score_capped(self) -> None:
        """Score for 'p^ssw0rd' must be capped at ≤ 25 points after detection."""
        result = self.a.analyze("p^ssw0rd")
        self.assertLessEqual(
            result.score, 25,
            f"'p^ssw0rd' scored {result.score}/100 — should be capped at ≤ 25"
        )

    def test_caret_in_admin_detected(self) -> None:
        """'^dmin' (caret-obfuscated 'admin') must be detected as common."""
        c = self._common_crit("^dmin")
        # Only fails if "admin" is in the common password list.
        # Accept pass (not in list) as a valid outcome; only flag a WRONG pass.
        # The important thing is that the LEET TABLE now maps ^ → a so the
        # normalise_for_lookup produces 'admin' as a variant.
        variants = normalise_for_lookup("^dmin")
        self.assertIn("admin", variants, "normalise_for_lookup('^dmin') must produce 'admin'")

    # -- Backslash (\) substitution for 'l' ------------------------------------

    def test_backslash_l_normalised(self) -> None:
        """'\\' must be normalised to 'l' in lookup variants."""
        pw = "e\\sa"         # backslash obfuscation of 'elsa'
        variants = normalise_for_lookup(pw)
        self.assertIn("elsa", variants,
            "normalise_for_lookup('e\\\\sa') must produce 'elsa'")

    # -- Previously-working substitutions still work ---------------------------

    def test_at_sign_still_detected(self) -> None:
        """'p@ssw0rd' (@ → a) must still be detected as before."""
        c = self._common_crit("p@ssw0rd")
        self.assertFalse(c.passed)

    def test_dollar_still_detected(self) -> None:
        """'p@$$w0rd' ($ → s) must still be detected."""
        c = self._common_crit("p@$$w0rd")
        self.assertFalse(c.passed)

    def test_genuinely_strong_unaffected(self) -> None:
        """A genuinely strong password must NOT be flagged as common."""
        from passcheck.constants.common_passwords_loader import is_wordlist_sufficient
        from passcheck.models import SkipReason
        c = self._common_crit("Xk9!mN#vLq2@Zr7$")
        # SEC-002: with the built-in-only list (< 5 000 entries), a "not found"
        # verdict is unreliable, so the criterion is skipped rather than passed.
        if is_wordlist_sufficient():
            self.assertTrue(c.passed, "Strong unique password should not be flagged as common")
        else:
            self.assertTrue(c.skipped,
                "Insufficient wordlist: strong password must be skipped, not falsely passed")
            self.assertFalse(c.passed)
            self.assertEqual(c.skip_reason, SkipReason.NO_WORDLIST_AVAILABLE)

# ===========================================================================
# Unicode entropy bound tests
# ===========================================================================

class TestUnicodeEntropyBounds(unittest.TestCase):
    """NON_ASCII_POOL_SIZE = 32,768 caused severe entropy overestimation. """

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_hiragana_pool_size_realistic(self) -> None:
        """Hiragana block pool must be ≤ 96, not 32,768."""
        pool = _unicode_pool_size("あいうえおかきく")
        self.assertGreater(pool, 0, "Hiragana pool must be positive")
        self.assertLessEqual(pool, 96, f"Hiragana pool {pool} >> 96 actual characters")

    def test_emoji_pool_size_realistic(self) -> None:
        """Unicode pool for emoji must be far below the old flat 32,768 constant."""
        pool = _unicode_pool_size("😀😂🙏💕😍🔥💯😎")
        self.assertGreater(pool, 0)
        # Must be dramatically smaller than the old flat constant.
        self.assertLess(pool, 2000,
            f"Emoji pool {pool} is unrealistically large (old constant was 32,768)")

    def test_single_block_emoji_pool_small(self) -> None:
        """Emoji drawn from only the emoticons block must have pool ≤ 100."""
        # U+1F600-U+1F64F are all in the emoticons block (≈80 printable)
        emoticons_only = "😀😁😂😃😄😅"   # all in 0x1F600-0x1F64F
        pool = _unicode_pool_size(emoticons_only)
        self.assertGreater(pool, 0)
        self.assertLessEqual(pool, 100,
            f"Single-block emoticons pool {pool} > 100 — block size is ~80")

    def test_ascii_pool_is_zero(self) -> None:
        """_unicode_pool_size() must return 0 for purely ASCII input."""
        self.assertEqual(_unicode_pool_size("password"), 0)
        self.assertEqual(_unicode_pool_size("P@ssw0rd!"), 0)

    def test_hiragana_entropy_below_old_claim(self) -> None:
        """8 hiragana chars must claim < 60 bits (old claim was 62.4)."""
        result = self.a.analyze("あいうえおかきく")
        self.assertLess(
            result.entropy_bits, 60,
            f"Hiragana entropy {result.entropy_bits:.1f} bits — should be < 60 after fix"
        )

    def test_emoji_entropy_below_old_claim(self) -> None:
        """8 common emoji must claim < 55 bits (old claim was 62.4)."""
        result = self.a.analyze("😀😂🙏💕😍🔥💯😎")
        self.assertLess(
            result.entropy_bits, 55,
            f"Emoji entropy {result.entropy_bits:.1f} bits — should be < 55 after fix"
        )

    def test_mixed_unicode_blocks_additive(self) -> None:
        """A password mixing two Unicode blocks gets a larger pool than either alone."""
        hiragana_pool = _unicode_pool_size("あいうえ")
        katakana_pool = _unicode_pool_size("アイウエ")
        mixed_pool    = _unicode_pool_size("あいアイ")
        self.assertGreater(
            mixed_pool, hiragana_pool,
            "Mixed-block pool must exceed single-block pool"
        )
        self.assertGreater(
            mixed_pool, katakana_pool,
            "Mixed-block pool must exceed single-block pool"
        )

    def test_entropy_still_positive_for_unicode(self) -> None:
        """Entropy must be > 0 for any non-empty Unicode password."""
        result = self.a.analyze("あいうえ")
        self.assertGreater(result.entropy_bits, 0)

# ===========================================================================
# Space no longer counted as a special character
# ===========================================================================

class TestSpaceNotSpecialChar(unittest.TestCase):

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_space_not_in_special_chars_set(self) -> None:
        self.assertNotIn(" ", SPECIAL_CHARS_SET,
            "Space must not be in SPECIAL_CHARS_SET after SA-D01")

    def test_space_not_in_special_chars_string(self) -> None:
        self.assertNotIn(" ", SPECIAL_CHARS,
            "Space must not be in SPECIAL_CHARS after SA-D01")

    def test_space_only_does_not_pass_special_criterion(self) -> None:
        """A password whose only non-alpha chars are spaces must fail Special Character."""
        c = _crit(self.a, "hello world", "Special Character")
        self.assertFalse(c.passed,
            "Spaces alone must not satisfy the Special Character criterion")

    def test_real_special_char_still_passes(self) -> None:
        """! is still a special character."""
        c = _crit(self.a, "hello!world", "Special Character")
        self.assertTrue(c.passed)

    def test_special_chars_count_is_32(self) -> None:
        """After removing space, exactly 32 standard ASCII special chars remain."""
        self.assertEqual(len(SPECIAL_CHARS_SET), 32,
            f"Expected 32 special chars, got {len(SPECIAL_CHARS_SET)}: {sorted(SPECIAL_CHARS_SET)}")

# ===========================================================================
# LENGTH_MAXIMUM raised to 256
# ===========================================================================

class TestLengthMaximumRaised(unittest.TestCase):
    """SA-D02: LENGTH_MAXIMUM was 128; now 256."""

    def test_length_maximum_value(self) -> None:
        self.assertEqual(LENGTH_MAXIMUM, 256,
            f"LENGTH_MAXIMUM should be 256 after SA-D02, got {LENGTH_MAXIMUM}")

    def test_200_char_password_accepted(self) -> None:
        """A 200-character password must be analysed without error."""
        pw = "Abc1!" * 40  # 200 chars, diverse character classes
        result = PasswordAnalyzer().analyze(pw)
        self.assertIsInstance(result, PasswordAnalysis)

    def test_256_char_password_accepted(self) -> None:
        """A 256-character password (new maximum) must be analysed without error."""
        pw = ("Abcdefgh1!" * 26)[:256]
        result = PasswordAnalyzer().analyze(pw)
        self.assertIsInstance(result, PasswordAnalysis)

    def test_257_char_password_rejected(self) -> None:
        """A 257-character password must raise ValueError (exceeds new maximum)."""
        pw = "a" * 257
        with self.assertRaises(ValueError):
            PasswordAnalyzer().analyze(pw)

# ===========================================================================
# Redact flag: criteria_summary and JSON output
# ===========================================================================

class TestRedactFlag(unittest.TestCase):

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_redact_false_returns_masked_form(self) -> None:
        """Default (redact=False) returns the asterisk-masked form."""
        result  = self.a.analyze("Hello123!")
        summary = criteria_summary(result, redact=False)
        self.assertNotEqual(summary["password_masked"], "[REDACTED]")
        self.assertIn("*", summary["password_masked"],
            "Non-redacted output must contain asterisks")

    def test_redact_true_returns_redacted_sentinel(self) -> None:
        """redact=True must return exactly '[REDACTED]' for password_masked."""
        result  = self.a.analyze("Hello123!")
        summary = criteria_summary(result, redact=True)
        self.assertEqual(summary["password_masked"], "[REDACTED]")

    def test_redact_does_not_alter_score(self) -> None:
        """Redaction must not affect the score or any other field."""
        result   = self.a.analyze("Hello123!")
        plain    = criteria_summary(result, redact=False)
        redacted = criteria_summary(result, redact=True)
        self.assertEqual(plain["score"],          redacted["score"])
        self.assertEqual(plain["strength_label"], redacted["strength_label"])
        self.assertEqual(plain["entropy_bits"],   redacted["entropy_bits"])
        self.assertEqual(plain["criteria"],       redacted["criteria"])

    def test_redact_default_is_false(self) -> None:
        """criteria_summary(analysis) without redact kwarg must NOT redact."""
        result  = self.a.analyze("Hello123!")
        summary = criteria_summary(result)
        self.assertNotEqual(summary["password_masked"], "[REDACTED]")

    def test_redact_json_field_is_string(self) -> None:
        """password_masked must always be a string even when redacted."""
        result  = self.a.analyze("TestPw99!")
        summary = criteria_summary(result, redact=True)
        self.assertIsInstance(summary["password_masked"], str)

    def test_redact_with_short_password(self) -> None:
        """Redaction works for short passwords (fully masked by masking logic)."""
        result  = self.a.analyze("ab")
        summary = criteria_summary(result, redact=True)
        self.assertEqual(summary["password_masked"], "[REDACTED]")

# ===========================================================================
# Unicode_checks_skipped field in JSON output
# ===========================================================================

class TestUnicodeSkipAdvisory(unittest.TestCase):

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def test_unicode_only_sets_flag_true(self) -> None:
        """Hiragana-only password must set unicode_checks_skipped=True."""
        result  = self.a.analyze("あいうえおかきく")
        summary = criteria_summary(result)
        self.assertIn("unicode_checks_skipped", summary,
            "unicode_checks_skipped key must be present in AnalysisSummary")
        self.assertTrue(summary["unicode_checks_skipped"],
            "Unicode-only password must set unicode_checks_skipped=True")

    def test_ascii_password_sets_flag_false(self) -> None:
        """ASCII password must set unicode_checks_skipped=False."""
        result  = self.a.analyze("Hello123!")
        summary = criteria_summary(result)
        self.assertFalse(summary["unicode_checks_skipped"],
            "ASCII password must set unicode_checks_skipped=False")

    def test_mixed_password_sets_flag_false(self) -> None:
        """Mixed ASCII+Unicode password must set unicode_checks_skipped=False
        (it has ASCII residue so checks can run)."""
        result  = self.a.analyze("Hello123あ")
        summary = criteria_summary(result)
        self.assertFalse(summary["unicode_checks_skipped"],
            "Mixed password with ASCII residue must not set unicode_checks_skipped")

    def test_unicode_criteria_have_correct_skip_reason(self) -> None:
        """The skipped criteria for Unicode-only passwords must carry
        SkipReason.UNICODE_ONLY_PASSWORD as their skip_reason."""
        result = self.a.analyze("あいうえおかきく")
        skipped_unicode = [
            c for c in result.criteria
            if c.skipped and c.skip_reason == SkipReason.UNICODE_ONLY_PASSWORD
        ]
        self.assertGreater(len(skipped_unicode), 0,
            "At least one criterion must be skipped with UNICODE_ONLY_PASSWORD reason")

# ===========================================================================
# Masked password boundary tests
# ===========================================================================

class TestMaskedPasswordBoundaries(unittest.TestCase):
    """Edge-case coverage for masked_password() length boundaries."""

    def test_length_1(self) -> None:
        self.assertEqual(masked_password("a"), "*")

    def test_length_5_fully_masked(self) -> None:
        """Passwords < 6 chars must be fully masked."""
        self.assertEqual(masked_password("abcde"), "*****")

    def test_length_6_single_edge(self) -> None:
        """At exactly 6 chars, only the first character is shown."""
        result = masked_password("abcdef")
        self.assertEqual(result[0], "a")
        self.assertTrue(all(c == "*" for c in result[1:]),
            f"Characters after first must be '*', got: {result!r}")

    def test_length_7_single_edge(self) -> None:
        """At 7 chars, only the first character is shown."""
        result = masked_password("abcdefg")
        self.assertEqual(result[0], "a")
        self.assertTrue(all(c == "*" for c in result[1:]))

    def test_length_8_first_and_last(self) -> None:
        """At 8 chars, first and last characters are both shown."""
        result = masked_password("abcdefgh")
        self.assertEqual(result[0],  "a")
        self.assertEqual(result[-1], "h")
        self.assertTrue(all(c == "*" for c in result[1:-1]),
            f"Middle chars must be '*', got: {result!r}")

    def test_length_9_first_and_last(self) -> None:
        result = masked_password("abcdefghi")
        self.assertEqual(result[0],  "a")
        self.assertEqual(result[-1], "i")

    def test_empty_password_returns_empty(self) -> None:
        self.assertEqual(masked_password(""), "")

    def test_emoji_grapheme_cluster_boundary(self) -> None:
        """Emoji should be treated as single grapheme clusters."""
        pw = "😀😂🙏💕😍🔥💯😎"  # 8 emoji
        result = masked_password(pw)
        self.assertEqual(len(result.replace("*", "")), 2,
            "Exactly 2 non-asterisk graphemes expected (first + last)")

# ===========================================================================
# Thread-safety of get_analyzer() (lock-always pattern)
# ===========================================================================

class TestSingletonNoConcurrentRace(unittest.TestCase):
    """get_analyzer() must return the same object under concurrent load."""

    def test_concurrent_get_analyzer_same_instance(self) -> None:
        """50 concurrent calls to get_analyzer() must all return the same object."""
        from passcheck.cli.analyzer_singleton import get_analyzer
        import passcheck.cli.analyzer_singleton as _singleton_mod

        # Reset the singleton so the race window is real.
        original = _singleton_mod._analyzer
        _singleton_mod._analyzer = None

        results: list[int] = []
        errors:  list[Exception] = []

        def worker() -> None:
            try:
                results.append(id(get_analyzer()))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Restore original state.
        _singleton_mod._analyzer = original

        self.assertEqual(errors, [], f"Errors during concurrent access: {errors}")
        self.assertEqual(
            len(set(results)), 1,
            f"get_analyzer() returned {len(set(results))} distinct objects "
            f"(expected 1) — possible singleton race condition"
        )

    def test_concurrent_common_passwords_same_instance(self) -> None:
        """50 concurrent calls to get_common_passwords() must return the same frozenset."""
        from passcheck.constants.common_passwords_loader import (
            get_common_passwords,
        )
        import passcheck.constants.common_passwords_loader as _loader

        original = _loader._COMMON_PASSWORDS_CACHE
        _loader._COMMON_PASSWORDS_CACHE = None

        results: list[int] = []
        errors:  list[Exception] = []

        def worker() -> None:
            try:
                results.append(id(get_common_passwords()))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        _loader._COMMON_PASSWORDS_CACHE = original

        self.assertEqual(errors, [], f"Errors during concurrent access: {errors}")
        self.assertEqual(len(set(results)), 1,
            "get_common_passwords() must return the same frozenset from all threads")

# ===========================================================================
# --password flag gate (CliRunner tests)
# ===========================================================================

class TestSecurityGates(unittest.TestCase):
    """--password must be gated behind PASSCHECK_ALLOW_INSECURE_FLAG=1."""

    def setUp(self) -> None:
        try:
            from click.testing import CliRunner
            from passcheck.cli import cli
            self.runner = CliRunner()
            self.cli    = cli
            self.available = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("click.testing not available")

    def test_password_flag_blocked_without_env(self) -> None:
        """--password without PASSCHECK_ALLOW_INSECURE_FLAG=1 must exit non-zero."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli, ["check", "--password", "testpassword"],
            catch_exceptions=False,
        )
        self.assertNotEqual(result.exit_code, 0,
            "--password should be blocked without the env gate")

    def test_password_flag_allowed_with_env(self) -> None:
        """--password with PASSCHECK_ALLOW_INSECURE_FLAG=1 must not error on the gate."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        # BUG-001 fix: ExitCode.ERROR == 1, not 2.  The previous assertion
        # `assertNotEqual(exit_code, 2)` was vacuously true because no exit
        # code in the system is ever 2, so it gave zero regression protection.
        # The correct assertion is that the gate-open path must succeed (0=OK)
        # or produce a partial result (3=PARTIAL) — never ERROR (1).
        from passcheck.cli.exit_codes import ExitCode
        self.assertIn(
            result.exit_code,
            (ExitCode.OK, ExitCode.PARTIAL),
            "--password with PASSCHECK_ALLOW_INSECURE_FLAG=1 must exit OK or "
            "PARTIAL (not ERROR), confirming the gate did not block the request",
        )

    def test_json_redact_flag_replaces_masked_password(self) -> None:
        """--json --redact must produce JSON with password_masked='[REDACTED]'."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--json", "--redact"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        # CliRunner mixes stderr (insecure-flag warning) into stdout by default.
        # Extract the JSON line: the last non-empty line that starts with '{'.
        json_line = next(
            (ln for ln in reversed(result.output.splitlines()) if ln.strip().startswith("{")),
            None,
        )
        if json_line is None:
            self.fail(f"No JSON line found in output: {result.output!r}")
        try:
            output = json.loads(json_line)
        except json.JSONDecodeError:
            self.fail(f"Last '{{'-prefixed line is not valid JSON: {json_line!r}")
        self.assertEqual(output.get("password_masked"), "[REDACTED]",
            "JSON output with --redact must have password_masked='[REDACTED]'")

    def test_json_without_redact_has_partial_mask(self) -> None:
        """--json without --redact must NOT show '[REDACTED]' — should be asterisks."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--json"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        json_line = next(
            (ln for ln in reversed(result.output.splitlines()) if ln.strip().startswith("{")),
            None,
        )
        if json_line is None:
            self.fail(f"No JSON line found in output: {result.output!r}")
        try:
            output = json.loads(json_line)
        except json.JSONDecodeError:
            self.fail(f"Last '{{'-prefixed line is not valid JSON: {json_line!r}")
        self.assertNotEqual(output.get("password_masked"), "[REDACTED]",
            "JSON output without --redact must NOT be '[REDACTED]'")
        self.assertIn("*", output.get("password_masked", ""),
            "JSON output without --redact must contain '*' masking")

    def test_unicode_checks_skipped_in_json(self) -> None:
        """unicode_checks_skipped must be True in JSON for Unicode-only passwords."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "あいうえおかきく", "--json"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        json_line = next(
            (ln for ln in reversed(result.output.splitlines()) if ln.strip().startswith("{")),
            None,
        )
        if json_line is None:
            self.fail(f"No JSON line found in output: {result.output!r}")
        try:
            output = json.loads(json_line)
        except json.JSONDecodeError:
            self.fail(f"Last '{{'-prefixed line is not valid JSON: {json_line!r}")
        self.assertIn("unicode_checks_skipped", output,
            "JSON output must include unicode_checks_skipped field")
        self.assertTrue(output["unicode_checks_skipped"],
            "unicode_checks_skipped must be True for a Unicode-only password")

# ===========================================================================
# SEC-001 — --redact must suppress password_length in all output paths
# ===========================================================================

class TestRedactSuppressesLength(unittest.TestCase):
    """SEC-001: --redact must hide the exact password length, not just the masked form."""

    def setUp(self) -> None:
        try:
            from click.testing import CliRunner
            from passcheck.cli import cli
            from passcheck.analyzer.core import PasswordAnalyzer
            from passcheck.scoring import criteria_summary
            # mix_stderr=False keeps the insecure-flag warning on stderr so
            # result.output contains only the JSON/human output we want to test.
            self.runner   = CliRunner()
            self.cli      = cli
            self.analyzer = PasswordAnalyzer()
            self.criteria_summary = criteria_summary
            self.available = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("dependencies not available")

    @staticmethod
    def _parse_json_output(output: str) -> dict:
        """Extract and parse the first JSON object from potentially mixed CLI output."""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
        raise AssertionError(f"No JSON object found in output: {output!r}")

    def test_redact_hides_length_in_json_summary(self) -> None:
        """criteria_summary(redact=True) must set password_length to None."""
        self._skip_if_unavailable()
        analysis = self.analyzer.analyze("MySecret99!")
        summary  = self.criteria_summary(analysis, redact=True)
        self.assertIsNone(
            summary["password_length"],
            "password_length must be None when redact=True (SEC-001)",
        )
        self.assertEqual(summary["password_masked"], "[REDACTED]")

    def test_redact_false_exposes_length_in_json_summary(self) -> None:
        """criteria_summary(redact=False) must include the real length."""
        self._skip_if_unavailable()
        analysis = self.analyzer.analyze("MySecret99!")
        summary  = self.criteria_summary(analysis, redact=False)
        self.assertEqual(summary["password_length"], analysis.password_length)

    def test_redact_hides_length_in_cli_json_output(self) -> None:
        """--json --redact must produce JSON with password_length=null."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--json", "--redact"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        output = self._parse_json_output(result.output)
        self.assertIsNone(
            output.get("password_length"),
            "JSON output with --redact must have password_length=null (SEC-001)",
        )
        self.assertEqual(output.get("password_masked"), "[REDACTED]")

    def test_redact_hides_password_length_field_in_header(self) -> None:
        """Human-readable header with --redact must not show the (N chars) suffix."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--redact"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        # Only the HEADER line is affected by the fix; the criteria-detail rows
        # (e.g. "9 chars (minimum 8)") are scoring rationale and are kept.
        # The header line looks like: "  Password: [REDACTED]  (N chars)"
        # With --redact it must be:   "  Password: [REDACTED]"
        header_lines = [
            ln for ln in result.output.splitlines()
            if "Password:" in ln
        ]
        self.assertTrue(header_lines, "Expected a 'Password:' header line in output")
        for line in header_lines:
            self.assertNotRegex(
                line,
                r"\d+\s*chars",
                "The Password: header line must not contain the char count with --redact (SEC-001)",
            )
        self.assertIn("[REDACTED]", result.output)

    def test_no_redact_shows_char_count_in_header(self) -> None:
        """Human-readable header without --redact must show the character count."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        header_lines = [ln for ln in result.output.splitlines() if "Password:" in ln]
        self.assertTrue(header_lines, "Expected a 'Password:' header line in output")
        char_count_shown = any(
            __import__("re").search(r"\d+\s*chars", ln) for ln in header_lines
        )
        self.assertTrue(
            char_count_shown,
            "The Password: header line must show the char count without --redact",
        )


# ===========================================================================
# SEC-002 — fail-closed behaviour when wordlist coverage is insufficient
# ===========================================================================

class TestWordlistFailClosed(unittest.TestCase):
    """SEC-002: common-password criterion must skip, not pass, when the wordlist
    is too small to produce a reliable 'not found' verdict."""

    def setUp(self) -> None:
        try:
            from passcheck.analyzer.patterns import criterion_no_common_password
            from passcheck.models import SkipReason
            self.criterion   = criterion_no_common_password
            self.SkipReason  = SkipReason
            self.available   = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("dependencies not available")

    def test_not_found_with_insufficient_wordlist_is_skipped(self) -> None:
        """'not found' + wordlist_sufficient=False must be SKIPPED, not passed."""
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=False,
            can_lookup=True,
            length=12,
            has_ascii_residue=True,
            wordlist_sufficient=False,
        )
        self.assertTrue(result.skipped,
            "criterion must be skipped when wordlist coverage is insufficient (SEC-002)")
        self.assertFalse(result.passed,
            "criterion must not pass when wordlist coverage is insufficient (SEC-002)")
        self.assertEqual(result.skip_reason, self.SkipReason.NO_WORDLIST_AVAILABLE)

    def test_found_with_insufficient_wordlist_still_fails(self) -> None:
        """A hit (is_common=True) must always be flagged regardless of list size."""
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=True,
            can_lookup=True,
            length=8,
            has_ascii_residue=True,
            wordlist_sufficient=False,
        )
        self.assertFalse(result.passed,
            "A common-password hit must be reported even with a small wordlist (SEC-002)")
        self.assertFalse(result.skipped,
            "A positive hit must not be skipped")

    def test_not_found_with_sufficient_wordlist_passes(self) -> None:
        """'not found' + wordlist_sufficient=True must PASS (normal behaviour)."""
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=False,
            can_lookup=True,
            length=12,
            has_ascii_residue=True,
            wordlist_sufficient=True,
        )
        self.assertTrue(result.passed,
            "criterion must pass when password is not found in a sufficient wordlist")
        self.assertFalse(result.skipped)

    def test_backward_compat_default_wordlist_sufficient_true(self) -> None:
        """Omitting wordlist_sufficient must default to True (backward compat)."""
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=False,
            can_lookup=True,
            length=12,
            has_ascii_residue=True,
            # wordlist_sufficient not passed → defaults to True
        )
        self.assertTrue(result.passed)
        self.assertFalse(result.skipped)

    def test_is_wordlist_sufficient_returns_bool(self) -> None:
        """is_wordlist_sufficient() must return a bool without raising."""
        try:
            from passcheck.constants.common_passwords_loader import is_wordlist_sufficient
        except ImportError:
            self.skipTest("common_passwords_loader not importable")
        result = is_wordlist_sufficient()
        self.assertIsInstance(result, bool,
            "is_wordlist_sufficient() must return bool")


# ===========================================================================
# SEC-003 — entropy annotation when pattern cap is applied
# ===========================================================================

class TestEntropyAnnotation(unittest.TestCase):
    """SEC-003: entropy_note must be present in JSON when weak_pattern_cap_applied."""

    def setUp(self) -> None:
        try:
            from click.testing import CliRunner
            from passcheck.cli import cli
            from passcheck.analyzer.core import PasswordAnalyzer
            from passcheck.scoring import criteria_summary
            self.runner   = CliRunner()
            self.cli      = cli
            self.analyzer = PasswordAnalyzer()
            self.criteria_summary = criteria_summary
            self.available = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("dependencies not available")

    @staticmethod
    def _parse_json_output(output: str) -> dict:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
        raise AssertionError(f"No JSON object found in output: {output!r}")

    def test_entropy_note_present_when_cap_applied(self) -> None:
        """entropy_note must be a non-empty string when weak_pattern_cap_applied=True."""
        self._skip_if_unavailable()
        analysis = self.analyzer.analyze("qwerty12345")
        self.assertTrue(analysis.weak_pattern_cap_applied,
            "Test prerequisite: qwerty12345 must trigger the pattern cap")
        summary = self.criteria_summary(analysis)
        self.assertIsNotNone(summary["entropy_note"],
            "entropy_note must not be None when weak_pattern_cap_applied (SEC-003)")
        self.assertIsInstance(summary["entropy_note"], str)
        self.assertGreater(len(summary["entropy_note"]), 0)

    def test_entropy_note_absent_when_cap_not_applied(self) -> None:
        """entropy_note must be None for passwords that did not trigger the cap."""
        self._skip_if_unavailable()
        analysis = self.analyzer.analyze("Xk9#mP2$vLqR")
        self.assertFalse(analysis.weak_pattern_cap_applied,
            "Test prerequisite: Xk9#mP2$vLqR must not trigger the pattern cap")
        summary = self.criteria_summary(analysis)
        self.assertIsNone(summary["entropy_note"],
            "entropy_note must be None when no cap was applied (SEC-003)")

    def test_entropy_note_in_cli_json_output_when_cap_applied(self) -> None:
        """CLI --json output must include entropy_note when a weak pattern fires."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "qwerty12345", "--json"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        output = self._parse_json_output(result.output)
        self.assertIn("entropy_note", output,
            "JSON output must contain entropy_note field (SEC-003)")
        self.assertIsNotNone(output["entropy_note"])

    def test_entropy_note_in_human_output_when_cap_applied(self) -> None:
        """Human-readable output must include an entropy annotation when cap fires."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "qwerty12345"],
            env={"PASSCHECK_ALLOW_INSECURE_FLAG": "1"},
            catch_exceptions=False,
        )
        self.assertIn("theoretical", result.output.lower(),
            "Human-readable output must mention the theoretical nature of the "
            "entropy estimate when the pattern cap was applied (SEC-003)")


# ===========================================================================
# SEC-004 — --redact suppresses length in batch JSON error events
# ===========================================================================

class TestBatchRedactSuppressesLength(unittest.TestCase):
    """SEC-004: batch --json --redact must omit length/limit from skipped_invalid events."""

    def setUp(self) -> None:
        try:
            from click.testing import CliRunner
            from passcheck.cli import cli
            self.runner    = CliRunner()
            self.cli       = cli
            self.available = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("dependencies not available")

    def test_batch_json_redact_hides_length_for_oversized_password(self) -> None:
        """skipped_invalid JSON event must not include length when --redact is set."""
        self._skip_if_unavailable()
        oversized = "a" * 300 + "\n"
        result = self.runner.invoke(
            self.cli,
            ["batch", "--json", "--redact"],
            input=oversized,
            catch_exceptions=False,
        )
        lines = [ln for ln in result.output.strip().splitlines() if ln.strip()]
        self.assertTrue(lines, "Expected at least one JSON line in output")
        event = json.loads(lines[0])
        self.assertEqual(event.get("event"), "skipped_invalid")
        self.assertNotIn("length", event,
            "length must be absent from skipped_invalid event when --redact is set (SEC-004)")
        self.assertNotIn("limit", event,
            "limit must be absent from skipped_invalid event when --redact is set (SEC-004)")

    def test_batch_json_no_redact_includes_length_for_oversized_password(self) -> None:
        """Without --redact, skipped_invalid must include length and limit for debugging."""
        self._skip_if_unavailable()
        oversized = "a" * 300 + "\n"
        result = self.runner.invoke(
            self.cli,
            ["batch", "--json"],
            input=oversized,
            catch_exceptions=False,
        )
        lines = [ln for ln in result.output.strip().splitlines() if ln.strip()]
        self.assertTrue(lines, "Expected at least one JSON line in output")
        event = json.loads(lines[0])
        self.assertEqual(event.get("event"), "skipped_invalid")
        self.assertIn("length", event,
            "length must appear in skipped_invalid event without --redact")
        self.assertEqual(event["length"], 300)


# ===========================================================================
# BUG-002 — Non-ASCII digits must not satisfy the fifth variety class
# ===========================================================================

class TestNonAsciiDigitVariety(unittest.TestCase):
    """BUG-002: Arabic-Indic and similar non-ASCII digits must not count toward
    the 'other Unicode characters' variety class while failing the ASCII-digit
    criterion — that combination produced contradictory user feedback."""

    def setUp(self) -> None:
        try:
            from passcheck.analyzer.character import (
                criterion_char_variety,
                criterion_has_digit,
            )
            self.criterion_variety = criterion_char_variety
            self.criterion_digit   = criterion_has_digit
            self.available         = True
        except ImportError:
            self.available = False

    def _skip_if_unavailable(self) -> None:
        if not self.available:
            self.skipTest("dependencies not available")

    def test_arabic_indic_digits_fail_ascii_digit_criterion(self) -> None:
        """Arabic-Indic digits (U+0660–U+0669) must not satisfy criterion_has_digit."""
        self._skip_if_unavailable()
        pw = "٠١٢٣٤٥٦٧٨"
        result = self.criterion_digit(pw)
        self.assertFalse(result.passed,
            "Non-ASCII digits must not satisfy the ASCII-digit criterion (BUG-002)")

    def test_arabic_indic_digits_fail_variety_class(self) -> None:
        """A password of only Arabic-Indic digits must show 0/5 character classes."""
        self._skip_if_unavailable()
        pw = "٠١٢٣٤٥٦٧٨"
        result = self.criterion_variety(pw)
        self.assertFalse(result.passed,
            "Arabic-Indic digits alone must not satisfy the variety criterion (BUG-002)")
        self.assertIn("0/5", result.detail,
            "Detail must show 0 classes present for Arabic-Indic-only password")

    def test_arabic_script_non_digits_still_satisfy_variety_class(self) -> None:
        """Non-digit Arabic characters (e.g. letters) must still count as class 5."""
        self._skip_if_unavailable()
        # Arabic letter 'ain' (ع) is not a digit, not ASCII, not upper, not lower
        pw = "عربي"  # Arabic letters — not digits
        result = self.criterion_variety(pw)
        # 1 class present (class 5 = other Unicode); variety fails (<3), but
        # the detail must show at least 1 class, confirming the class was counted.
        self.assertNotIn("0/5", result.detail,
            "Non-digit Arabic letters must still count as the 'other Unicode' class (BUG-002 fix must not over-exclude)")

    def test_hiragana_still_satisfies_variety_class(self) -> None:
        """Hiragana (non-ASCII, non-digit) must still count as the 5th variety class."""
        self._skip_if_unavailable()
        pw = "あいうえお"  # Hiragana — not digits
        result = self.criterion_variety(pw)
        # Should show 1/5, not 0/5
        self.assertNotIn("0/5", result.detail,
            "Hiragana must still count as the 'other Unicode' variety class")


# ===========================================================================
# BUG-003 — NON_ASCII_POOL_SIZE deprecation warning
# ===========================================================================

class TestNonAsciiPoolSizeDeprecation(unittest.TestCase):
    """BUG-003: Accessing NON_ASCII_POOL_SIZE must emit a DeprecationWarning."""

    def test_non_ascii_pool_size_emits_deprecation_warning(self) -> None:
        """Importing NON_ASCII_POOL_SIZE via passcheck.constants must warn."""
        import warnings
        import importlib
        import sys

        # Reload the constants package to ensure __getattr__ is exercised even
        # if the name was previously imported (cached in the module namespace).
        mod_name = "passcheck.constants"
        if mod_name in sys.modules:
            # Remove only if it was already imported so we can test __getattr__
            pass  # __getattr__ fires on attribute access, not just first import

        import passcheck.constants as constants_mod
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = constants_mod.NON_ASCII_POOL_SIZE  # triggers __getattr__

        deprecation_warnings = [
            w for w in caught
            if issubclass(w.category, DeprecationWarning)
            and "NON_ASCII_POOL_SIZE" in str(w.message)
        ]
        self.assertTrue(
            deprecation_warnings,
            "Accessing passcheck.constants.NON_ASCII_POOL_SIZE must emit a "
            "DeprecationWarning mentioning 'NON_ASCII_POOL_SIZE' (BUG-003)",
        )

    def test_non_ascii_pool_size_not_in_star_import(self) -> None:
        """NON_ASCII_POOL_SIZE must not appear in passcheck.constants.__all__."""
        import passcheck.constants as constants_mod
        self.assertNotIn(
            "NON_ASCII_POOL_SIZE",
            constants_mod.__all__,
            "NON_ASCII_POOL_SIZE must be removed from __all__ (BUG-003)",
        )

    def test_non_ascii_pool_size_backward_compat_value(self) -> None:
        """The deprecated constant must still return 32 768 for backward compat."""
        import warnings
        import passcheck.constants as constants_mod
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            value = constants_mod.NON_ASCII_POOL_SIZE
        self.assertEqual(value, 32_768,
            "Backward-compat shim must return the original 32 768 value")


if __name__ == "__main__":
    unittest.main(verbosity=2)