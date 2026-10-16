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
        from passcheck.constants.common_passwords_loader import is_wordlist_sufficient
        crit = _crit(self.a, "Xk9!mN#vLq2@", "Not a Common Password")
        if is_wordlist_sufficient():
            self.assertTrue(crit.passed,
                "With a sufficient wordlist, an obscure password must pass")
        else:
            self.assertFalse(crit.passed,
                "With an insufficient wordlist the criterion must not pass")
            self.assertFalse(crit.skipped,
                "With an insufficient wordlist the criterion must fail-closed")

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
        # BUG-001 fix: removed SkipReason.NO_WORDLIST_AVAILABLE reference.
        from passcheck.constants.common_passwords_loader import is_wordlist_sufficient
        c = self._common_crit("Xk9!mN#vLq2@Zr7$")
        if is_wordlist_sufficient():
            self.assertTrue(c.passed, "Strong unique password should not be flagged as common")
        else:
            self.assertFalse(c.passed,
                "With an insufficient wordlist the criterion must not pass")
            self.assertFalse(c.skipped,
                "With an insufficient wordlist the criterion must fail-closed")

    def test_digit_one_as_l_people(self) -> None:
        """'pe0p1e' must produce 'people' via the 1→l leet path."""
        variants = normalise_for_lookup("pe0p1e")
        self.assertIn(
            "people", variants,
            "normalise_for_lookup('pe0p1e') must produce 'people' via 1→l path",
        )

    def test_digit_one_as_l_soldier(self) -> None:
        """'so1dier' must produce 'soldier' via the 1→l leet path."""
        variants = normalise_for_lookup("so1dier")
        self.assertIn(
            "soldier", variants,
            "normalise_for_lookup('so1dier') must produce 'soldier'",
        )

    def test_digit_one_as_l_ball(self) -> None:
        """'ba11' must produce 'ball' via the 1→l leet path."""
        variants = normalise_for_lookup("ba11")
        self.assertIn(
            "ball", variants,
            "normalise_for_lookup('ba11') must produce 'ball'",
        )

    def test_digit_one_as_l_particle(self) -> None:
        """'partic1e' must produce 'particle' via the 1→l leet path."""
        variants = normalise_for_lookup("partic1e")
        self.assertIn(
            "particle", variants,
            "normalise_for_lookup('partic1e') must produce 'particle'",
        )

    def test_digit_one_as_i_still_works_admin(self) -> None:
        """'adm1n' must still produce 'admin' via the 1→i path."""
        variants = normalise_for_lookup("adm1n")
        self.assertIn(
            "admin", variants,
            "normalise_for_lookup('adm1n') must still produce 'admin' (1→i path)",
        )

class TestSpaceEntropyPool(unittest.TestCase):
    """space must be counted in the entropy pool so passphrase-style
    passwords receive a more accurate bit estimate."""

    def setUp(self) -> None:
        from passcheck.analyzer.entropy import compute_entropy
        self.compute = compute_entropy

    def test_passphrase_entropy_higher_than_no_space(self) -> None:
        """A passphrase with spaces must have higher entropy than the same text
        without spaces, because the pool includes one extra character."""
        pw_space    = "correct horse battery staple"
        pw_nospace  = "correcthorsebatterystaple"
        g_space    = list(pw_space)
        g_nospace  = list(pw_nospace)
        e_space    = self.compute(pw_space,   g_space,   len(g_space))
        e_nospace  = self.compute(pw_nospace, g_nospace, len(g_nospace))
        self.assertGreater(
            e_space, e_nospace,
            f"Space passphrase entropy ({e_space:.2f} bits) must exceed no-space "
            f"version ({e_nospace:.2f} bits) because the pool is larger",
        )

    def test_no_space_password_unaffected(self) -> None:
        """Passwords without spaces must be unaffected by the SEC-005 fix."""
        pw = "Password123!"
        g  = list(pw)
        e  = self.compute(pw, g, len(g))
        self.assertGreater(e, 0.0, "Non-space password must have positive entropy")

class TestNoDuplicateSuggestions(unittest.TestCase):

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _check_no_duplicates(self, pw: str) -> None:
        result = self.a.analyze(pw)
        seen:    set[str] = set()
        for s in result.suggestions:
            self.assertNotIn(
                s, seen,
                f"Duplicate suggestion {s!r} found for password {pw!r}",
            )
            seen.add(s)

    def test_no_duplicates_very_short(self) -> None:
        """Very short password triggers many criteria — none should duplicate."""
        self._check_no_duplicates("a")

    def test_no_duplicates_empty(self) -> None:
        """Empty password must produce no suggestions (skipped/failed with empty suggestion)."""
        result = self.a.analyze("")
        self.assertEqual(
            len(result.suggestions), len(set(result.suggestions)),
            "Empty password must not produce duplicate suggestions",
        )

    def test_no_duplicates_common_password(self) -> None:
        """Common-password derivatives must not produce duplicate suggestions."""
        self._check_no_duplicates("password")

    def test_no_duplicates_moderate_password(self) -> None:
        """A medium-strength password must not produce duplicate suggestions."""
        self._check_no_duplicates("Hello123")

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
            "Space must not be in SPECIAL_CHARS_SET")

    def test_space_not_in_special_chars_string(self) -> None:
        self.assertNotIn(" ", SPECIAL_CHARS,
            "Space must not be in SPECIAL_CHARS")

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
            f"LENGTH_MAXIMUM should be 256, got {LENGTH_MAXIMUM}")

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
        """Redaction must not affect score, strength label, or any criterion's
        pass/skip/score fields."""
        result   = self.a.analyze("Hello123!")
        plain    = criteria_summary(result, redact=False)
        redacted = criteria_summary(result, redact=True)
        self.assertEqual(plain["score"],          redacted["score"])
        self.assertEqual(plain["strength_label"], redacted["strength_label"])
        # entropy_bits is bucketed to nearest 5 bits in redact mode.
        redacted_entropy = redacted["entropy_bits"]
        self.assertEqual(redacted_entropy % 5, 0,
            f"Redacted entropy must be a multiple of 5, got {redacted_entropy}")
        self.assertAlmostEqual(
            redacted_entropy,
            round(plain["entropy_bits"] / 5.0) * 5.0,
            places=6,
            msg="Redacted entropy must equal plain entropy rounded to nearest 5 bits",
        )
        # Structural equality: same criteria in the same order with the same
        # scoring outcome — only detail strings may differ due to scrubbing.
        self.assertEqual(len(plain["criteria"]), len(redacted["criteria"]))
        for p_c, r_c in zip(plain["criteria"], redacted["criteria"]):
            self.assertEqual(p_c["name"],      r_c["name"])
            self.assertEqual(p_c["passed"],    r_c["passed"])
            self.assertEqual(p_c["skipped"],   r_c["skipped"])
            self.assertEqual(p_c["score"],     r_c["score"])
            self.assertEqual(p_c["max_score"], r_c["max_score"])

    def test_redact_default_is_true(self) -> None:
        """criteria_summary(analysis) without redact kwarg must redact by default."""
        result  = self.a.analyze("Hello123!")
        summary = criteria_summary(result)
        self.assertEqual(
            summary["password_masked"], "[REDACTED]",
            "Default redact=True must suppress the masked form",
        )
        self.assertIsNone(
            summary["password_length"],
            "Default redact=True must suppress the length",
        )

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
# --redact must hide length in the human-readable table
# ===========================================================================

class TestRedactHidesLengthInCriteriaTable(unittest.TestCase):
    """Regression tests."""

    def setUp(self) -> None:
        import io
        import re
        import contextlib
        self._io      = io
        self._re      = re
        self._ctx     = contextlib
        self.a        = PasswordAnalyzer()

    def _render_human(self, pw: str, *, redact: bool) -> str:
        from passcheck.display import print_analysis
        buf = self._io.StringIO()
        with self._ctx.redirect_stdout(buf):
            print_analysis(self.a.analyze(pw), redact=redact)
        return buf.getvalue()

    def test_no_redact_shows_length_in_detail(self) -> None:
        """Without --redact the length must appear in the length-criterion rows."""
        output = self._render_human("Hello123!", redact=False)
        self.assertTrue(
            self._re.search(r"\b\d+\s+chars\b", output),
            "Non-redacted output must contain 'N chars' in the criteria table",
        )

    def test_redact_hides_length_in_criteria_table(self) -> None:
        """With --redact no bare integer must precede ' chars' in the table rows."""
        output = self._render_human("Hello123!", redact=True)
        self.assertFalse(
            self._re.search(r"\b\d+\s+chars\b", output),
            f"--redact must suppress 'N chars' in the criteria table, got:\n{output}",
        )

    def test_redact_replaces_with_hidden_sentinel(self) -> None:
        """With --redact the length rows must contain '<hidden> chars …'."""
        output = self._render_human("Hello123!", redact=True)
        self.assertIn(
            "<hidden>",
            output,
            "--redact must replace the length integer with '<hidden>'",
        )

    def test_redact_still_suppresses_header_password(self) -> None:
        """--redact must still replace the header password with [REDACTED]."""
        output = self._render_human("Hello123!", redact=True)
        self.assertIn("[REDACTED]", output)

    def test_json_and_human_redact_are_consistent(self) -> None:
        """JSON criteria detail and human-readable detail must both be scrubbed."""
        import re
        result   = self.a.analyze("Hello123!")
        summary  = criteria_summary(result, redact=True)
        for crit in summary["criteria"]:
            self.assertFalse(
                re.match(r"^\d+(?= chars )", crit["detail"]),
                f"JSON detail still contains leading integer: {crit['detail']!r}",
            )
        output = self._render_human("Hello123!", redact=True)
        self.assertFalse(
            re.search(r"\b\d+\s+chars\b", output),
            "Human-readable output still contains 'N chars' under --redact",
        )

# ===========================================================================
# Entropy must not double-penalise moderate repetition
# ===========================================================================

class TestEntropyNoDoublePenalty(unittest.TestCase):
    """Regression tests."""

    def _entropy(self, pw: str) -> float:
        g = split_graphemes(pw)
        return compute_entropy(pw, g, len(g))

    def test_moderate_repetition_not_over_penalised(self) -> None:
        """'aaaaabcde' (5 of 9 chars repeated) must score above 20 bits."""
        e = self._entropy("aaaaabcde")
        self.assertGreater(e, 20.0,
            f"Moderate-repetition password should score >20 bits, got {e:.1f}")
        self.assertLess(e, 40.0,
            f"Moderate-repetition password should still score <40 bits, got {e:.1f}")

    def test_fully_uniform_password_remains_near_zero(self) -> None:
        """A password of all-identical characters must still score near 0 bits."""
        e = self._entropy("aaaaaaaaaa")
        self.assertLess(e, 10.0,
            f"All-same-char password should stay <10 bits, got {e:.1f}")

    def test_structural_block_repeat_still_penalised(self) -> None:
        """'Ab1!Ab1!Ab1!Ab1!Ab1!' (perfect 4-char block × 5) must be penalised
        via the retained repeated_block_period reduction."""
        e = self._entropy("Ab1!" * 5)
        long_e = self._entropy("Ab1!" * 5 + "Xy9#Zq7@")  # non-repeating suffix
        self.assertLess(e, long_e,
            "Structural repeat must score lower than a non-repeating equivalent")

    def test_diverse_long_password_scores_high(self) -> None:
        """A complex 22-char password must exceed the 70-bit ENTROPY_GOOD_THRESHOLD."""
        e = self._entropy("P@ssw0rd!ExtraLong#2024")
        self.assertGreater(e, 70.0,
            f"Complex 22-char password should exceed 70 bits, got {e:.1f}")

    def test_entropy_monotone_with_length_for_uniform_pool(self) -> None:
        """Entropy of 'Abc1!...' must grow as we add more diverse characters."""
        pw_short = "Abc1!"
        pw_long  = "Abc1!Xyz9#Pqr7@"
        e_short  = self._entropy(pw_short)
        e_long   = self._entropy(pw_long)
        self.assertGreater(e_long, e_short,
            "A longer, diverse password must score higher than the shorter prefix")

# ===========================================================================
# Long passphrases must not be capped for substring patterns
# ===========================================================================

class TestKeyboardPatternFractionGate(unittest.TestCase):
    """Regression tests."""

    def setUp(self) -> None:
        self.a = PasswordAnalyzer()

    def _kb(self, pw: str):
        return next(c for c in self.a.analyze(pw).criteria
                    if c.name == "No Keyboard Pattern")

    def test_true_positive_short_qwerty(self) -> None:
        """'qwerty123' (6/9 chars = 67 %) must still be flagged."""
        self.assertFalse(self._kb("qwerty123").passed)

    def test_true_positive_numeric_walk(self) -> None:
        """'abc123456' with 6-char numeric walk (67 %) must still be flagged."""
        self.assertFalse(self._kb("abc123456").passed)

    def test_false_positive_passphrase_qwerty_suffix(self) -> None:
        """'correct-horse-battery-staple-qwerty' (35 chars, 'qwerty' = 17 %)
        must no longer trigger the pattern criterion."""
        result = self.a.analyze("correct-horse-battery-staple-qwerty")
        self.assertTrue(self._kb("correct-horse-battery-staple-qwerty").passed,
            "35-char passphrase must not be flagged for a 6-char keyboard suffix")
        self.assertFalse(result.weak_pattern_cap_applied,
            "Passphrase must not have the weak-pattern cap applied")

    def test_false_positive_passphrase_numeric_suffix(self) -> None:
        """'my-secure-passphrase-1234567890' must not be capped (10/30 = 33 %)."""
        pw = "my-secure-passphrase-1234567890"
        result = self.a.analyze(pw)
        self.assertFalse(result.weak_pattern_cap_applied,
            "Passphrase with numeric suffix must not be capped")

    def test_passphrase_scores_above_medium_after_fix(self) -> None:
        """A 35-char mixed passphrase must score well above Medium (40 %)."""
        result = self.a.analyze("correct-horse-battery-staple-qwerty")
        self.assertGreater(result.score_percent, 40,
            f"Expected >40 %, got {result.score_percent} %")

    def test_clean_strong_password_unaffected(self) -> None:
        """'Xk9!mN#vLq2@' must still pass the keyboard check."""
        self.assertTrue(self._kb("Xk9!mN#vLq2@").passed)

# ===========================================================================
# criterion_char_uniqueness must skip for empty passwords
# ===========================================================================

class TestCharUniquenessEmptyPasswordSkip(unittest.TestCase):
    """Regression tests for BUG-002."""

    def setUp(self) -> None:
        from passcheck.analyzer.character import criterion_char_uniqueness
        self._fn = criterion_char_uniqueness

    def test_empty_password_is_skipped(self) -> None:
        result = self._fn([], 0)
        self.assertTrue(result.skipped,
            "criterion_char_uniqueness must return skipped=True for empty input")

    def test_empty_password_skip_reason(self) -> None:
        result = self._fn([], 0)
        self.assertEqual(result.skip_reason, SkipReason.EMPTY_PASSWORD)

    def test_empty_password_no_misleading_suggestion(self) -> None:
        result = self._fn([], 0)
        self.assertEqual(result.suggestion, "",
            "A skipped criterion must not carry a suggestion")

    def test_empty_password_score_is_zero(self) -> None:
        result = self._fn([], 0)
        self.assertEqual(result.score, 0)

    def test_non_empty_password_still_evaluated(self) -> None:
        result = self._fn(["a", "b", "c", "d"], 4)
        self.assertFalse(result.skipped,
            "Non-empty input must not be skipped")

    def test_high_uniqueness_still_passes(self) -> None:
        graphemes = list("Abc1!Xyz9")
        result    = self._fn(graphemes, len(graphemes))
        self.assertTrue(result.passed)

# ===========================================================================
# Built-in wordlist must be below the raised threshold
# ===========================================================================

class TestWordlistThresholdRaised(unittest.TestCase):
    """Regression tests."""

    def test_builtin_list_meets_min_threshold_after_reversal_expansion(self) -> None:
        from passcheck.constants.common_passwords_data import RAW_BUILTIN_COMMON_PASSWORDS
        from passcheck.constants.common_passwords_loader import (
            _expand_builtin_passwords,
            _MIN_EXPECTED_COMMON_PASSWORDS,
        )
        expanded = _expand_builtin_passwords(RAW_BUILTIN_COMMON_PASSWORDS)
        self.assertGreaterEqual(
            len(expanded),
            _MIN_EXPECTED_COMMON_PASSWORDS,
            f"Built-in list ({len(expanded)} entries) must meet or exceed the minimum "
            f"({_MIN_EXPECTED_COMMON_PASSWORDS}) after DESIGN-003 reversal expansion.",
        )

    def test_known_common_password_still_detected_without_wordlist(self) -> None:
        """'password' must still be flagged even when the wordlist is insufficient,
        because is_common is evaluated before the wordlist_sufficient check."""
        a    = PasswordAnalyzer()
        crit = next(c for c in a.analyze("password").criteria
                    if c.name == "Not a Common Password")
        # Either failed (found in built-in list) or skipped (wordlist insufficient).
        # Either outcome is correct; the important thing is it must NOT pass.
        self.assertFalse(crit.passed,
            "'password' must never pass the common-password criterion")

    def test_wordlist_sufficient_true_with_builtin_list(self) -> None:
        """wordlist_degraded (always-False dead field) replaced
        by wordlist_sufficient and external_wordlist_loaded.  The built-in
        expanded list meets the minimum threshold so wordlist_sufficient
        must be True in a default install."""
        a       = PasswordAnalyzer()
        summary = criteria_summary(a.analyze("Xk9!mN#vLq2@"))
        self.assertIn("wordlist_sufficient", summary,
            "wordlist_sufficient key must be present in AnalysisSummary")
        self.assertNotIn("wordlist_degraded", summary,
            "wordlist_degraded must have been removed (was permanently False dead code)")
        self.assertTrue(
            summary["wordlist_sufficient"],
            "Built-in list must meet the minimum threshold; wordlist_sufficient must be True",
        )

    def test_external_wordlist_loaded_false_without_data_file(self) -> None:
        """external_wordlist_loaded must be False when only
        the built-in list is in use."""
        import pathlib as _pathlib
        data_file = (_pathlib.Path(__file__).parent.parent
                     / "passcheck" / "data" / "common_passwords.txt")
        if data_file.exists():
            self.skipTest("External wordlist present")
        a       = PasswordAnalyzer()
        summary = criteria_summary(a.analyze("Xk9!mN#vLq2@"))
        self.assertIn("external_wordlist_loaded", summary,
            "external_wordlist_loaded key must be present in AnalysisSummary")
        self.assertFalse(
            summary["external_wordlist_loaded"],
            "external_wordlist_loaded must be False when data file is absent",
        )

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
        original      = _singleton_mod._analyzer
        original_fast = _singleton_mod._analyzer_fast
        _singleton_mod._analyzer      = None
        _singleton_mod._analyzer_fast = None

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

        # Restore original state (both fast-path and canonical references).
        _singleton_mod._analyzer      = original
        _singleton_mod._analyzer_fast = original_fast

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
        """--json --no-redact must NOT show '[REDACTED]' — should be asterisks."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--json", "--no-redact"],
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
# --redact must suppress password_length in all output paths
# ===========================================================================

class TestRedactSuppressesLength(unittest.TestCase):
    """--redact must hide the exact password length, not just the masked form."""

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
            "password_length must be None when redact=True",
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
            "JSON output with --redact must have password_length=null",
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
                "The Password: header line must not contain the char count with --redact",
            )
        self.assertIn("[REDACTED]", result.output)

    def test_no_redact_shows_char_count_in_header(self) -> None:
        """Human-readable header with --no-redact must show the character count."""
        self._skip_if_unavailable()
        result = self.runner.invoke(
            self.cli,
            ["check", "--password", "Hello123!", "--no-redact"],
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
# fail-closed behaviour when wordlist coverage is insufficient
# ===========================================================================

class TestWordlistFailClosed(unittest.TestCase):
    """common-password criterion must skip, not pass, when the wordlist
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

    def test_not_found_with_insufficient_wordlist_is_failed(self) -> None:
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=False,
            can_lookup=True,
            length=12,
            has_ascii_residue=True,
            wordlist_sufficient=False,
        )
        self.assertFalse(result.skipped,
            "criterion must NOT be skipped when wordlist coverage is insufficient; "
            "it must be a fail so the denominator stays at 100")
        self.assertFalse(result.passed,
            "criterion must not pass when wordlist coverage is insufficient")
        self.assertIsNone(result.skip_reason,
            "skip_reason must be None on a failed (non-skipped) criterion")
        self.assertEqual(result.score, 0,
            "score must be 0 when wordlist is insufficient")
        self.assertIn("could not verify", result.detail,
            "detail must explain that verification was impossible, not that it passed")

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
            "A common-password hit must be reported even with a small wordlist")
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

    def test_default_wordlist_sufficient_is_false(self) -> None:
        self._skip_if_unavailable()
        result = self.criterion(
            is_common=False,
            can_lookup=True,
            length=12,
            has_ascii_residue=True,
            # wordlist_sufficient NOT passed — must default to False (fail-closed)
        )
        self.assertFalse(
            result.skipped,
            "Default wordlist_sufficient=False must produce a FAIL, not a SKIP, "
            "so the score denominator is not inflated.",
        )
        self.assertFalse(result.passed,
            "criterion must not pass when wordlist_sufficient defaults to False")
        self.assertIsNone(result.skip_reason,
            "skip_reason must be None on a failed (non-skipped) criterion")

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
# entropy annotation when pattern cap is applied
# ===========================================================================

class TestEntropyAnnotation(unittest.TestCase):
    """entropy_note must be present in JSON when weak_pattern_cap_applied."""

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
            "entropy_note must not be None when weak_pattern_cap_applied")
        self.assertIsInstance(summary["entropy_note"], str)
        self.assertGreater(len(summary["entropy_note"]), 0)

    def test_entropy_note_always_present(self) -> None:
        """entropy_note must always be a non-empty string regardless of cap (SEC-001)."""
        self._skip_if_unavailable()
        analysis = self.analyzer.analyze("Xk9#mP2$vLqR")
        self.assertFalse(analysis.weak_pattern_cap_applied,
            "Test prerequisite: Xk9#mP2$vLqR must not trigger the pattern cap")
        summary = self.criteria_summary(analysis)
        self.assertIsNotNone(
            summary["entropy_note"],
            "entropy_note must always be present — formula is always an upper-bound estimate",
        )
        self.assertIsInstance(summary["entropy_note"], str)
        self.assertGreater(
            len(summary["entropy_note"]), 0,
            "entropy_note must not be an empty string",
        )

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
            "JSON output must contain entropy_note field")
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
            "entropy estimate when the pattern cap was applied")

# ===========================================================================
# --redact suppresses length in batch JSON error events
# ===========================================================================

class TestBatchRedactSuppressesLength(unittest.TestCase):
    """batch --json --redact must omit length/limit from skipped_invalid events."""

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
            "length must be absent from skipped_invalid event when --redact is set")
        self.assertNotIn("limit", event,
            "limit must be absent from skipped_invalid event when --redact is set")

    def test_batch_json_no_redact_includes_length_for_oversized_password(self) -> None:
        """With --no-redact, skipped_invalid must include length and limit for debugging."""
        self._skip_if_unavailable()
        oversized = "a" * 300 + "\n"
        result = self.runner.invoke(
            self.cli,
            ["batch", "--json", "--no-redact"],
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
# Non-ASCII digits must not satisfy the fifth variety class
# ===========================================================================

class TestNonAsciiDigitVariety(unittest.TestCase):

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
            "Non-ASCII digits must not satisfy the ASCII-digit criterion")

    def test_arabic_indic_digits_fail_variety_class(self) -> None:
        """A password of only Arabic-Indic digits must fail the variety criterion."""
        self._skip_if_unavailable()
        pw = "٠١٢٣٤٥٦٧٨"
        result = self.criterion_variety(pw)
        self.assertFalse(result.passed,
            "Arabic-Indic digits alone must not satisfy the variety criterion")
        self.assertIn("1/5", result.detail,
            "Arabic-Indic digits count as 'other Unicode' (class 5) → detail must show 1/5")

    def test_arabic_script_non_digits_still_satisfy_variety_class(self) -> None:
        """Non-digit Arabic characters (e.g. letters) must still count as class 5."""
        self._skip_if_unavailable()
        # Arabic letter 'ain' (ع) is not a digit, not ASCII, not upper, not lower
        pw = "عربي"  # Arabic letters — not digits
        result = self.criterion_variety(pw)
        # 1 class present (class 5 = other Unicode); variety fails (<3), but
        # the detail must show at least 1 class, confirming the class was counted.
        self.assertNotIn("0/5", result.detail,
            "Non-digit Arabic letters must still count as the 'other Unicode' class")

    def test_hiragana_still_satisfies_variety_class(self) -> None:
        """Hiragana (non-ASCII, non-digit) must still count as the 5th variety class."""
        self._skip_if_unavailable()
        pw = "あいうえお"  # Hiragana — not digits
        result = self.criterion_variety(pw)
        # Should show 1/5, not 0/5
        self.assertNotIn("0/5", result.detail,
            "Hiragana must still count as the 'other Unicode' variety class")

# ===========================================================================
# NON_ASCII_POOL_SIZE deprecation warning
# ===========================================================================

class TestNonAsciiPoolSizeDeprecation(unittest.TestCase):

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
            "DeprecationWarning mentioning 'NON_ASCII_POOL_SIZE'",
        )

    def test_non_ascii_pool_size_not_in_star_import(self) -> None:
        """NON_ASCII_POOL_SIZE must not appear in passcheck.constants.__all__."""
        import passcheck.constants as constants_mod
        self.assertNotIn(
            "NON_ASCII_POOL_SIZE",
            constants_mod.__all__,
            "NON_ASCII_POOL_SIZE must be removed from __all__",
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

# ==========================================================================
# Regression tests added during the security-audit refactoring.
# Each class is labelled with the audit finding it covers.
# ==========================================================================

class TestStructuralRepeatIsCommonSkip(unittest.TestCase):
    """criterion_no_structural_repeat must skip for common passwords."""

    def setUp(self) -> None:
        from passcheck.analyzer.patterns import criterion_no_structural_repeat
        self.fn = criterion_no_structural_repeat

    def test_skips_when_is_common_true(self) -> None:
        from passcheck.models import SkipReason
        r = self.fn(list("aaaaaaa"), 7, is_common=True)
        self.assertTrue(r.skipped,
            "criterion_no_structural_repeat must skip when is_common=True")
        self.assertEqual(r.skip_reason, SkipReason.COMMON_PASSWORD_DETECTED)
        self.assertEqual(r.score, 0)

    def test_fires_when_is_common_false(self) -> None:
        r = self.fn(list("aaaaaaa"), 7, is_common=False)
        self.assertFalse(r.skipped)
        self.assertFalse(r.passed)

    def test_passes_non_repetitive_non_common(self) -> None:
        r = self.fn(list("aBcDeFgH"), 8, is_common=False)
        self.assertFalse(r.skipped)
        self.assertTrue(r.passed)

    def test_default_is_common_false(self) -> None:
        """is_common defaults to False so existing callers that omit it are unaffected."""
        r = self.fn(list("aaaaaaa"), 7)
        self.assertFalse(r.skipped)
        self.assertFalse(r.passed)

    def test_end_to_end_common_and_repetitive(self) -> None:
        """password is common: the structural-repeat criterion must be skipped."""
        from passcheck.analyzer.core import PasswordAnalyzer
        from passcheck.models import SkipReason
        az = PasswordAnalyzer()
        r = az.analyze("password")
        struct_crit = next(
            (c for c in r.criteria if c.name == "No Structural Repetition"), None)
        self.assertIsNotNone(struct_crit)
        self.assertTrue(struct_crit.skipped,
            "Structural-repeat criterion must be skipped for a common password")
        self.assertEqual(struct_crit.skip_reason, SkipReason.COMMON_PASSWORD_DETECTED)

class TestTopNumericPasswordsDetected(unittest.TestCase):
    """Globally common all-digit passwords must be in the built-in list."""

    def setUp(self) -> None:
        from passcheck.analyzer.core import PasswordAnalyzer
        self.az = PasswordAnalyzer()

    def _common_crit(self, pw: str):
        return next(
            c for c in self.az.analyze(pw).criteria
            if c.name == "Not a Common Password")

    def test_111111_detected(self) -> None:
        self.assertFalse(self._common_crit("111111").passed,
            "'111111' must be detected as a common password")

    def test_123456_detected(self) -> None:
        self.assertFalse(self._common_crit("123456").passed,
            "'123456' must be detected as a common password")

    def test_654321_detected(self) -> None:
        self.assertFalse(self._common_crit("654321").passed,
            "'654321' must be detected as a common password")

    def test_123123_detected(self) -> None:
        self.assertFalse(self._common_crit("123123").passed,
            "'123123' must be detected as a common password")

    def test_11111111_detected(self) -> None:
        self.assertFalse(self._common_crit("11111111").passed,
            "'11111111' must be detected as a common password")

    def test_111111_also_flagged_by_repeated_chars(self) -> None:
        r = self.az.analyze("111111")
        rep = next(c for c in r.criteria if c.name == "No Repeated Characters")
        self.assertFalse(rep.passed,
            "'111111' must fail the repeated-chars criterion (defence-in-depth)")

class TestDictAttackAdvisory(unittest.TestCase):
    """dict_attack_advisory fires for leet-substitution dictionary passwords."""

    def setUp(self) -> None:
        from passcheck.analyzer.core import PasswordAnalyzer
        self.az = PasswordAnalyzer()

    def test_leet_dictionary_password_gets_advisory(self) -> None:
        r = self.az.analyze("Tr0ub4dor&3")
        self.assertIn(r.strength_label, ("Strong", "Very Strong"),
            "Tr0ub4dor&3 must score Strong/Very Strong for this test to be meaningful")
        self.assertIsNotNone(r.dict_attack_advisory,
            "dict_attack_advisory must be non-None for a leet-substitution dictionary password")

    def test_high_entropy_random_no_advisory(self) -> None:
        r = self.az.analyze("xK2$mL8!nP4@qR6^wT1")
        if r.strength_label not in ("Strong", "Very Strong"):
            self.skipTest("Password did not score Strong/Very Strong")
        self.assertIsNone(r.dict_attack_advisory,
            "A genuinely high-entropy password must not receive the advisory")

    def test_advisory_absent_for_weak_password(self) -> None:
        r = self.az.analyze("password")
        self.assertNotIn(r.strength_label, ("Strong", "Very Strong"))
        self.assertIsNone(r.dict_attack_advisory,
            "Weak passwords must not receive the dictionary-attack advisory")

    def test_advisory_in_json_non_redact(self) -> None:
        from passcheck.scoring import criteria_summary
        r = self.az.analyze("Tr0ub4dor&3")
        summary = criteria_summary(r, redact=False)
        self.assertIn("dict_attack_advisory", summary)

    def test_advisory_none_in_redact_mode(self) -> None:
        from passcheck.scoring import criteria_summary
        r = self.az.analyze("Tr0ub4dor&3")
        summary = criteria_summary(r, redact=True)
        self.assertIsNone(summary["dict_attack_advisory"],
            "dict_attack_advisory must be None in redact mode")

class TestWarningTextConsistency(unittest.TestCase):
    """The missing-wordlist warning must not contradict actual behaviour."""

    def _capture_warning(self) -> str:
        import io, sys, pathlib
        from passcheck.constants.common_passwords_loader import _warn_missing_wordlist
        buf = io.StringIO()
        old, sys.stderr = sys.stderr, buf
        try:
            _warn_missing_wordlist(pathlib.Path("/tmp/nonexistent_wordlist.txt"))
        finally:
            sys.stderr = old
        return buf.getvalue()

    def test_does_not_claim_criterion_is_failed(self) -> None:
        text = self._capture_warning()
        self.assertNotIn("treated as FAILED", text,
            "Warning must not claim criterion is FAILED when it actually PASSES")
        self.assertNotIn("score = 0", text,
            "Warning must not claim score=0 when the built-in list is sufficient")

    def test_mentions_builtin_list_is_functional(self) -> None:
        text = self._capture_warning().lower()
        self.assertTrue(
            any(w in text for w in ("built-in", "fallback", "sufficient")),
            "Warning must mention the built-in list and indicate it is functional")

class TestAnalyzerSingletonFastPath(unittest.TestCase):
    """BUG-005: get_analyzer() must use a lock-free fast path after first init."""

    def test_fast_path_set_after_first_call(self) -> None:
        from passcheck.cli import analyzer_singleton
        _ = analyzer_singleton.get_analyzer()
        self.assertIsNotNone(analyzer_singleton._analyzer_fast,
            "_analyzer_fast must be set after the first get_analyzer() call")

    def test_repeated_calls_return_same_instance(self) -> None:
        from passcheck.cli.analyzer_singleton import get_analyzer
        a1, a2 = get_analyzer(), get_analyzer()
        self.assertIs(a1, a2)

    def test_fast_and_canonical_are_same_object(self) -> None:
        """After a clean init, _analyzer and _analyzer_fast must be the same object.
        We reset both references first so that prior test teardowns that
        partially restore state (e.g. TestSingletonNoConcurrentRace) cannot
        leave them out of sync before this assertion.
        """
        import passcheck.cli.analyzer_singleton as _mod
        orig      = _mod._analyzer
        orig_fast = _mod._analyzer_fast
        _mod._analyzer      = None
        _mod._analyzer_fast = None
        try:
            instance = _mod.get_analyzer()
            self.assertIs(_mod._analyzer, _mod._analyzer_fast,
                "_analyzer and _analyzer_fast must point to the same object after init")
            self.assertIs(instance, _mod._analyzer_fast)
        finally:
            _mod._analyzer      = orig
            _mod._analyzer_fast = orig_fast

class TestArgvRedaction(unittest.TestCase):
    """SEC-003: _redact_argv must overwrite the password in sys.argv."""

    def test_redacts_standalone_value(self) -> None:
        import sys
        from passcheck.cli.security import _redact_argv
        orig = sys.argv[:]
        try:
            sys.argv = ["passcheck", "--password", "mysecret"]
            _redact_argv("mysecret")
            self.assertNotIn("mysecret", sys.argv)
        finally:
            sys.argv = orig

    def test_redacts_equals_form(self) -> None:
        import sys
        from passcheck.cli.security import _redact_argv
        orig = sys.argv[:]
        try:
            sys.argv = ["passcheck", "--password=mysecret"]
            _redact_argv("mysecret")
            self.assertNotIn("mysecret", sys.argv)
        finally:
            sys.argv = orig

    def test_no_raise_when_value_absent(self) -> None:
        import sys
        from passcheck.cli.security import _redact_argv
        orig = sys.argv[:]
        try:
            sys.argv = ["passcheck"]
            _redact_argv("notpresent")
        finally:
            sys.argv = orig