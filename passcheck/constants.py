from __future__ import annotations

import logging  as _logging
import pathlib  as _pathlib
import random   as _random
import threading as _threading
from types import MappingProxyType

from .utils import normalise_for_lookup as _normalise_for_lookup

__all__ = [
    "SCORE_WEIGHTS",
    "LENGTH_MINIMUM",
    "LENGTH_GOOD",
    "LENGTH_EXCELLENT",
    "LENGTH_MAXIMUM",
    "ENTROPY_GOOD_THRESHOLD",
    "NON_ASCII_POOL_SIZE",
    "REPEATED_CHAR_RATIO",
    "SHANNON_WEIGHT",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_SET",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "KEYBOARD_PATTERNS",
    "get_common_passwords",
    "CHAR_UNIQUENESS_MIN_RATIO",
    "CHAR_VARIETY_MIN_CLASSES",
    "CHAR_CLASS_COUNT",
]

_logger = _logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

SCORE_WEIGHTS: MappingProxyType[str, int] = MappingProxyType({
    "length_minimum":       9,
    "length_good":          9,
    "length_excellent":     4,
    "has_uppercase":        7,
    "has_lowercase":        7,
    "has_digit":            9,
    "has_special":         12,
    "char_variety":         9,
    "char_uniqueness":      4,
    "no_common_password":   9,
    "no_keyboard_pattern":  9,
    "no_repeated_chars":    4,
    "entropy":              8,
})

if not all(v >= 0 for v in SCORE_WEIGHTS.values()):
    raise ValueError("All SCORE_WEIGHTS values must be non-negative.")

_weights_total = sum(SCORE_WEIGHTS.values())
if _weights_total != 100:
    raise ValueError(
        f"SCORE_WEIGHTS must sum to exactly 100 so that a perfect password "
        f"reaches a score of exactly 100. Current sum: {_weights_total}."
    )
del _weights_total

_EXPECTED_WEIGHT_KEYS: frozenset[str] = frozenset({
    "length_minimum",
    "length_good",
    "length_excellent",
    "has_uppercase",
    "has_lowercase",
    "has_digit",
    "has_special",
    "char_variety",
    "char_uniqueness",
    "no_common_password",
    "no_keyboard_pattern",
    "no_repeated_chars",
    "entropy",
})

_missing_weight_keys = _EXPECTED_WEIGHT_KEYS - frozenset(SCORE_WEIGHTS)
_extra_weight_keys   = frozenset(SCORE_WEIGHTS) - _EXPECTED_WEIGHT_KEYS
if _missing_weight_keys or _extra_weight_keys:
    raise ValueError(
        f"SCORE_WEIGHTS key mismatch. "
        f"Missing keys: {sorted(_missing_weight_keys)}. "
        f"Unexpected keys: {sorted(_extra_weight_keys)}. "
        "Ensure every criterion key in analyzer.py has a corresponding entry "
        "in SCORE_WEIGHTS and vice versa."
    )
del _missing_weight_keys, _extra_weight_keys, _EXPECTED_WEIGHT_KEYS

# ---------------------------------------------------------------------------
# Length thresholds
# ---------------------------------------------------------------------------

LENGTH_MINIMUM:   int = 8
LENGTH_GOOD:      int = 12
LENGTH_EXCELLENT: int = 20
LENGTH_MAXIMUM:   int = 128

if not (LENGTH_MINIMUM < LENGTH_GOOD < LENGTH_EXCELLENT < LENGTH_MAXIMUM):
    raise ValueError(
        "Length thresholds must be strictly increasing: "
        f"LENGTH_MINIMUM={LENGTH_MINIMUM}, LENGTH_GOOD={LENGTH_GOOD}, "
        f"LENGTH_EXCELLENT={LENGTH_EXCELLENT}, LENGTH_MAXIMUM={LENGTH_MAXIMUM}."
    )

# ---------------------------------------------------------------------------
# Entropy (bits)
# ---------------------------------------------------------------------------

ENTROPY_GOOD_THRESHOLD: float = 50.0

SHANNON_WEIGHT: float = 0.6   # blend factor: 40 % pool, 60 % Shannon

if not (0.0 < SHANNON_WEIGHT < 1.0):
    raise ValueError(f"SHANNON_WEIGHT must be in (0, 1), got {SHANNON_WEIGHT!r}.")

NON_ASCII_POOL_SIZE: int = 32_768

# ---------------------------------------------------------------------------
# Repeated-character threshold
# ---------------------------------------------------------------------------

REPEATED_CHAR_RATIO: float = 0.4  # fails at >= this ratio (strict less-than check)

if not (0.0 < REPEATED_CHAR_RATIO < 1.0):
    raise ValueError(
        f"REPEATED_CHAR_RATIO must be in (0, 1), got {REPEATED_CHAR_RATIO!r}."
    )

# ---------------------------------------------------------------------------
# Composition thresholds
# ---------------------------------------------------------------------------

CHAR_UNIQUENESS_MIN_RATIO: float = 0.6

if not (0.0 < CHAR_UNIQUENESS_MIN_RATIO <= 1.0):
    raise ValueError(
        f"CHAR_UNIQUENESS_MIN_RATIO must be in (0, 1], "
        f"got {CHAR_UNIQUENESS_MIN_RATIO!r}."
    )

CHAR_CLASS_COUNT: int = 5

CHAR_VARIETY_MIN_CLASSES: int = 3

if not (2 <= CHAR_VARIETY_MIN_CLASSES <= CHAR_CLASS_COUNT):
    raise ValueError(
        f"CHAR_VARIETY_MIN_CLASSES must be in [2, {CHAR_CLASS_COUNT}] "
        f"(the analyser measures at most {CHAR_CLASS_COUNT} character classes). "
        f"Got {CHAR_VARIETY_MIN_CLASSES!r}."
    )

# ---------------------------------------------------------------------------
# Strength bands  (threshold, label, colour_key) — sorted descending by threshold
# ---------------------------------------------------------------------------

# Immutable tuple so post-import mutation raises TypeError.
STRENGTH_BANDS: tuple[tuple[int, str, str], ...] = (
    (80, "Very Strong", "bright_green"),
    (60, "Strong",      "green"),
    (40, "Medium",      "yellow"),
    (20, "Weak",        "red"),
    ( 0, "Very Weak",   "bright_red"),
)

_sorted_bands = tuple(sorted(STRENGTH_BANDS, key=lambda t: t[0], reverse=True))
if STRENGTH_BANDS != _sorted_bands:
    raise ValueError(
        "STRENGTH_BANDS must be sorted by threshold descending. "
        f"Expected order: {list(_sorted_bands)}."
    )
del _sorted_bands

if STRENGTH_BANDS[-1][0] != 0:
    raise ValueError(
        "STRENGTH_BANDS must contain a catch-all entry with threshold 0 "
        f"as its last element. Last entry found: {STRENGTH_BANDS[-1]}."
    )

# Derive the set of valid colour keys directly from the bands definition.
VALID_COLOUR_KEYS: frozenset[str] = frozenset(colour for _, _, colour in STRENGTH_BANDS)

# ---------------------------------------------------------------------------
# Special characters
# ---------------------------------------------------------------------------

SPECIAL_CHARS: str = """ !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
SPECIAL_CHARS_INCLUDES_SPACE: bool = " " in SPECIAL_CHARS
SPECIAL_CHARS_SET: frozenset[str] = frozenset(SPECIAL_CHARS)

# ---------------------------------------------------------------------------
# Keyboard walk patterns
# ---------------------------------------------------------------------------

_KEYBOARD_PATTERN_MIN_LEN: int = 4

_BASE_KEYBOARD_PATTERNS: tuple[str, ...] = (
    # ── Horizontal rows (left-to-right) ─────────────────────────────────────
    "qwerty", "qwertz", "azerty",
    # Middle row
    "asdfgh",
    # Bottom row
    "zxcvbn",
    "ytrewq",        # reverse of qwerty top row
    "poiuyt",        # right half of top row, reversed
    "lkjhgf",        # right half of middle row, reversed
    "lkjhgfdsa",     # full middle row, reversed
    "mnbvcxz",       # bottom row, reversed

    # ── Numeric sequences ────────────────────────────────────────────────────
    "123456",
    "234567", "345678", "456789", "567890",
    "987654", "876543", "765432",
    "0987654321",

    # ── Alphabetical sequences ───────────────────────────────────────────────
    "abcdef", "abcdefg", "abcdefgh",

    # ── Vertical single-column walks ─────────────────────────────────────────
    "1qaz", "2wsx", "3edc",

    # ── Multi-column vertical walks ──────────────────────────────────────────
    "qazwsx", "wsxedc", "edcrfv", "rfvtgb",

    # ── Mixed numeric-alpha diagonal walks ───────────────────────────────────
    "1q2w3e", "q2w3e4", "1q2w3e4r",

    # ── Shifted-key numeric sequences (Shift+1..6 on QWERTY = !@#$%^) ───────
    "!@#$%^", "!@#$%^&",

    # ── Numpad walks ─────────────────────────────────────────────────────────
    "7894561230",    # numpad rows top-to-bottom
    "0321654987",    # numpad rows bottom-to-top
    "741852963",     # numpad left column → middle → right (vertical sweep)
    "369258147",     # numpad right column → middle → left
    "159357",        # numpad diagonal
    "753159",        # reverse diagonal
)

# Expand each base pattern to include its reverse; deduplicate while preserving
# order; drop any variant shorter than the minimum length.
KEYBOARD_PATTERNS: tuple[str, ...] = tuple(dict.fromkeys(
    variant
    for base in _BASE_KEYBOARD_PATTERNS
    for variant in (base, base[::-1])
    if len(variant) >= _KEYBOARD_PATTERN_MIN_LEN
))

_short_patterns = [p for p in KEYBOARD_PATTERNS if len(p) < _KEYBOARD_PATTERN_MIN_LEN]
if _short_patterns:
    raise ValueError(
        f"Every KEYBOARD_PATTERNS entry must be at least "
        f"{_KEYBOARD_PATTERN_MIN_LEN} characters. "
        f"Offending entries: {_short_patterns}."
    )
del _short_patterns

# ---------------------------------------------------------------------------
# Common passwords list
# ---------------------------------------------------------------------------

_RAW_BUILTIN_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "0.0.0.000", "0.0.000", "0000", "00000",
    "000000", "0000000", "00000000", "000000000",
    "0000000000", "0000007", "000007", "0007",
    "007007", "0101", "010101", "01011",
    "01011900", "01011960", "01011970", "01011971",
    "01011973", "01011974", "01011976", "01011978",
    "01011979", "01011980", "01011981", "01011985",
    "01011986", "01011990", "01011991", "01011994",
    "01011995", "01012000", "01012001", "01012009",
    "01012010", "01012011", "010180", "010191",
    "010203", "01021988", "01021989", "01021990",
    "01031983", "01031984", "01031985", "01031986",
    "01031988", "01031989", "01041985", "01041987",
    "01041988", "01041990", "01041992", "01051986",
    "01051988", "01051989", "01061986", "01061987",
    "01061988", "01061990", "01071986", "01071987",
    "01081989", "01081990", "01091985", "01091987",
    "01121986", "01121987", "01121988", "012345",
    "0123456", "0123456789", "0192837465", "02011975",
    "02011980", "02011981", "02011982", "02011983",
    "02011984", "02011989", "02021971", "02021973",
    "2001", "2002", "2003", "2004",
    "2005", "2006", "2007", "2008",
    "2009", "2010", "2011", "2012",
    "aircraft", "airforce", "airman", "airport",
    "alabama", "alan", "albert", "alberto",
    "alexander", "alexandra", "alexandria",
    "alexei", "alfred", "alicia", "allen",
    "alliance", "allison", "altamira", "amanda",
    "amateur", "ambers", "amelia", "america",
    "americo", "amigo", "amores", "amsterdam",
    "andrea", "andrew", "andy", "angel",
    "angel1", "angela", "angeles", "angelica",
    "angelina", "angelo", "angie", "aninha",
    "anita", "anna", "annabell", "annette",
    "anthony", "antonio", "anything", "apollo",
    "apple", "april", "archer", "arsenal",
    "arthur", "asdf", "asdfghjkl",
    "ashley", "assman", "aston", "atlantis",
    "atlas", "austin", "australia", "autumn",
    "avatar", "baboon", "badboy", "badman",
    "bailey", "banana", "barney", "baseball",
    "batman", "beavis", "bender", "berlin",
    "bingo", "birgit", "birdie", "bismarck",
    "biteme", "bitches", "blink182", "blonde",
    "blossom", "blubber", "bluebird", "bobcat",
    "booboo", "booger", "bookie", "boston",
    "boxer", "brandon", "brasil", "bridge",
    "broncos", "bronson", "brownie", "brutus",
    "bubbles", "buddy", "bulldog", "bullet",
    "buster", "butter", "camelot", "cameron",
    "camilla", "camping", "captain", "carlos",
    "carmen", "caroline", "casper", "cassie",
    "castle", "cavalry", "champion", "charlie",
    "cheese", "chelsea", "cheryl", "chester",
    "chicken", "chocolat", "chocolate", "chris",
    "christian", "christmas", "chuck", "cindy",
    "cisco", "clement", "cleopatra", "clooney",
    "cloud9", "cobain", "cocacola", "coffee",
    "comet", "commander", "compaq", "computer",
    "cookies", "corona", "cowboy", "crash",
    "crazy", "creative", "criminal", "crystal",
    "cumshot", "dakota", "dallas", "daniel",
    "danielle", "darkside", "darwin", "david",
    "davidson", "debbie", "december", "delta",
    "denise", "denmark", "dexter", "diamond",
    "diandra", "diego", "dino", "dinosaur",
    "dirty", "doctor", "doggy", "dolphin",
    "donald", "donkey", "dragoon", "dragon",
    "dreamer", "driving", "drummer", "eagle",
    "eagles", "eclipse", "edward", "einstein",
    "elephant", "elizabeth", "emerald", "emerson",
    "eminem", "england", "enigma", "enter",
    "eric", "erotic", "escape", "everton",
    "extreme", "falcon", "fantasy", "ferrari",
    "fighter", "flower", "forever", "france",
    "frank", "frank1", "fred", "freedom",
    "fuckyou", "gandalf", "george", "ghost",
    "ginger", "golden", "goober", "google",
    "grace", "green", "guitar", "gunner",
    "hammer", "happy", "harley", "harold",
    "hawaii", "health", "hello", "helpme",
    "hockey", "hooters", "hornet", "hunter",
    "iloveyou", "imagine", "internet", "ireland",
    "istanbul", "jack", "jackie", "jackson",
    "jaguar", "jasmine", "jasper", "jessica",
    "johnny", "jordan", "joseph", "joshua",
    "junior", "kevin", "killer", "kitten",
    "knight", "ladies", "lambda", "laptop",
    "laser", "latin", "latino", "lauren",
    "leather", "letmein", "lewis", "lincoln",
    "liverpool", "london", "lonely", "lovely",
    "lover", "lucky", "madrid", "magic",
    "magnum", "manual", "marina", "mario",
    "martin", "master", "matrix", "maverick",
    "maximum", "maxwell", "melissa", "michael",
    "mickey", "mike", "miller", "mirror",
    "monkey", "monster", "morgan", "mortal",
    "mother", "muffin", "mustang", "nathan",
    "neptune", "newman", "nicholas", "nichole",
    "nintendo", "nirvana", "nobody", "noodle",
    "nothing", "nugget", "october", "office",
    "oliver", "oracle", "orange", "orchid",
    "oregon", "orlando", "outside", "oxford",
    "pacific", "panther", "parker", "parola",
    "parool", "passwd", "password", "password1",
    "password12", "password123", "patricia", "patrick",
    "peaches", "peanut", "pelican", "penguin",
    "perfect", "phoenix", "pickle", "pioneer",
    "pirate", "player", "please", "pokemon",
    "police", "poncho", "poopie", "porsche",
    "potato", "prince", "princess", "private",
    "purple", "python", "qwerty123",
    "qwertyui", "qwertyuiop", "rabbit", "rachael",
    "rachel", "racing", "raiders", "rainbow",
    "ranger", "raymond", "redskin", "redskins",
    "richard", "robert", "rocket", "roger",
    "roland", "ronaldo", "ronnie", "russia",
    "russian", "sacred", "sailor", "samson",
    "sandra", "saturn", "scooby", "scooter",
    "scotty", "secret", "secure", "semper",
    "server", "shadow", "shania", "shannon",
    "shark", "silver", "simple", "sister",
    "skipper", "slayer", "sleepy", "smokey",
    "snoopy", "soccer", "softball", "soldier",
    "sophie", "spam", "sparky", "sparta",
    "spider", "spirit", "spring", "squirt",
    "startrek", "starwars", "steven", "stress",
    "strong", "student", "summer", "summer99",
    "summit", "sundance", "sunday", "sundevil",
    "sunfire", "sunflower", "sunny", "sunny1",
    "sunrise", "sunset", "sunshine", "super",
    "super1", "super12", "super123", "superman",
    "superstar", "support", "surfer", "surfing",
    "survivor", "susan", "sushi", "suzuki",
    "sweden", "sweet", "sweetie", "sweetness",
    "sweetpea", "swimming", "swordfish", "sydney",
    "sylvia", "synergy", "system", "tabasco",
    "taylor", "teacher", "tennis", "tequila",
    "terminator", "test", "test1", "test123",
    "testing", "testtest", "texas", "thanks",
    "thomas", "thompson", "thunder", "tiger",
    "tigers", "tigger", "timothy", "tinkerbell",
    "titanic", "toad", "tobias", "tomcat",
    "tonight", "tony", "toyota", "tracker",
    "trinity", "trojan", "trouble", "tucker",
    "turkey", "turner", "turtle", "tweety",
    "twilight", "twister", "twitter", "tyler",
    "ubuntu", "ultimate", "unknown", "user",
    "user123", "username", "vacation", "vader",
    "vampire", "vanessa", "vanilla", "venezuela",
    "venus", "victor", "victoria", "victory",
    "viking", "vikings", "violet", "viper",
    "virginia", "welcome", "welcome1", "wendy",
    "western", "whiskey", "whisper", "william",
    "williams", "willow", "windows", "winner",
    "winston", "winter", "wisdom", "wizard",
    "wolfpack", "wolverine", "wolves", "wonder",
    "woody", "world", "wwwwww", "xbox360",
    "yamaha", "yankees", "yellow", "yoyoyo",
    "zachary", "zebra", "zeppelin", "zodiac",
    "zombie", "zxcasdqwe", "zxcv", "zxcvbn1",
    "zxcvbnm", "zxcvbnm123", "zxczxc", "zxzxzx",
    "zzzzzz", "zzzzzzz", "zzzzzzzz",
})

# Validate raw entries: all must be lowercase ASCII before expansion.
_non_canonical = [
    e for e in _RAW_BUILTIN_COMMON_PASSWORDS
    if not e.isascii() or e != e.lower()
]
if _non_canonical:
    raise ValueError(
        "_RAW_BUILTIN_COMMON_PASSWORDS entries must be lowercase ASCII. "
        f"Non-canonical entries: {sorted(_non_canonical)[:10]}"
        + ("..." if len(_non_canonical) > 10 else "")
    )
del _non_canonical

def _expand_builtin_passwords(raw: frozenset[str]) -> frozenset[str]:
    """Expand each raw entry into all normalised lookup variants."""
    expanded: set[str] = set()
    for entry in raw:
        expanded.update(v for v in _normalise_for_lookup(entry) if v)
    return frozenset(expanded)

_BUILTIN_COMMON_PASSWORDS: frozenset[str] = _expand_builtin_passwords(
    _RAW_BUILTIN_COMMON_PASSWORDS
)

_MAX_COMMON_PASSWORDS_FILE_BYTES: int = 50 * 1024 * 1024  # 50 MB
_MIN_EXPECTED_COMMON_PASSWORDS: int = 100

def _load_common_passwords() -> frozenset[str]:
    """Load common passwords from an external file, falling back to the built-in set."""
    data_path = _pathlib.Path(__file__).parent / "data" / "common_passwords.txt"

    if not data_path.exists():
        _logger.warning(
            "Common passwords data file not found at %s. "
            "Using the built-in fallback list (%d variant entries). "
            "For proper coverage, ship data/common_passwords.txt with at least "
            "the SecLists top-10 000 password list "
            "(https://github.com/danielmiessler/SecLists).",
            data_path,
            len(_BUILTIN_COMMON_PASSWORDS),
        )
        return _BUILTIN_COMMON_PASSWORDS

    entries_set: set[str] = set()
    raw_count   = 0

    try:
        total_bytes = 0
        with data_path.open("rb") as fh:
            for raw_line_bytes in fh:
                total_bytes += len(raw_line_bytes)
                if total_bytes > _MAX_COMMON_PASSWORDS_FILE_BYTES:
                    _logger.warning(
                        "Common passwords file at %s exceeded the safety cap "
                        "(~%d MB) after reading ~%d bytes. "
                        "Using the %d entries loaded so far, merged with the "
                        "built-in list.  Split the file or raise "
                        "_MAX_COMMON_PASSWORDS_FILE_BYTES if intentional.",
                        data_path,
                        _MAX_COMMON_PASSWORDS_FILE_BYTES // (1024 * 1024),
                        total_bytes,
                        len(entries_set),
                    )
                    break

                # Decode each line individually so a single bad line doesn't
                # abort the entire load (graceful degradation).
                try:
                    raw_line = raw_line_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    _logger.debug(
                        "Skipped a line in %s that could not be decoded as UTF-8.",
                        data_path,
                    )
                    continue

                raw_entry = raw_line.strip()
                if not raw_entry:
                    continue
                raw_count += 1

                entries_set.update(_normalise_for_lookup(raw_entry))

    except (OSError, ValueError) as exc:
        _logger.warning(
            "Could not read common passwords from %s (%s). "
            "Falling back to the built-in list (%d variant entries).",
            data_path, exc, len(_BUILTIN_COMMON_PASSWORDS),
        )
        return _BUILTIN_COMMON_PASSWORDS

    loaded = frozenset(entries_set)
    result = loaded | _BUILTIN_COMMON_PASSWORDS

    _logger.debug(
        "Loaded %d raw entries from %s; expanded to %d file variants; "
        "%d built-in variant entries; %d total after merge.",
        raw_count, data_path, len(loaded),
        len(_BUILTIN_COMMON_PASSWORDS), len(result),
    )
    return result

def _debug_log_pattern_overlaps(
    loaded: frozenset[str],
    *,
    sample_size: int = 500,
    seed:        int = 42,
) -> None:
    """Log keyboard-pattern / common-password overlaps using a deterministic sample."""
    _rng    = _random.Random(seed)
    sample  = _rng.sample(sorted(loaded), min(sample_size, len(loaded)))
    overlaps = [
        (pattern, entry)
        for pattern in KEYBOARD_PATTERNS
        for entry in sample
        if pattern in entry and pattern != entry
    ]
    if overlaps:
        preview    = overlaps[:10]
        extra      = len(overlaps) - len(preview)
        extra_note = f"\n  ...and {extra} more" if extra else ""
        _logger.debug(
            "KEYBOARD_PATTERNS substrings found inside COMMON_PASSWORDS sample "
            "(double penalty handled by skip logic):\n%s%s",
            "\n".join(
                f"  pattern {p!r} found inside common password {e!r}"
                for p, e in preview
            ),
            extra_note,
        )

# ---------------------------------------------------------------------------
# Common-password cache
# ---------------------------------------------------------------------------

_COMMON_PASSWORDS_CACHE: frozenset[str] | None = None
_COMMON_PASSWORDS_LOCK:  _threading.Lock       = _threading.Lock()

def get_common_passwords() -> frozenset[str]:
    """Return the merged common-password frozenset, loading it on first call."""
    global _COMMON_PASSWORDS_CACHE

    if _COMMON_PASSWORDS_CACHE is not None:
        return _COMMON_PASSWORDS_CACHE

    with _COMMON_PASSWORDS_LOCK:
        # Re-check inside the lock: another thread may have completed
        # initialisation while we were waiting to acquire it.
        if _COMMON_PASSWORDS_CACHE is not None:
            return _COMMON_PASSWORDS_CACHE

        try:
            loaded = _load_common_passwords()

            # Validate: all normalised entries must be lower-case.
            _mixed_case = [e for e in loaded if e != e.lower()]
            if _mixed_case:
                _sorted_bad = sorted(_mixed_case)
                _suffix     = "..." if len(_sorted_bad) > 10 else ""
                raise ValueError(
                    f"All COMMON_PASSWORDS entries must be lower-case. "
                    f"Offending entries: {_sorted_bad[:10]}{_suffix}"
                )

            # Sanity check: a suspiciously small merged set means common-password
            # detection coverage is severely degraded.
            if len(loaded) < _MIN_EXPECTED_COMMON_PASSWORDS:
                _logger.warning(
                    "Common passwords set has only %d entries (expected at "
                    "least %d). Common-password detection coverage may be "
                    "severely degraded.",
                    len(loaded), _MIN_EXPECTED_COMMON_PASSWORDS,
                )

            # Overlap with keyboard patterns — informational only; double-penalty
            # is already prevented by the skip logic in PasswordAnalyzer.
            _overlap = frozenset(KEYBOARD_PATTERNS) & loaded
            if _overlap:
                _logger.debug(
                    "Entries appear in both KEYBOARD_PATTERNS and COMMON_PASSWORDS "
                    "(double penalty prevented by skip logic): %s",
                    sorted(_overlap),
                )

            if _logger.isEnabledFor(_logging.DEBUG):
                _debug_log_pattern_overlaps(loaded)

            _COMMON_PASSWORDS_CACHE = loaded

        except (OSError, ValueError, UnicodeDecodeError, MemoryError) as exc:
            _logger.warning(
                "Unexpected error while loading or validating the common passwords "
                "list (%s: %s). Falling back to the built-in list (%d variant "
                "entries). The tool will continue to function with reduced coverage.",
                type(exc).__name__,
                exc,
                len(_BUILTIN_COMMON_PASSWORDS),
            )
            _COMMON_PASSWORDS_CACHE = _BUILTIN_COMMON_PASSWORDS

        # Return from inside the lock — _COMMON_PASSWORDS_CACHE is guaranteed
        # to be set by both branches of the try/except above.
        return _COMMON_PASSWORDS_CACHE