from __future__ import annotations

import logging as _logging
import pathlib as _pathlib

__all__ = [
    "SCORE_WEIGHTS",
    "LENGTH_MINIMUM",
    "LENGTH_GOOD",
    "LENGTH_EXCELLENT",
    "LENGTH_MAXIMUM",
    "ENTROPY_GOOD_THRESHOLD",
    "REPEATED_CHAR_RATIO",
    "SHANNON_WEIGHT",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "SPECIAL_CHARS",
    "KEYBOARD_PATTERNS",
    "COMMON_PASSWORDS",
]

_log = _logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
SCORE_WEIGHTS: dict[str, int] = {
    "length_minimum":      10,
    "length_good":         10,
    "length_excellent":     5,
    "has_uppercase":       10,
    "has_lowercase":        5,
    "has_digit":           10,
    "has_special":         15,
    "char_variety":        10,
    "char_uniqueness":      5,
    "no_common_password":  10,
    "no_keyboard_pattern": 10,
    "no_repeated_chars":    5,
    "entropy_bonus":       10,
}

if not all(v >= 0 for v in SCORE_WEIGHTS.values()):
    raise ValueError("All SCORE_WEIGHTS values must be non-negative.")
_weights_total = sum(SCORE_WEIGHTS.values())
if _weights_total < 100:
    raise ValueError(
        f"SCORE_WEIGHTS sum to {_weights_total}, must be >= 100 "
        "so that a perfect password can reach a score of 100."
    )
del _weights_total

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
SHANNON_WEIGHT:         float = 0.4

if not (0.0 < SHANNON_WEIGHT < 1.0):
    raise ValueError(f"SHANNON_WEIGHT must be in (0, 1), got {SHANNON_WEIGHT!r}.")

# ---------------------------------------------------------------------------
# Repeated characters
# ---------------------------------------------------------------------------
REPEATED_CHAR_RATIO: float = 0.4

if not (0.0 < REPEATED_CHAR_RATIO < 1.0):
    raise ValueError(f"REPEATED_CHAR_RATIO must be in (0, 1), got {REPEATED_CHAR_RATIO!r}.")

# ---------------------------------------------------------------------------
# Strength bands
# ---------------------------------------------------------------------------
STRENGTH_BANDS: list[tuple[int, str, str]] = [
    (80, "Very Strong", "bright_green"),
    (60, "Strong",      "green"),
    (40, "Medium",      "yellow"),
    (20, "Weak",        "red"),
    ( 0, "Very Weak",   "bright_red"),
]

_sorted_bands = sorted(STRENGTH_BANDS, key=lambda t: t[0], reverse=True)
if STRENGTH_BANDS != _sorted_bands:
    raise ValueError(
        "STRENGTH_BANDS must be sorted by threshold descending. "
        f"Expected order: {_sorted_bands}."
    )
del _sorted_bands

if STRENGTH_BANDS[-1][0] != 0:
    raise ValueError(
        "STRENGTH_BANDS must contain a catch-all entry with threshold 0 "
        f"as its last element. Last entry found: {STRENGTH_BANDS[-1]}."
    )

VALID_COLOUR_KEYS: frozenset[str] = frozenset(colour for _, _, colour in STRENGTH_BANDS)

# ---------------------------------------------------------------------------
# Special characters
# ---------------------------------------------------------------------------
SPECIAL_CHARS: str = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Keyboard walk patterns.
# ---------------------------------------------------------------------------

# Internal guard — NOT part of the public API (removed from __all__).
_KEYBOARD_PATTERN_MIN_LEN: int = 4

_BASE_KEYBOARD_PATTERNS: tuple[str, ...] = (
    # Horizontal rows
    "qwerty", "qwertz", "azerty",
    # Middle row
    "asdfgh",
    # Bottom row
    "zxcvbn",
    # Numeric sequences
    "123456",
    "234567", "345678", "456789", "567890",
    "987654", "876543", "765432",
    "0987654321",
    # Alphabetical sequences
    "abcdef", "abcdefg", "abcdefgh",
    # Vertical column walks
    "1qaz", "2wsx", "3edc",
)

# Generate forward + reverse for every base pattern, deduplicate while
# preserving order, and enforce the minimum length constraint.
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
# Common passwords list.
# ---------------------------------------------------------------------------
_BUILTIN_COMMON_PASSWORDS: frozenset[str] = frozenset({
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
    "alexand", "alexander", "alexandra", "alexandria",
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
    "tigers", "tigger", "timothy", "tinkerbe",
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

def _load_common_passwords() -> frozenset[str]:
    """Load common passwords from an external file, or fall back to built-in set."""
    data_path = _pathlib.Path(__file__).parent / "data" / "common_passwords.txt"
    if not data_path.exists():
        _log.debug(
            "Common passwords data file not found at %s. "
            "Using the built-in fallback list (%d entries). "
            "For better coverage, ship data/common_passwords.txt with at least "
            "the SecLists top-10 000 password list.",
            data_path,
            len(_BUILTIN_COMMON_PASSWORDS),
        )
        return _BUILTIN_COMMON_PASSWORDS

    entries: list[str] = []
    bad_case: list[str] = []
    for raw_line in data_path.read_text("utf-8").splitlines():
        entry = raw_line.strip()
        if not entry:
            continue
        if entry != entry.lower():
            bad_case.append(entry)
        else:
            entries.append(entry)

    if bad_case:
        _log.warning(
            "common_passwords.txt contains %d entries that are not fully "
            "lower-cased and have been skipped: %s%s",
            len(bad_case),
            bad_case[:10],
            "..." if len(bad_case) > 10 else "",
        )

    loaded = frozenset(entries)
    _log.debug("Loaded %d common passwords from %s.", len(loaded), data_path)
    return loaded | _BUILTIN_COMMON_PASSWORDS

COMMON_PASSWORDS: frozenset[str] = _load_common_passwords()

_mixed_case = [e for e in COMMON_PASSWORDS if e != e.lower()]
if _mixed_case:
    _sorted_bad = sorted(_mixed_case)
    _suffix     = "..." if len(_sorted_bad) > 10 else ""
    raise ValueError(
        f"All COMMON_PASSWORDS entries must be lower-case. "
        f"Offending entries: {_sorted_bad[:10]}{_suffix}"
    )
del _mixed_case

# ---------------------------------------------------------------------------
# Overlap guard — stays at bottom so both collections are fully defined.
# ---------------------------------------------------------------------------
_overlap = frozenset(KEYBOARD_PATTERNS) & COMMON_PASSWORDS
if _overlap:
    raise ValueError(
        f"Entries in both KEYBOARD_PATTERNS and COMMON_PASSWORDS: {sorted(_overlap)}. "
        "This causes a hidden double-penalty. Remove duplicates from one list."
    )
del _overlap

# Substring overlaps produce a double penalty on affected inputs.
# Logged at DEBUG level (not warnings.warn) to avoid polluting CI output
# and test runners that import the module in fresh interpreter sessions.
_substring_overlaps: list[tuple[str, str]] = [
    (pattern, entry)
    for pattern in KEYBOARD_PATTERNS
    for entry in COMMON_PASSWORDS
    if pattern in entry and pattern != entry
]
if _substring_overlaps:
    _preview    = _substring_overlaps[:10]
    _extra      = len(_substring_overlaps) - len(_preview)
    _extra_note = f"\n  ...and {_extra} more" if _extra else ""
    _log.debug(
        "KEYBOARD_PATTERNS substrings found inside COMMON_PASSWORDS entries "
        "(double penalty handled by skip logic):\n%s%s",
        "\n".join(
            f"  pattern '{p}' found inside common password '{e}'"
            for p, e in _preview
        ),
        _extra_note,
    )
del _substring_overlaps