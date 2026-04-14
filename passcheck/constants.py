from __future__ import annotations

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
    "SPECIAL_CHARS",
    "KEYBOARD_PATTERNS",
    "KEYBOARD_PATTERN_MIN_LEN",
    "COMMON_PASSWORDS",
]

# ---------------------------------------------------------------------------
# Scoring weights
# Guard: values must be non-negative and the total must be >= 100 so that a
# password meeting every criterion can always reach a score of 100.
# ---------------------------------------------------------------------------
SCORE_WEIGHTS: dict[str, int] = {
    "length_minimum":      10,  # meets bare minimum length
    "length_good":         10,  # meets recommended length
    "length_excellent":     5,  # extra credit for very long passwords
    "has_uppercase":       10,  # at least one uppercase letter
    "has_lowercase":        5,  # at least one lowercase letter
    "has_digit":           10,  # at least one digit
    "has_special":         15,  # at least one special character
    "char_variety":        10,  # uses 3+ of the 5 character classes
    "no_common_password":  10,  # not a known common password
    "no_keyboard_pattern": 10,  # no obvious keyboard sequence
    "no_repeated_chars":    5,  # no excessive character repetition
    "entropy_bonus":       10,  # entropy >= threshold
}

if not all(v >= 0 for v in SCORE_WEIGHTS.values()):
    raise ValueError(
        "All SCORE_WEIGHTS values must be non-negative."
    )
_weights_total = sum(SCORE_WEIGHTS.values())
if _weights_total < 100:
    raise ValueError(
        f"SCORE_WEIGHTS sum to {_weights_total}, must be >= 100 "
        "so that a perfect password can reach a score of 100."
    )
del _weights_total

# ---------------------------------------------------------------------------
# Length thresholds
# Guard: thresholds must be strictly increasing so that each tier is
# reachable and the bonus checks are logically independent.
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
ENTROPY_GOOD_THRESHOLD: float = 50.0   # qualifies for entropy bonus

# Blend weight for Shannon entropy in the entropy calculation.
# 0.0 → pure pool-size estimate; 1.0 → pure Shannon distribution measure.
SHANNON_WEIGHT: float = 0.4

if not (0.0 < SHANNON_WEIGHT < 1.0):
    raise ValueError(
        f"SHANNON_WEIGHT must be in (0, 1), got {SHANNON_WEIGHT!r}."
    )

# ---------------------------------------------------------------------------
# Repeated characters — flag if any char appears >= this fraction of length
# ---------------------------------------------------------------------------
REPEATED_CHAR_RATIO: float = 0.4

if not (0.0 < REPEATED_CHAR_RATIO < 1.0):
    raise ValueError(
        f"REPEATED_CHAR_RATIO must be in (0, 1), got {REPEATED_CHAR_RATIO!r}."
    )

# ---------------------------------------------------------------------------
# Strength band definitions  (score lower-bound -> label, colour code)
# Sorted descending so the first match wins in a linear scan.
# Guard: list must already be in descending order and must include a catch-all
# entry at threshold 0 so every possible score maps to exactly one band.
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

# ---------------------------------------------------------------------------
# Special characters recognised by the checker
# ---------------------------------------------------------------------------
SPECIAL_CHARS: str = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Keyboard walk patterns.
# ---------------------------------------------------------------------------
KEYBOARD_PATTERN_MIN_LEN: int = 4

KEYBOARD_PATTERNS: tuple[str, ...] = (
    # Horizontal rows — left-to-right
    "qwerty", "qwertz", "azerty",
    # Horizontal rows — right-to-left (reverses)
    # FIX: added "ytreza" (reverse of "azerty") to complete the symmetric set.
    "ytrewq", "ztrewq", "ytreza",
    # Middle row — left-to-right and right-to-left
    "asdfgh", "hgfdsa",
    # Bottom row — left-to-right and right-to-left
    "zxcvbn", "nbvcxz",
    # Numeric sequences — ascending / descending
    "123456",
    "234567", "345678", "456789", "567890",
    "987654", "876543", "765432",
    "0987654321",
    # Alphabetical sequences
    "abcdef", "abcdefg", "abcdefgh",
    # Vertical column walks (left column, second column, third column)
    "1qaz", "2wsx", "3edc",
    # Vertical column walks — reversed
    "zaq1", "xsw2", "cde3",
)

_short_patterns = [p for p in KEYBOARD_PATTERNS if len(p) < KEYBOARD_PATTERN_MIN_LEN]
if _short_patterns:
    raise ValueError(
        f"Every KEYBOARD_PATTERNS entry must be at least "
        f"{KEYBOARD_PATTERN_MIN_LEN} characters. "
        f"Offending entries: {_short_patterns}."
    )
del _short_patterns

# ---------------------------------------------------------------------------
# Common passwords list (subset — extend or load from file in production).
# Guard: all entries must already be lower-cased because the checker
# normalises the candidate password with .lower() before comparison.
# ---------------------------------------------------------------------------
COMMON_PASSWORDS: frozenset[str] = frozenset({
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
    "2013", "2014", "2015", "2016",
    "2112", "222222", "2222222", "22222222",
    "232323", "246810", "321321", "333333",
    "3333333", "33333333", "369369", "404040",
    "420420", "444444", "4444444", "44444444",
    "4815162342", "494949", "555555",
    "5555555", "55555555", "654321", "666666",
    "6666666", "66666666", "696969", "742742",
    "777777", "7777777", "77777777", "7777777777",
    "7654321", "789456", "789456123", "852456",
    "888888", "8888888", "88888888", "987654321",
    "999999", "9999999", "99999999", "9999999999",
    "a123456", "a1b2c3", "aaaa", "aaaaa",
    "aaaaaa", "aaaaaaa", "aaaaaaaa", "aaaaaaaaa",
    "aaaaaaaaaa", "abc123", "abcabc", "abcd",
    "abcd1234", "access",
    "access14", "action", "adam", "admin",
    "admin1", "admin12", "admin123", "adobe123",
    "adriana", "adult", "aezakmi", "agatka",
    "agosto", "ahmed", "ahtlbq", "aiden",
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

_mixed_case = [e for e in COMMON_PASSWORDS if e != e.lower()]
if _mixed_case:
    raise ValueError(
        f"All COMMON_PASSWORDS entries must be lower-case. "
        f"Offending entries: {sorted(_mixed_case)[:10]}..."
    )
del _mixed_case

# ---------------------------------------------------------------------------
# Overlap guard — must stay at the bottom so both collections are fully
# defined before the check runs.
# ---------------------------------------------------------------------------
_overlap = frozenset(KEYBOARD_PATTERNS) & COMMON_PASSWORDS
if _overlap:
    raise ValueError(
        f"Entries in both KEYBOARD_PATTERNS and COMMON_PASSWORDS: {sorted(_overlap)}. "
        "This causes a hidden double-penalty. Remove duplicates from one list."
    )
del _overlap