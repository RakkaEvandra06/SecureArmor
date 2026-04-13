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
# ---------------------------------------------------------------------------
SCORE_WEIGHTS: dict[str, int] = {
    "length_minimum":      10,  # meets bare minimum length
    "length_good":         10,  # meets recommended length
    "length_excellent":     5,  # extra credit for very long passwords
    "has_uppercase":       10,  # at least one uppercase letter
    "has_lowercase":        5,  # at least one lowercase letter
    "has_digit":           10,  # at least one digit
    "has_special":         15,  # at least one special character
    "char_variety":        10,  # uses 3+ of the 4 character classes
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
# Sorted descending so the first match wins.
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
KEYBOARD_PATTERN_MIN_LEN: int = 4

# ---------------------------------------------------------------------------
# Keyboard walk patterns.
# ---------------------------------------------------------------------------
KEYBOARD_PATTERNS: list[str] = [
    # Horizontal rows — left-to-right
    "qwerty", "qwertz", "azerty",
    # Horizontal rows — right-to-left (reverses)
    "ytrewq", "ztrewq",
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
]

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
    "02021976", "02021979", "02021980", "02021981",
    "02021982", "02021990", "02021991", "02031973",
    "02031975", "02031977", "02031978", "02031979",
    "02031980", "02031981", "02031982", "02031983",
    "02031985", "02031988", "02031989", "02041974",
    "02041975", "02041976", "02041977", "02041978",
    "02041979", "02041980", "02041981", "02041985",
    "02041989", "02051972", "02051973", "02051975",
    "02051976", "02051977", "02051978", "02051980",
    "02051981", "02051982", "02051984", "02051985",
    "02051987", "02051988", "02051989", "02061976",
    "02061977", "02061979", "02061980", "02061982",
    "02061983", "02061984", "02061987", "02061988",
    "02071971", "02071975", "02071976", "02071977",
    "02071978", "02071979", "02071980", "02071981",
    "02071983", "02071984", "02071985", "02071987",
    "02071988", "02071989", "02081974", "02081976",
    "02081977", "02081979", "02081980", "02081981",
    "02081982", "02081983", "02081985", "02091973",
    "02091975", "02091976", "02091977", "02091980",
    "02091981", "02091983", "02091984", "02091985",
    "02091988", "02091989", "02101976", "02101977",
    "02101978", "02101979", "02101980", "02101981",
    "02101983", "02101984", "02101986", "02101987",
    "02101988", "02101989", "03011987", "03021986",
    "03031986", "03031988", "03031990", "03031993",
    "03041980", "03041986", "03041991", "03051986",
    "03051987", "03061987", "03071986", "03071987",
    "03081986", "03081987", "03091986", "03091987",
    "03101986", "03111986", "03121986", "04011985",
    "04011986", "04011987", "04011988", "04011989",
    "04021984", "04021985", "04021986", "04021987",
    "04021988", "04021989", "04031984", "04031985",
    "04031986", "04031987", "04031988", "04031989",
    "04041984", "04041985", "04041986", "04041987",
    "04041988", "04041989", "04051983", "04051984",
    "04051985", "04051986", "04051987", "04051988",
    "04061984", "04061985", "04061986", "04061987",
    "04061988", "04071984", "04071985", "04071986",
    "04071987", "04081985", "04081986", "04081987",
    "04091985", "04091986", "04101985", "04101986",
    "04111985", "04121985", "04121986", "05011984",
    "05011985", "05011986", "05011987", "05011988",
    "05021984", "05021985", "05021986", "05021987",
    "05031983", "05031984", "05031985", "05031986",
    "05031987", "05041982", "05041983", "05041984",
    "05041985", "05041986", "05041987", "05051984",
    "05051985", "05051986", "05051987", "05061984",
    "05061985", "05061986", "05071984", "05071985",
    "05081984", "05081985", "05091984", "05091985",
    "05101984", "05111984", "05121984", "06011984",
    "06011985", "06011986", "06011987", "06021984",
    "06021985", "06021986", "06031984", "06031985",
    "06041984", "06041985", "06051984", "06051985",
    "06061984", "06061985", "06071984", "06081984",
    "06091984", "06101984", "06111984", "06121984",
    "07011984", "07011985", "07011986", "07021984",
    "07021985", "07031984", "07031985", "07041984",
    "07041985", "07051984", "07061984", "07071984",
    "07081984", "07091984", "07101984", "07111984",
    "07121984", "08011984", "08011985", "08021984",
    "08031984", "08041984", "08051984", "08061984",
    "08071984", "08081984", "08091984", "08101984",
    "08111984", "08121984", "09011984", "09021984",
    "09031984", "09041984", "09051984", "09061984",
    "09071984", "09081984", "09091984", "09101984",
    "09111984", "09121984", "10011984", "10021984",
    "10031984", "10041984", "10051984", "10061984",
    "10071984", "10081984", "10091984", "10101984",
    "10111984", "10121984", "11011984", "11021984",
    "11031984", "11041984", "11051984", "11061984",
    "11071984", "11081984", "11091984", "11101984",
    "11111984", "11121984", "12011984", "12021984",
    "12031984", "12041984", "12051984", "12061984",
    "12071984", "12081984", "12091984", "12101984",
    "12111984", "12121984", "121212", "123123",
    "1234", "12345", "1234567",
    "12345678", "123456789", "1234567890", "123456789a",
    "12345678910", "123456a", "1234qwer", "123abc",
    "123qwe", "123qweasd", "1q2w3e", "1q2w3e4r",
    "1q2w3e4r5t", "1qaz2wsx", "1qazxsw2", "2000",
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