//! The PGP word list (Juola and Zimmermann, 1995), used for codes and SAS words.
//!
//! The list is really two lists of 256 words. Byte values at even positions
//! (0, 2, ...) use the two-syllable [`EVEN`] list and odd positions use the
//! three-syllable [`ODD`] list, so a swapped or dropped word is detectable.
//!
//! The words are stored lowercase, which is also the canonical form in codes.
//! The tables were taken from the `magic-wormhole` 0.8.1 crate
//! (`pgpwords.json`) and checked against the independent `pgp-words` 1.1.0
//! crate (identical) and the fingerprint example in the Wikipedia article
//! "PGP word list". The original PGPfone alphabet is a different list.

/// Two-syllable words, used at even byte positions (byte 0, 2, ...).
pub const EVEN: [&str; 256] = [
    "aardvark",
    "absurd",
    "accrue",
    "acme",
    "adrift",
    "adult",
    "afflict",
    "ahead",
    "aimless",
    "algol",
    "allow",
    "alone",
    "ammo",
    "ancient",
    "apple",
    "artist",
    "assume",
    "athens",
    "atlas",
    "aztec",
    "baboon",
    "backfield",
    "backward",
    "banjo",
    "beaming",
    "bedlamp",
    "beehive",
    "beeswax",
    "befriend",
    "belfast",
    "berserk",
    "billiard",
    "bison",
    "blackjack",
    "blockade",
    "blowtorch",
    "bluebird",
    "bombast",
    "bookshelf",
    "brackish",
    "breadline",
    "breakup",
    "brickyard",
    "briefcase",
    "burbank",
    "button",
    "buzzard",
    "cement",
    "chairlift",
    "chatter",
    "checkup",
    "chisel",
    "choking",
    "chopper",
    "christmas",
    "clamshell",
    "classic",
    "classroom",
    "cleanup",
    "clockwork",
    "cobra",
    "commence",
    "concert",
    "cowbell",
    "crackdown",
    "cranky",
    "crowfoot",
    "crucial",
    "crumpled",
    "crusade",
    "cubic",
    "dashboard",
    "deadbolt",
    "deckhand",
    "dogsled",
    "dragnet",
    "drainage",
    "dreadful",
    "drifter",
    "dropper",
    "drumbeat",
    "drunken",
    "dupont",
    "dwelling",
    "eating",
    "edict",
    "egghead",
    "eightball",
    "endorse",
    "endow",
    "enlist",
    "erase",
    "escape",
    "exceed",
    "eyeglass",
    "eyetooth",
    "facial",
    "fallout",
    "flagpole",
    "flatfoot",
    "flytrap",
    "fracture",
    "framework",
    "freedom",
    "frighten",
    "gazelle",
    "geiger",
    "glitter",
    "glucose",
    "goggles",
    "goldfish",
    "gremlin",
    "guidance",
    "hamlet",
    "highchair",
    "hockey",
    "indoors",
    "indulge",
    "inverse",
    "involve",
    "island",
    "jawbone",
    "keyboard",
    "kickoff",
    "kiwi",
    "klaxon",
    "locale",
    "lockup",
    "merit",
    "minnow",
    "miser",
    "mohawk",
    "mural",
    "music",
    "necklace",
    "neptune",
    "newborn",
    "nightbird",
    "oakland",
    "obtuse",
    "offload",
    "optic",
    "orca",
    "payday",
    "peachy",
    "pheasant",
    "physique",
    "playhouse",
    "pluto",
    "preclude",
    "prefer",
    "preshrunk",
    "printer",
    "prowler",
    "pupil",
    "puppy",
    "python",
    "quadrant",
    "quiver",
    "quota",
    "ragtime",
    "ratchet",
    "rebirth",
    "reform",
    "regain",
    "reindeer",
    "rematch",
    "repay",
    "retouch",
    "revenge",
    "reward",
    "rhythm",
    "ribcage",
    "ringbolt",
    "robust",
    "rocker",
    "ruffled",
    "sailboat",
    "sawdust",
    "scallion",
    "scenic",
    "scorecard",
    "scotland",
    "seabird",
    "select",
    "sentence",
    "shadow",
    "shamrock",
    "showgirl",
    "skullcap",
    "skydive",
    "slingshot",
    "slowdown",
    "snapline",
    "snapshot",
    "snowcap",
    "snowslide",
    "solo",
    "southward",
    "soybean",
    "spaniel",
    "spearhead",
    "spellbind",
    "spheroid",
    "spigot",
    "spindle",
    "spyglass",
    "stagehand",
    "stagnate",
    "stairway",
    "standard",
    "stapler",
    "steamship",
    "sterling",
    "stockman",
    "stopwatch",
    "stormy",
    "sugar",
    "surmount",
    "suspense",
    "sweatband",
    "swelter",
    "tactics",
    "talon",
    "tapeworm",
    "tempest",
    "tiger",
    "tissue",
    "tonic",
    "topmost",
    "tracker",
    "transit",
    "trauma",
    "treadmill",
    "trojan",
    "trouble",
    "tumor",
    "tunnel",
    "tycoon",
    "uncut",
    "unearth",
    "unwind",
    "uproot",
    "upset",
    "upshot",
    "vapor",
    "village",
    "virus",
    "vulcan",
    "waffle",
    "wallet",
    "watchword",
    "wayside",
    "willow",
    "woodlark",
    "zulu",
];

/// Three-syllable words, used at odd byte positions (byte 1, 3, ...).
pub const ODD: [&str; 256] = [
    "adroitness",
    "adviser",
    "aftermath",
    "aggregate",
    "alkali",
    "almighty",
    "amulet",
    "amusement",
    "antenna",
    "applicant",
    "apollo",
    "armistice",
    "article",
    "asteroid",
    "atlantic",
    "atmosphere",
    "autopsy",
    "babylon",
    "backwater",
    "barbecue",
    "belowground",
    "bifocals",
    "bodyguard",
    "bookseller",
    "borderline",
    "bottomless",
    "bradbury",
    "bravado",
    "brazilian",
    "breakaway",
    "burlington",
    "businessman",
    "butterfat",
    "camelot",
    "candidate",
    "cannonball",
    "capricorn",
    "caravan",
    "caretaker",
    "celebrate",
    "cellulose",
    "certify",
    "chambermaid",
    "cherokee",
    "chicago",
    "clergyman",
    "coherence",
    "combustion",
    "commando",
    "company",
    "component",
    "concurrent",
    "confidence",
    "conformist",
    "congregate",
    "consensus",
    "consulting",
    "corporate",
    "corrosion",
    "councilman",
    "crossover",
    "crucifix",
    "cumbersome",
    "customer",
    "dakota",
    "decadence",
    "december",
    "decimal",
    "designing",
    "detector",
    "detergent",
    "determine",
    "dictator",
    "dinosaur",
    "direction",
    "disable",
    "disbelief",
    "disruptive",
    "distortion",
    "document",
    "embezzle",
    "enchanting",
    "enrollment",
    "enterprise",
    "equation",
    "equipment",
    "escapade",
    "eskimo",
    "everyday",
    "examine",
    "existence",
    "exodus",
    "fascinate",
    "filament",
    "finicky",
    "forever",
    "fortitude",
    "frequency",
    "gadgetry",
    "galveston",
    "getaway",
    "glossary",
    "gossamer",
    "graduate",
    "gravity",
    "guitarist",
    "hamburger",
    "hamilton",
    "handiwork",
    "hazardous",
    "headwaters",
    "hemisphere",
    "hesitate",
    "hideaway",
    "holiness",
    "hurricane",
    "hydraulic",
    "impartial",
    "impetus",
    "inception",
    "indigo",
    "inertia",
    "infancy",
    "inferno",
    "informant",
    "insincere",
    "insurgent",
    "integrate",
    "intention",
    "inventive",
    "istanbul",
    "jamaica",
    "jupiter",
    "leprosy",
    "letterhead",
    "liberty",
    "maritime",
    "matchmaker",
    "maverick",
    "medusa",
    "megaton",
    "microscope",
    "microwave",
    "midsummer",
    "millionaire",
    "miracle",
    "misnomer",
    "molasses",
    "molecule",
    "montana",
    "monument",
    "mosquito",
    "narrative",
    "nebula",
    "newsletter",
    "norwegian",
    "october",
    "ohio",
    "onlooker",
    "opulent",
    "orlando",
    "outfielder",
    "pacific",
    "pandemic",
    "pandora",
    "paperweight",
    "paragon",
    "paragraph",
    "paramount",
    "passenger",
    "pedigree",
    "pegasus",
    "penetrate",
    "perceptive",
    "performance",
    "pharmacy",
    "phonetic",
    "photograph",
    "pioneer",
    "pocketful",
    "politeness",
    "positive",
    "potato",
    "processor",
    "provincial",
    "proximate",
    "puberty",
    "publisher",
    "pyramid",
    "quantity",
    "racketeer",
    "rebellion",
    "recipe",
    "recover",
    "repellent",
    "replica",
    "reproduce",
    "resistor",
    "responsive",
    "retraction",
    "retrieval",
    "retrospect",
    "revenue",
    "revival",
    "revolver",
    "sandalwood",
    "sardonic",
    "saturday",
    "savagery",
    "scavenger",
    "sensation",
    "sociable",
    "souvenir",
    "specialist",
    "speculate",
    "stethoscope",
    "stupendous",
    "supportive",
    "surrender",
    "suspicious",
    "sympathy",
    "tambourine",
    "telephone",
    "therapist",
    "tobacco",
    "tolerance",
    "tomorrow",
    "torpedo",
    "tradition",
    "travesty",
    "trombonist",
    "truncated",
    "typewriter",
    "ultimate",
    "undaunted",
    "underfoot",
    "unicorn",
    "unify",
    "universe",
    "unravel",
    "upcoming",
    "vacancy",
    "vagabond",
    "vertigo",
    "virginia",
    "visitor",
    "vocalist",
    "voyager",
    "warranty",
    "waterloo",
    "whimsical",
    "wichita",
    "wilmington",
    "wyoming",
    "yesteryear",
    "yucatan",
];

/// Which of the two lists a word comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordList {
    /// Two-syllable words, for even byte positions.
    Even,
    /// Three-syllable words, for odd byte positions.
    Odd,
}

impl WordList {
    /// The list used for byte position `index` (0-based).
    pub fn for_position(index: usize) -> WordList {
        if index.is_multiple_of(2) {
            WordList::Even
        } else {
            WordList::Odd
        }
    }

    /// All 256 words, lowercase.
    pub fn words(self) -> &'static [&'static str; 256] {
        match self {
            WordList::Even => &EVEN,
            WordList::Odd => &ODD,
        }
    }

    /// The word for `byte`.
    pub fn word(self, byte: u8) -> &'static str {
        self.words()[usize::from(byte)]
    }

    /// The byte for a lowercase `word`, if it is in this list.
    pub fn byte(self, word: &str) -> Option<u8> {
        let index = self.words().iter().position(|w| *w == word)?;
        u8::try_from(index).ok()
    }
}

/// Encodes bytes as PGP words, alternating even/odd lists by position.
pub fn encode(bytes: &[u8]) -> Vec<&'static str> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| WordList::for_position(i).word(*b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;

    #[test]
    fn lists_have_256_unique_lowercase_words_each_and_never_overlap() {
        let even: HashSet<_> = EVEN.iter().collect();
        let odd: HashSet<_> = ODD.iter().collect();
        assert_eq!((EVEN.len(), even.len()), (256, 256));
        assert_eq!((ODD.len(), odd.len()), (256, 256));
        assert!(even.is_disjoint(&odd), "a word appears in both lists");
        for w in EVEN.iter().chain(ODD.iter()) {
            assert!(
                !w.is_empty() && w.bytes().all(|c| c.is_ascii_lowercase()),
                "{w}"
            );
        }
        // The published maximum word lengths: 9 letters (even) and 11 (odd).
        assert_eq!(EVEN.iter().map(|w| w.len()).max(), Some(9));
        assert_eq!(ODD.iter().map(|w| w.len()).max(), Some(11));
    }

    #[test]
    fn known_first_and_last_words() {
        assert_eq!((EVEN[0], EVEN[255]), ("aardvark", "zulu"));
        assert_eq!((ODD[0], ODD[255]), ("adroitness", "yucatan"));
        assert_eq!((EVEN[1], ODD[6], EVEN[14]), ("absurd", "amulet", "apple"));
    }

    #[test]
    fn wikipedia_fingerprint_example() {
        // "E582" is "topmost Istanbul" and "82E5" is "miser travesty".
        assert_eq!(encode(&[0xE5, 0x82]), ["topmost", "istanbul"]);
        assert_eq!(encode(&[0x82, 0xE5]), ["miser", "travesty"]);
        let fp = [
            0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48, 0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC,
            0x52, 0x8F, 0xD7, 0xFA, 0x3F, 0x19,
        ];
        let expected = "topmost istanbul pluto vagabond treadmill pacific brackish dictator \
                        goldfish medusa afflict bravado chatter revolver dupont midsummer \
                        stopwatch whimsical cowbell bottomless";
        assert_eq!(encode(&fp).join(" "), expected);
    }

    #[test]
    fn table_digest_is_pinned() {
        // Catches any accidental edit to either table.
        let mut joined = String::new();
        for w in EVEN.iter().chain(ODD.iter()) {
            joined.push_str(w);
            joined.push('\n');
        }
        let digest = Sha256::digest(joined.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0847bcad4a09374ec628019e7c3e3eeee1dfa2f3870168eaa306310eeda40ff5"
        );
    }

    #[test]
    fn byte_lookup_round_trips() {
        for b in 0..=255u8 {
            assert_eq!(WordList::Even.byte(WordList::Even.word(b)), Some(b));
            assert_eq!(WordList::Odd.byte(WordList::Odd.word(b)), Some(b));
        }
        assert_eq!(WordList::Even.byte("adroitness"), None);
        assert_eq!(WordList::Odd.byte("aardvark"), None);
    }
}
