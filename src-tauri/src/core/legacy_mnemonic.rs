// core/legacy_mnemonic.rs — Legacy Electrum mnemonic wordlist (pre-BIP39)
//
// Ported from archive/electrumsv/old_mnemonic.py. The wordlist is from
// http://en.wiktionary.org/wiki/Wiktionary:Frequency_lists/Contemporary_poetry
//
// This is the *original* Electrum mnemonic scheme (pre-BIP39) where each
// word does not represent a given digit — the digit represented by a word
// is variable and depends on the previous word. See US patent no 5892470.
//
// Encoding: 8 hex chars (32 bits) → 3 words. Decoding: 3 words → 8 hex chars.

use serde::{Deserialize, Serialize};

/// Number of words in the legacy wordlist.
pub const N: usize = 1626;

/// The legacy Electrum wordlist (1626 words from contemporary poetry frequency list).
pub const LEGACY_WORDS: &[&str] = &[
    "like", "just", "love", "know", "never", "want", "time", "out", "there", "make",
    "look", "eye", "down", "only", "think", "heart", "back", "then", "into", "about",
    "more", "away", "still", "them", "take", "thing", "even", "through", "long", "always",
    "world", "too", "friend", "tell", "try", "hand", "thought", "over", "here", "other",
    "need", "smile", "again", "much", "cry", "been", "night", "ever", "little", "said",
    "end", "some", "those", "around", "mind", "people", "girl", "leave", "dream", "left",
    "turn", "myself", "give", "nothing", "really", "off", "before", "something", "find", "walk",
    "wish", "good", "once", "place", "ask", "stop", "keep", "watch", "seem", "everything",
    "wait", "got", "yet", "made", "remember", "start", "alone", "run", "hope", "maybe",
    "believe", "body", "hate", "after", "close", "talk", "stand", "own", "each", "hurt",
    "help", "home", "god", "soul", "new", "many", "two", "inside", "should", "true",
    "first", "fear", "mean", "better", "play", "another", "gone", "change", "use", "wonder",
    "someone", "hair", "cold", "open", "best", "any", "behind", "happen", "water", "dark",
    "laugh", "stay", "forever", "name", "work", "show", "sky", "break", "came", "deep",
    "door", "put", "black", "together", "upon", "happy", "such", "great", "white", "matter",
    "fill", "past", "please", "burn", "cause", "enough", "touch", "moment", "soon", "voice",
    "scream", "anything", "stare", "sound", "red", "everyone", "hide", "kiss", "truth", "death",
    "beautiful", "mine", "blood", "broken", "very", "pass", "next", "forget", "tree", "wrong",
    "air", "mother", "understand", "lip", "hit", "wall", "memory", "sleep", "free", "high",
    "realize", "school", "might", "skin", "sweet", "perfect", "blue", "kill", "breath", "dance",
    "against", "fly", "between", "grow", "strong", "under", "listen", "bring", "sometimes", "speak",
    "pull", "person", "become", "family", "begin", "ground", "real", "small", "father", "sure",
    "feet", "rest", "young", "finally", "land", "across", "today", "different", "guy", "line",
    "fire", "reason", "reach", "second", "slowly", "write", "eat", "smell", "mouth", "step",
    "learn", "three", "floor", "promise", "breathe", "darkness", "push", "earth", "guess", "save",
    "song", "above", "along", "both", "color", "house", "almost", "sorry", "anymore", "brother",
    "okay", "dear", "game", "fade", "already", "apart", "warm", "beauty", "heard", "notice",
    "question", "shine", "began", "piece", "whole", "shadow", "secret", "street", "within", "finger",
    "point", "morning", "whisper", "child", "moon", "green", "story", "glass", "kid", "silence",
    "since", "soft", "yourself", "empty", "shall", "angel", "answer", "baby", "bright", "dad",
    "path", "worry", "hour", "drop", "follow", "power", "war", "half", "flow", "heaven",
    "act", "chance", "fact", "least", "tired", "children", "near", "quite", "afraid", "rise",
    "sea", "taste", "window", "cover", "nice", "trust", "lot", "sad", "cool", "force",
    "peace", "return", "blind", "easy", "ready", "roll", "rose", "drive", "held", "music",
    "beneath", "hang", "mom", "paint", "emotion", "quiet", "clear", "cloud", "few", "pretty",
    "bird", "outside", "paper", "picture", "front", "rock", "simple", "anyone", "meant", "reality",
    "road", "sense", "waste", "bit", "leaf", "thank", "happiness", "meet", "men", "smoke",
    "truly", "decide", "self", "age", "book", "form", "alive", "carry", "escape", "damn",
    "instead", "able", "ice", "minute", "throw", "catch", "leg", "ring", "course", "goodbye",
    "lead", "poem", "sick", "corner", "desire", "known", "problem", "remind", "shoulder", "suppose",
    "toward", "wave", "drink", "jump", "woman", "pretend", "sister", "week", "human", "joy",
    "crack", "grey", "pray", "surprise", "dry", "knee", "less", "search", "bleed", "caught",
    "clean", "embrace", "future", "king", "son", "sorrow", "chest", "hug", "remain", "sat",
    "worth", "blow", "daddy", "final", "parent", "tight", "also", "create", "lonely", "safe",
    "cross", "dress", "evil", "silent", "bone", "fate", "perhaps", "anger", "class", "scar",
    "snow", "tiny", "tonight", "continue", "control", "dog", "edge", "mirror", "month", "suddenly",
    "comfort", "given", "loud", "quickly", "gaze", "plan", "rush", "stone", "town", "battle",
    "ignore", "spirit", "stood", "stupid", "yours", "brown", "build", "dust", "hey", "kept",
    "pay", "phone", "twist", "although", "ball", "beyond", "hidden", "nose", "taken", "fail",
    "float", "pure", "somehow", "wash", "wrap", "angry", "cheek", "creature", "forgotten", "heat",
    "rip", "single", "space", "special", "weak", "whatever", "yell", "anyway", "blame", "job",
    "choose", "country", "curse", "drift", "echo", "figure", "grew", "laughter", "neck", "suffer",
    "worse", "yeah", "disappear", "foot", "forward", "knife", "mess", "somewhere", "stomach", "storm",
    "beg", "idea", "lift", "offer", "breeze", "field", "five", "often", "simply", "stuck",
    "win", "allow", "confuse", "enjoy", "except", "flower", "seek", "strength", "calm", "grin",
    "gun", "heavy", "hill", "large", "ocean", "shoe", "sigh", "straight", "summer", "tongue",
    "accept", "crazy", "everyday", "exist", "grass", "mistake", "sent", "shut", "surround", "table",
    "ache", "brain", "destroy", "heal", "nature", "shout", "sign", "stain", "choice", "doubt",
    "glance", "glow", "mountain", "queen", "stranger", "throat", "tomorrow", "city", "either", "fish",
    "flame", "rather", "shape", "spin", "spread", "ash", "distance", "finish", "image", "imagine",
    "important", "nobody", "shatter", "warmth", "became", "feed", "flesh", "funny", "lust", "shirt",
    "trouble", "yellow", "attention", "bare", "bite", "money", "protect", "amaze", "appear", "born",
    "choke", "completely", "daughter", "fresh", "friendship", "gentle", "probably", "six", "deserve", "expect",
    "grab", "middle", "nightmare", "river", "thousand", "weight", "worst", "wound", "barely", "bottle",
    "cream", "regret", "relationship", "stick", "test", "crush", "endless", "fault", "itself", "rule",
    "spill", "art", "circle", "join", "kick", "mask", "master", "passion", "quick", "raise",
    "smooth", "unless", "wander", "actually", "broke", "chair", "deal", "favorite", "gift", "note",
    "number", "sweat", "box", "chill", "clothes", "lady", "mark", "park", "poor", "sadness",
    "tie", "animal", "belong", "brush", "consume", "dawn", "forest", "innocent", "pen", "pride",
    "stream", "thick", "clay", "complete", "count", "draw", "faith", "press", "silver", "struggle",
    "surface", "taught", "teach", "wet", "bless", "chase", "climb", "enter", "letter", "melt",
    "metal", "movie", "stretch", "swing", "vision", "wife", "beside", "crash", "forgot", "guide",
    "haunt", "joke", "knock", "plant", "pour", "prove", "reveal", "steal", "stuff", "trip",
    "wood", "wrist", "bother", "bottom", "crawl", "crowd", "fix", "forgive", "frown", "grace",
    "loose", "lucky", "party", "release", "surely", "survive", "teacher", "gently", "grip", "speed",
    "suicide", "travel", "treat", "vein", "written", "cage", "chain", "conversation", "date", "enemy",
    "however", "interest", "million", "page", "pink", "proud", "sway", "themselves", "winter", "church",
    "cruel", "cup", "demon", "experience", "freedom", "pair", "pop", "purpose", "respect", "shoot",
    "softly", "state", "strange", "bar", "birth", "curl", "dirt", "excuse", "lord", "lovely",
    "monster", "order", "pack", "pants", "pool", "scene", "seven", "shame", "slide", "ugly",
    "among", "blade", "blonde", "closet", "creek", "deny", "drug", "eternity", "gain", "grade",
    "handle", "key", "linger", "pale", "prepare", "swallow", "swim", "tremble", "wheel", "won",
    "cast", "cigarette", "claim", "college", "direction", "dirty", "gather", "ghost", "hundred", "loss",
    "lung", "orange", "present", "swear", "swirl", "twice", "wild", "bitter", "blanket", "doctor",
    "everywhere", "flash", "grown", "knowledge", "numb", "pressure", "radio", "repeat", "ruin", "spend",
    "unknown", "buy", "clock", "devil", "early", "false", "fantasy", "pound", "precious", "refuse",
    "sheet", "teeth", "welcome", "add", "ahead", "block", "bury", "caress", "content", "depth",
    "despite", "distant", "marry", "purple", "threw", "whenever", "bomb", "dull", "easily", "grasp",
    "hospital", "innocence", "normal", "receive", "reply", "rhyme", "shade", "someday", "sword", "toe",
    "visit", "asleep", "bought", "center", "consider", "flat", "hero", "history", "ink", "insane",
    "muscle", "mystery", "pocket", "reflection", "shove", "silently", "smart", "soldier", "spot", "stress",
    "train", "type", "view", "whether", "bus", "energy", "explain", "holy", "hunger", "inch",
    "magic", "mix", "noise", "nowhere", "prayer", "presence", "shock", "snap", "spider", "study",
    "thunder", "trail", "admit", "agree", "bag", "bang", "bound", "butterfly", "cute", "exactly",
    "explode", "familiar", "fold", "further", "pierce", "reflect", "scent", "selfish", "sharp", "sink",
    "spring", "stumble", "universe", "weep", "women", "wonderful", "action", "ancient", "attempt", "avoid",
    "birthday", "branch", "chocolate", "core", "depress", "drunk", "especially", "focus", "fruit", "honest",
    "match", "palm", "perfectly", "pillow", "pity", "poison", "roar", "shift", "slightly", "thump",
    "truck", "tune", "twenty", "unable", "wipe", "wrote", "coat", "constant", "dinner", "drove",
    "egg", "eternal", "flight", "flood", "frame", "freak", "gasp", "glad", "hollow", "motion",
    "peer", "plastic", "root", "screen", "season", "sting", "strike", "team", "unlike", "victim",
    "volume", "warn", "weird", "attack", "await", "awake", "built", "charm", "crave", "despair",
    "fought", "grant", "grief", "horse", "limit", "message", "ripple", "sanity", "scatter", "serve",
    "split", "string", "trick", "annoy", "blur", "boat", "brave", "clearly", "cling", "connect",
    "fist", "forth", "imagination", "iron", "jock", "judge", "lesson", "milk", "misery", "nail",
    "naked", "ourselves", "poet", "possible", "princess", "sail", "size", "snake", "society", "stroke",
    "torture", "toss", "trace", "wise", "bloom", "bullet", "cell", "check", "cost", "darling",
    "during", "footstep", "fragile", "hallway", "hardly", "horizon", "invisible", "journey", "midnight", "mud",
    "nod", "pause", "relax", "shiver", "sudden", "value", "youth", "abuse", "admire", "blink",
    "breast", "bruise", "constantly", "couple", "creep", "curve", "difference", "dumb", "emptiness", "gotta",
    "honor", "plain", "planet", "recall", "rub", "ship", "slam", "soar", "somebody", "tightly",
    "weather", "adore", "approach", "bond", "bread", "burst", "candle", "coffee", "cousin", "crime",
    "desert", "flutter", "frozen", "grand", "heel", "hello", "language", "level", "movement", "pleasure",
    "powerful", "random", "rhythm", "settle", "silly", "slap", "sort", "spoken", "steel", "threaten",
    "tumble", "upset", "aside", "awkward", "bee", "blank", "board", "button", "card", "carefully",
    "complain", "crap", "deeply", "discover", "drag", "dread", "effort", "entire", "fairy", "giant",
    "gotten", "greet", "illusion", "jeans", "leap", "liquid", "march", "mend", "nervous", "nine",
    "replace", "rope", "spine", "stole", "terror", "accident", "apple", "balance", "boom", "childhood",
    "collect", "demand", "depression", "eventually", "faint", "glare", "goal", "group", "honey", "kitchen",
    "laid", "limb", "machine", "mere", "mold", "murder", "nerve", "painful", "poetry", "prince",
    "rabbit", "shelter", "shore", "shower", "soothe", "stair", "steady", "sunlight", "tangle", "tease",
    "treasure", "uncle", "begun", "bliss", "canvas", "cheer", "claw", "clutch", "commit", "crimson",
    "crystal", "delight", "doll", "existence", "express", "fog", "football", "gay", "goose", "guard",
    "hatred", "illuminate", "mass", "math", "mourn", "rich", "rough", "skip", "stir", "student",
    "style", "support", "thorn", "tough", "yard", "yearn", "yesterday", "advice", "appreciate", "autumn",
    "bank", "beam", "bowl", "capture", "carve", "collapse", "confusion", "creation", "dove", "feather",
    "girlfriend", "glory", "government", "harsh", "hop", "inner", "loser", "moonlight", "neighbor", "neither",
    "peach", "pig", "praise", "screw", "shield", "shimmer", "sneak", "stab", "subject", "throughout",
    "thrown", "tower", "twirl", "wow", "army", "arrive", "bathroom", "bump", "cease", "cookie",
    "couch", "courage", "dim", "guilt", "howl", "hum", "husband", "insult", "led", "lunch",
    "mock", "mostly", "natural", "nearly", "needle", "nerd", "peaceful", "perfection", "pile", "price",
    "remove", "roam", "sanctuary", "serious", "shiny", "shook", "sob", "stolen", "tap", "vain",
    "void", "warrior", "wrinkle", "affection", "apologize", "blossom", "bounce", "bridge", "cheap", "crumble",
    "decision", "descend", "desperately", "dig", "dot", "flip", "frighten", "heartbeat", "huge", "lazy",
    "lick", "odd", "opinion", "process", "puzzle", "quietly", "retreat", "score", "sentence", "separate",
    "situation", "skill", "soak", "square", "stray", "taint", "task", "tide", "underneath", "veil",
    "whistle", "anywhere", "bedroom", "bid", "bloody", "burden", "careful", "compare", "concern", "curtain",
    "decay", "defeat", "describe", "double", "dreamer", "driver", "dwell", "evening", "flare", "flicker",
    "grandma", "guitar", "harm", "horrible", "hungry", "indeed", "lace", "melody", "monkey", "nation",
    "object", "obviously", "rainbow", "salt", "scratch", "shown", "shy", "stage", "stun", "third",
    "tickle", "useless", "weakness", "worship", "worthless", "afternoon", "beard", "boyfriend", "bubble", "busy",
    "certain", "chin", "concrete", "desk", "diamond", "doom", "drawn", "due", "felicity", "freeze",
    "frost", "garden", "glide", "harmony", "hopefully", "hunt", "jealous", "lightning", "mama", "mercy",
    "peel", "physical", "position", "pulse", "punch", "quit", "rant", "respond", "salty", "sane",
    "satisfy", "savior", "sheep", "slept", "social", "sport", "tuck", "utter", "valley", "wolf",
    "aim", "alas", "alter", "arrow", "awaken", "beaten", "belief", "brand", "ceiling", "cheese",
    "clue", "confidence", "connection", "daily", "disguise", "eager", "erase", "essence", "everytime", "expression",
    "fan", "flag", "flirt", "foul", "fur", "giggle", "glorious", "ignorance", "law", "lifeless",
    "measure", "mighty", "muse", "north", "opposite", "paradise", "patience", "patient", "pencil", "petal",
    "plate", "ponder", "possibly", "practice", "slice", "spell", "stock", "strife", "strip", "suffocate",
    "suit", "tender", "tool", "trade", "velvet", "verse", "waist", "witch", "aunt", "bench",
    "bold", "cap", "certainly", "click", "companion", "creator", "dart", "delicate", "determine", "dish",
    "dragon", "drama", "drum", "dude", "everybody", "feast", "forehead", "former", "fright", "fully",
    "gas", "hook", "hurl", "invite", "juice", "manage", "moral", "possess", "raw", "rebel",
    "royal", "scale", "scary", "several", "slight", "stubborn", "swell", "talent", "tea", "terrible",
    "thread", "torment", "trickle", "usually", "vast", "violence", "weave", "acid", "agony", "ashamed",
    "awe", "belly", "blend", "blush", "character", "cheat", "common", "company", "coward", "creak",
    "danger", "deadly", "defense", "define", "depend", "desperate", "destination", "dew", "duck", "dusty",
    "embarrass", "engine", "example", "explore", "foe", "freely", "frustrate", "generation", "glove", "guilty",
    "health", "hurry", "idiot", "impossible", "inhale", "jaw", "kingdom", "mention", "mist", "moan",
    "mumble", "mutter", "observe", "ode", "pathetic", "pattern", "pie", "prefer", "puff", "rape",
    "rare", "revenge", "rude", "scrape", "spiral", "squeeze", "strain", "sunset", "suspend", "sympathy",
    "thigh", "throne", "total", "unseen", "weapon", "weary",
];

/// Errors from the legacy mnemonic module.
#[derive(Debug, thiserror::Error)]
pub enum LegacyMnemonicError {
    #[error("invalid hex string length: must be a multiple of 8, got {0}")]
    InvalidHexLength(usize),
    #[error("invalid hex character at position {pos}: {ch}")]
    InvalidHexChar { pos: usize, ch: char },
    #[error("word not found in wordlist: {0}")]
    WordNotFound(String),
    #[error("word list length must be a multiple of 3, got {0}")]
    InvalidWordCount(usize),
    #[error("overflow in mnemonic decode arithmetic")]
    Overflow,
}

/// Encode a hex string into legacy mnemonic words.
///
/// The input must be a hex string with length divisible by 8. Each 8-hex-char
/// chunk (32 bits) produces 3 words.
///
/// Algorithm (matching `mn_encode` in old_mnemonic.py):
/// ```text
/// x = int(hex_chunk, 16)
/// w1 = x % N
/// w2 = ((x // N) + w1) % N
/// w3 = ((x // N // N) + w2) % N
/// → words[w1], words[w2], words[w3]
/// ```
pub fn mn_encode(message: &str) -> Result<Vec<&'static str>, LegacyMnemonicError> {
    if message.len() % 8 != 0 {
        return Err(LegacyMnemonicError::InvalidHexLength(message.len()));
    }

    // Validate hex characters.
    for (i, ch) in message.chars().enumerate() {
        if !ch.is_ascii_hexdigit() {
            return Err(LegacyMnemonicError::InvalidHexChar { pos: i, ch });
        }
    }

    let mut out = Vec::with_capacity(message.len() / 8 * 3);
    for chunk in message.as_bytes().chunks(8) {
        let chunk_str = std::str::from_utf8(chunk).expect("validated hex");
        let x = u64::from_str_radix(chunk_str, 16).map_err(|_| {
            LegacyMnemonicError::InvalidHexChar { pos: 0, ch: '\0' }
        })?;
        let n = N as u64;
        let w1 = (x % n) as usize;
        let w2 = (((x / n) + w1 as u64) % n) as usize;
        let w3 = (((x / n / n) + w2 as u64) % n) as usize;
        out.push(LEGACY_WORDS[w1]);
        out.push(LEGACY_WORDS[w2]);
        out.push(LEGACY_WORDS[w3]);
    }
    Ok(out)
}

/// Decode legacy mnemonic words back into a hex string.
///
/// The word list length must be a multiple of 3. Each 3 words produce 8 hex
/// chars.
///
/// Algorithm (matching `mn_decode` in old_mnemonic.py):
/// ```text
/// w1 = index(word1)
/// w2 = index(word2)
/// w3 = index(word3)
/// x = w1 + N * ((w2 - w1) % N) + N*N * ((w3 - w2) % N)
/// → format(x, '08x')
/// ```
pub fn mn_decode(wlist: &[&str]) -> Result<String, LegacyMnemonicError> {
    if wlist.len() % 3 != 0 {
        return Err(LegacyMnemonicError::InvalidWordCount(wlist.len()));
    }

    let mut out = String::with_capacity(wlist.len() / 3 * 8);
    for chunk in wlist.chunks(3) {
        let w1 = word_index(&chunk[0].to_lowercase())?;
        let w2 = word_index(&chunk[1].to_lowercase())?;
        let w3 = word_index(&chunk[2].to_lowercase())?;

        let n = N as i128;
        let x = (w1 as i128)
            + n * (((w2 as i128) - (w1 as i128)).rem_euclid(n))
            + n * n * (((w3 as i128) - (w2 as i128)).rem_euclid(n));

        let x_u64: u64 = x
            .try_into()
            .map_err(|_| LegacyMnemonicError::Overflow)?;
        out.push_str(&format!("{:08x}", x_u64));
    }
    Ok(out)
}

/// Look up the index of a word in the wordlist (linear search, like Python `index()`).
fn word_index(word: &str) -> Result<usize, LegacyMnemonicError> {
    LEGACY_WORDS
        .iter()
        .position(|&w| w == word)
        .ok_or_else(|| LegacyMnemonicError::WordNotFound(word.to_string()))
}

/// A legacy mnemonic phrase (owned words + the original hex it encodes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyMnemonic {
    /// The mnemonic words.
    pub words: Vec<String>,
    /// The hex string the words encode.
    pub hex: String,
}

impl LegacyMnemonic {
    /// Create a legacy mnemonic from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, LegacyMnemonicError> {
        let words: Vec<String> = mn_encode(hex)?
            .into_iter()
            .map(String::from)
            .collect();
        Ok(Self {
            words,
            hex: hex.to_string(),
        })
    }

    /// Recover the hex from a mnemonic word list.
    pub fn from_words(words: &[&str]) -> Result<Self, LegacyMnemonicError> {
        let hex = mn_decode(words)?;
        Ok(Self {
            words: words.iter().map(|s| s.to_string()).collect(),
            hex,
        })
    }

    /// Verify that the words decode back to the stored hex.
    pub fn verify(&self) -> bool {
        let refs: Vec<&str> = self.words.iter().map(|s| s.as_str()).collect();
        mn_decode(&refs)
            .map(|decoded| decoded == self.hex)
            .unwrap_or(false)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_has_1626_words() {
        assert_eq!(LEGACY_WORDS.len(), 1626);
        assert_eq!(N, 1626);
    }

    #[test]
    fn test_wordlist_no_duplicates() {
        let mut sorted: Vec<&str> = LEGACY_WORDS.to_vec();
        sorted.sort();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), before, "wordlist has duplicates");
    }

    #[test]
    fn test_first_and_last_words() {
        assert_eq!(LEGACY_WORDS[0], "like");
        assert_eq!(LEGACY_WORDS[1], "just");
        assert_eq!(LEGACY_WORDS[2], "love");
        assert_eq!(LEGACY_WORDS[1625], "weary");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let hex = "deadbeefcafebabe";
        let encoded = mn_encode(hex).expect("encode");
        assert_eq!(encoded.len(), 6); // 16 hex chars / 8 = 2 chunks * 3 words
        let decoded = mn_decode(&encoded).expect("decode");
        assert_eq!(decoded, hex);
    }

    #[test]
    fn test_encode_decode_all_zeros() {
        let hex = "0000000000000000";
        let encoded = mn_encode(hex).expect("encode");
        let decoded = mn_decode(&encoded).expect("decode");
        assert_eq!(decoded, hex);
    }

    #[test]
    fn test_encode_decode_max_value() {
        let hex = "ffffffffffffffff";
        let encoded = mn_encode(hex).expect("encode");
        let decoded = mn_decode(&encoded).expect("decode");
        assert_eq!(decoded, hex);
    }

    #[test]
    fn test_encode_invalid_hex_length() {
        assert!(mn_encode("abc").is_err());
        assert!(mn_encode("abcdef0").is_err());
    }

    #[test]
    fn test_decode_invalid_word_count() {
        assert!(mn_decode(&["like", "just"]).is_err());
        assert!(mn_decode(&["like", "just", "love", "know"]).is_err());
    }

    #[test]
    fn test_decode_unknown_word() {
        assert!(mn_decode(&["like", "just", "NOTAWORD"]).is_err());
    }

    #[test]
    fn test_legacy_mnemonic_roundtrip() {
        let hex = "0123456789abcdef";
        let mnemonic = LegacyMnemonic::from_hex(hex).expect("from_hex");
        assert!(mnemonic.verify(), "words should decode back to hex");
        let refs: Vec<&str> = mnemonic.words.iter().map(|s| s.as_str()).collect();
        let recovered = LegacyMnemonic::from_words(&refs).expect("from_words");
        assert_eq!(recovered.hex, hex);
    }
}