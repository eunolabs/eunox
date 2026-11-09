//! Known agents: how each one identifies itself and how it can be verified.
//!
//! The data lives in `data/agents.toml`, embedded as [`Catalog::seed`]; see
//! that file for provenance and which entries are still unverified.
//! [`Catalog::from_toml`] parses the same format from a string the caller
//! has read, so this module stays I/O-free.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use sfv::{ListEntry, Parser};

/// One agent a request can claim to be.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// Stable eunox id, e.g. `openai-gptbot`. Policy will name these.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Operator id. Must match [`crate::Key::operator`] for keys from this
    /// operator's directory.
    pub operator: String,
    /// User-agent product tokens, matched case-insensitively as whole tokens.
    #[serde(default)]
    pub user_agent_tokens: Vec<String>,
    /// `Signature-Agent` origins (`https://host`) this agent signs with.
    #[serde(default)]
    pub signature_agents: Vec<String>,
    /// Id of the published IP range set covering this agent, if any. The
    /// `directory` crate maps ids to the operator's range files.
    #[serde(default)]
    pub ip_ranges: Option<String>,
    /// Hostname suffixes accepted by forward-confirmed reverse DNS, if the
    /// operator documents that method.
    #[serde(default)]
    pub rdns_suffixes: Vec<String>,
}

impl Agent {
    /// Whether forward-confirmed reverse DNS can verify this agent. When it
    /// can and the IP isn't in its published ranges, do the lookup before
    /// classifying, or the request can only come out unverifiable.
    pub fn uses_rdns(&self) -> bool {
        !self.rdns_suffixes.is_empty()
    }

    /// Whether `hostname` is under one of this agent's reverse-DNS suffixes.
    pub fn rdns_matches(&self, hostname: &str) -> bool {
        let host = hostname.trim_end_matches('.').to_ascii_lowercase();
        self.rdns_suffixes.iter().any(|suffix| {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            host == suffix
                || host
                    .strip_suffix(&suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

/// The set of known agents.
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    agents: Vec<Agent>,
}

impl Catalog {
    /// A catalog from explicit entries, unvalidated. Prefer
    /// [`Catalog::from_toml`] for anything user-supplied.
    pub fn new(agents: Vec<Agent>) -> Self {
        Self { agents }
    }

    /// All entries, in file order.
    pub fn agents(&self) -> &[Agent] {
        &self.agents
    }

    /// Entry by id.
    pub fn get(&self, id: &str) -> Option<&Agent> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// Entries for an operator.
    pub fn by_operator(&self, operator: &str) -> Vec<&Agent> {
        self.agents
            .iter()
            .filter(|a| a.operator == operator)
            .collect()
    }

    /// The agent with the longest token appearing in `user_agent`, so a
    /// specific token beats a generic one regardless of entry order. Ties go
    /// to the earlier entry.
    pub fn match_user_agent(&self, user_agent: &str) -> Option<&Agent> {
        let mut best: Option<(&Agent, usize)> = None;
        for a in &self.agents {
            for t in &a.user_agent_tokens {
                if best.is_none_or(|(_, len)| t.len() > len) && contains_token(user_agent, t) {
                    best = Some((a, t.len()));
                }
            }
        }
        best.map(|(a, _)| a)
    }

    /// The agent whose origin `url` is under, if any.
    pub fn match_signature_agent(&self, url: &str) -> Option<&Agent> {
        let origin = origin_of(url)?;
        self.agents.iter().find(|a| {
            a.signature_agents
                .iter()
                .any(|s| origin_of(s).is_some_and(|o| o == origin))
        })
    }

    /// The built-in list, embedded from `data/agents.toml`: OpenAI,
    /// Anthropic, Perplexity, Google and Common Crawl.
    pub fn seed() -> Self {
        Self::from_toml(SEED_TOML).expect("embedded data/agents.toml is valid")
    }

    /// Parse a catalog from TOML in the format of `data/agents.toml`: an
    /// `[[agent]]` array of tables. Pure: the caller reads the file.
    pub fn from_toml(source: &str) -> Result<Self, CatalogError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            #[serde(default)]
            agent: Vec<Agent>,
        }
        let file: File =
            toml::from_str(source).map_err(|e| CatalogError::Parse(e.to_string()))?;
        validate(&file.agent)?;
        Ok(Self::new(file.agent))
    }
}

/// The embedded seed catalog.
const SEED_TOML: &str = include_str!("../data/agents.toml");

/// Why a catalog was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// Not valid TOML, or doesn't match the schema (including unknown fields).
    Parse(String),
    /// `id`, `name` or `operator` is empty.
    MissingField {
        /// The agent's id, possibly empty.
        id: String,
        /// The empty field.
        field: &'static str,
    },
    /// Two entries share an id.
    DuplicateId(String),
    /// Neither a user-agent token nor a signature agent, so it can never match.
    Unmatchable(String),
    /// An empty user-agent token or reverse-DNS suffix.
    EmptyValue {
        /// The agent's id.
        id: String,
        /// The field holding the empty value.
        field: &'static str,
    },
    /// A signature agent that isn't an `http(s)` origin.
    BadSignatureAgent {
        /// The agent's id.
        id: String,
        /// The offending value.
        value: String,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "invalid catalog: {e}"),
            Self::MissingField { id, field } => write!(f, "agent {id:?}: {field} is empty"),
            Self::DuplicateId(id) => write!(f, "agent {id:?} appears more than once"),
            Self::Unmatchable(id) => write!(
                f,
                "agent {id:?} has no user_agent_tokens or signature_agents, so nothing can match it"
            ),
            Self::EmptyValue { id, field } => write!(f, "agent {id:?}: empty entry in {field}"),
            Self::BadSignatureAgent { id, value } => write!(
                f,
                "agent {id:?}: signature agent {value:?} is not an http(s) origin"
            ),
        }
    }
}

impl std::error::Error for CatalogError {}

fn validate(agents: &[Agent]) -> Result<(), CatalogError> {
    let mut seen = HashSet::new();
    for a in agents {
        for (field, value) in [("id", &a.id), ("name", &a.name), ("operator", &a.operator)] {
            if value.trim().is_empty() {
                return Err(CatalogError::MissingField {
                    id: a.id.clone(),
                    field,
                });
            }
        }
        if !seen.insert(a.id.as_str()) {
            return Err(CatalogError::DuplicateId(a.id.clone()));
        }
        if a.user_agent_tokens.is_empty() && a.signature_agents.is_empty() {
            return Err(CatalogError::Unmatchable(a.id.clone()));
        }
        for (field, values) in [
            ("user_agent_tokens", &a.user_agent_tokens),
            ("rdns_suffixes", &a.rdns_suffixes),
        ] {
            if values.iter().any(|v| v.trim().is_empty()) {
                return Err(CatalogError::EmptyValue {
                    id: a.id.clone(),
                    field,
                });
            }
        }
        if let Some(bad) = a.signature_agents.iter().find(|s| origin_of(s).is_none()) {
            return Err(CatalogError::BadSignatureAgent {
                id: a.id.clone(),
                value: bad.clone(),
            });
        }
    }
    Ok(())
}

/// Case-insensitive whole-token match: `token` must not be preceded or
/// followed by a letter or digit, so `GPTBot` doesn't match `XGPTBotX`.
pub fn contains_token(haystack: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let hay = haystack.to_ascii_lowercase();
    let tok = token.to_ascii_lowercase();
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    hay.match_indices(&tok).any(|(i, _)| {
        !is_word(hay[..i].chars().next_back()) && !is_word(hay[i + tok.len()..].chars().next())
    })
}

/// `scheme://host[:port]`, lowercased, from an `http(s)` URL.
fn origin_of(url: &str) -> Option<String> {
    let lower = url.trim().to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// Directory URLs named in a `Signature-Agent` header, without verifying
/// anything. Accepts the dictionary form (`agent1="https://..."`) and the
/// older single-string form.
pub fn signature_agent_urls(header: &str) -> Vec<String> {
    if let Ok(item) = Parser::new(header).parse_item() {
        return item
            .bare_item
            .as_string()
            .map(|s| vec![s.as_str().to_owned()])
            .unwrap_or_default();
    }
    match Parser::new(header).parse_dictionary() {
        Ok(dict) => dict
            .values()
            .filter_map(|entry| match entry {
                ListEntry::Item(item) => item.bare_item.as_string().map(|s| s.as_str().to_owned()),
                ListEntry::InnerList(_) => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// HTTP client libraries and automation tools, matched as substrings.
/// Seeded from AgentSniff's `automation_user_agent_tokens`.
const AUTOMATION_TOKENS: &[&str] = &[
    "python-requests",
    "python-urllib",
    "python-httpx",
    "aiohttp",
    "go-http-client",
    "curl/",
    "wget/",
    "node-fetch",
    "undici",
    "axios/",
    "okhttp/",
    "libwww-perl",
    "java-http-client",
    "apache-httpclient",
    "scrapy",
    "headlesschrome",
];

/// Phone brands whose names end in "bot".
const NOT_BOTS: &[&str] = &["cubot"];

/// If `user_agent` looks like a crawler or automation client, the word or
/// token that gave it away.
pub fn generic_bot_marker(user_agent: &str) -> Option<String> {
    let lower = user_agent.to_ascii_lowercase();
    if let Some(t) = AUTOMATION_TOKENS.iter().find(|t| lower.contains(*t)) {
        return Some((*t).to_owned());
    }
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|word| {
            !NOT_BOTS.contains(word)
                && ((word.len() > 3 && word.ends_with("bot"))
                    || word.contains("crawler")
                    || word.contains("spider")
                    || word.contains("scraper"))
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_token_matching() {
        assert!(contains_token(
            "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "GPTBot"
        ));
        assert!(contains_token("gptbot", "GPTBot"));
        assert!(!contains_token("NotGPTBotReally", "GPTBot"));
        assert!(contains_token("Googlebot-Image/1.0", "Googlebot"));
        assert!(!contains_token("anything", ""));
    }

    #[test]
    fn similar_tokens_resolve_to_the_right_agent() {
        let c = Catalog::seed();
        let id = |ua| c.match_user_agent(ua).map(|a| a.id.as_str());
        assert_eq!(id("Claude-User/1.0"), Some("anthropic-claude-user"));
        assert_eq!(
            id("Claude-SearchBot/1.0"),
            Some("anthropic-claude-searchbot")
        );
        assert_eq!(
            id("Mozilla/5.0 (compatible; ClaudeBot/1.0)"),
            Some("anthropic-claudebot")
        );
        assert_eq!(id("Mozilla/5.0 Chrome/131.0"), None);
    }

    #[test]
    fn seed_parses() {
        let c = Catalog::seed();
        assert_eq!(c.agents().len(), 14);
        let g = c.get("google-agent").unwrap();
        assert_eq!(g.operator, "google");
        assert_eq!(g.signature_agents, ["https://agent.bot.goog"]);
        assert_eq!(g.ip_ranges.as_deref(), Some("google-user-triggered-agents"));
        // Its reverse-DNS names include customer-controlled googleusercontent.com.
        assert!(!g.uses_rdns());
        let chatgpt = c.get("openai-chatgpt-agent").unwrap();
        assert!(chatgpt.user_agent_tokens.is_empty());
        assert_eq!(chatgpt.ip_ranges, None);
    }

    #[test]
    fn longest_token_wins_regardless_of_order() {
        let two = |first: &str, second: &str| format!("[[agent]]\n{first}\n[[agent]]\n{second}\n");
        let generic = r#"id = "g"
name = "G"
operator = "x"
user_agent_tokens = ["Googlebot"]"#;
        let specific = r#"id = "gi"
name = "GI"
operator = "x"
user_agent_tokens = ["Googlebot-Image"]"#;
        for c in [
            Catalog::from_toml(&two(generic, specific)).unwrap(),
            Catalog::from_toml(&two(specific, generic)).unwrap(),
        ] {
            let id = |ua| c.match_user_agent(ua).map(|a| a.id.as_str());
            assert_eq!(id("Googlebot-Image/1.0"), Some("gi"));
            assert_eq!(id("Googlebot/2.1"), Some("g"));
        }
    }

    #[test]
    fn rejects_bad_catalogs() {
        let one = |body: &str| Catalog::from_toml(&format!("[[agent]]\n{body}"));
        let base = "id = \"a\"\nname = \"A\"\noperator = \"o\"\n";
        assert!(one(&format!("{base}user_agent_tokens = [\"A\"]")).is_ok());
        assert!(matches!(
            one(&format!("{base}user_agent_tokens = [\"A\"]\nip_range = \"typo\"")),
            Err(CatalogError::Parse(_))
        ));
        assert_eq!(
            one(base).unwrap_err(),
            CatalogError::Unmatchable("a".into())
        );
        assert_eq!(
            one("id = \"a\"\nname = \"\"\noperator = \"o\"\nuser_agent_tokens = [\"A\"]")
                .unwrap_err(),
            CatalogError::MissingField {
                id: "a".into(),
                field: "name"
            }
        );
        assert!(matches!(
            one(&format!("{base}user_agent_tokens = [\"\"]")),
            Err(CatalogError::EmptyValue { .. })
        ));
        assert!(matches!(
            one(&format!("{base}signature_agents = [\"chatgpt.com\"]")),
            Err(CatalogError::BadSignatureAgent { .. })
        ));
        let dup = format!("[[agent]]\n{base}user_agent_tokens = [\"A\"]\n").repeat(2);
        assert_eq!(
            Catalog::from_toml(&dup).unwrap_err(),
            CatalogError::DuplicateId("a".into())
        );
        assert_eq!(Catalog::from_toml("").unwrap().agents().len(), 0);
    }

    #[test]
    fn signature_agent_origin_matching() {
        let c = Catalog::seed();
        let id = |u| c.match_signature_agent(u).map(|a| a.id.as_str());
        assert_eq!(
            id("https://chatgpt.com/.well-known/http-message-signatures-directory"),
            Some("openai-chatgpt-agent")
        );
        assert_eq!(id("HTTPS://ChatGPT.com"), Some("openai-chatgpt-agent"));
        assert_eq!(id("https://chatgpt.com.evil.example/"), None);
        assert_eq!(id("ftp://chatgpt.com"), None);
    }

    #[test]
    fn parses_both_signature_agent_forms() {
        assert_eq!(
            signature_agent_urls(r#""https://a.example""#),
            vec!["https://a.example"]
        );
        assert_eq!(
            signature_agent_urls(r#"a1="https://a.example", a2="https://b.example""#),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(signature_agent_urls("not( valid").is_empty());
    }

    #[test]
    fn rdns_suffixes() {
        let g = Catalog::seed().get("google-googlebot").unwrap().clone();
        assert!(g.rdns_matches("crawl-66-249-66-1.googlebot.com"));
        assert!(g.rdns_matches("crawl-66-249-66-1.googlebot.com."));
        assert!(g.rdns_matches("GOOGLEBOT.COM"));
        assert!(!g.rdns_matches("evilgooglebot.com"));
        assert!(!g.rdns_matches("googlebot.com.evil.example"));
    }

    #[test]
    fn generic_bots() {
        assert_eq!(generic_bot_marker("curl/8.5.0").as_deref(), Some("curl/"));
        assert_eq!(
            generic_bot_marker("Mozilla/5.0 (compatible; SemrushBot/7)").as_deref(),
            Some("semrushbot")
        );
        assert_eq!(
            generic_bot_marker("MJ12bot/v1.4.8").as_deref(),
            Some("mj12bot")
        );
        assert_eq!(
            generic_bot_marker("Mozilla/5.0 (Linux; Android 10; CUBOT X30)"),
            None
        );
        assert_eq!(
            generic_bot_marker("Mozilla/5.0 (Macintosh) Safari/605.1.15"),
            None
        );
        assert_eq!(
            generic_bot_marker("a web crawler").as_deref(),
            Some("crawler")
        );
    }
}
