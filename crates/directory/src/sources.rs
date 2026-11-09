//! What to fetch. Only these URLs are ever fetched: never a URL taken from a
//! request (`Signature-Agent` is attacker-controlled, so fetching it would let
//! any client make this service issue requests).

/// A published IP range file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeSource {
    /// Range set id, as named by `eunox_core::Agent::ip_ranges`.
    pub id: String,
    /// File URL. All seed files use Google's `{"prefixes": [{"ipv4Prefix"}]}`
    /// format.
    pub url: String,
}

/// A Web Bot Auth key directory (`/.well-known/http-message-signatures-directory`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySource {
    /// Operator the keys belong to, as named by `eunox_core::Agent::operator`.
    pub operator: String,
    /// Directory URL.
    pub url: String,
}

/// Everything to fetch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sources {
    /// IP range files.
    pub ranges: Vec<RangeSource>,
    /// Key directories.
    pub keys: Vec<KeySource>,
}

impl Sources {
    /// Seed sources for the operators in the project plan.
    ///
    /// Checked against operator documentation on 2026-11-08:
    /// - OpenAI: developers.openai.com/api/docs/bots
    /// - Anthropic: support.claude.com article 8896518
    /// - Perplexity: docs.perplexity.ai/docs/resources/perplexity-crawlers
    /// - Google: developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
    /// - Common Crawl: commoncrawl.org/ccbot
    ///
    /// Key directories were found by probing each operator's well-known path.
    /// Only OpenAI and Google served one; Anthropic, Perplexity and Common
    /// Crawl returned 404 at the hosts tried.
    pub fn seed() -> Self {
        let range = |id: &str, url: &str| RangeSource {
            id: id.into(),
            url: url.into(),
        };
        let key = |operator: &str, url: &str| KeySource {
            operator: operator.into(),
            url: url.into(),
        };
        const GOOGLE: &str = "https://developers.google.com/static/crawling/ipranges";
        Self {
            ranges: vec![
                range("openai-gptbot", "https://openai.com/gptbot.json"),
                range("openai-searchbot", "https://openai.com/searchbot.json"),
                range(
                    "openai-chatgpt-user",
                    "https://openai.com/chatgpt-user.json",
                ),
                range("openai-adsbot", "https://openai.com/adsbot.json"),
                range("anthropic", "https://claude.com/crawling/bots.json"),
                range(
                    "perplexity-bot",
                    "https://www.perplexity.ai/perplexitybot.json",
                ),
                range(
                    "perplexity-user",
                    "https://www.perplexity.ai/perplexity-user.json",
                ),
                range(
                    "google-common-crawlers",
                    &format!("{GOOGLE}/common-crawlers.json"),
                ),
                range(
                    "google-user-triggered-agents",
                    &format!("{GOOGLE}/user-triggered-agents.json"),
                ),
                range(
                    "commoncrawl-ccbot",
                    "https://index.commoncrawl.org/ccbot.json",
                ),
            ],
            keys: vec![
                key(
                    "openai",
                    "https://chatgpt.com/.well-known/http-message-signatures-directory",
                ),
                key(
                    "google",
                    "https://agent.bot.goog/.well-known/http-message-signatures-directory",
                ),
            ],
        }
    }
}
