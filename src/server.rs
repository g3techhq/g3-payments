//! The server side: verifying proofs and recording entitlements.
//!
//! Account-bound endpoints stay in each app, as thin server functions that
//! call into this module with the app's own user. Webhooks and license
//! routes need no session, so this module provides them as routes.
//!
//! Every provider call goes through [`http_client`], whose TLS runs on ring,
//! the same crypto the rest of the crate uses. Tokens for Apple's and
//! Google's APIs are signed with ring too ([`jwt`]), so no second crypto
//! backend enters an app's build through this crate.

use crate::entitlements::{ProductKey, Provider};

pub mod routes;
pub mod service;
pub mod store;

#[cfg(feature = "stripe")]
pub mod stripe;

#[cfg(feature = "app-store")]
pub mod app_store;

#[cfg(feature = "play")]
pub mod play;

#[cfg(feature = "license-server")]
pub mod license_keys;

#[cfg(feature = "surreal")]
pub mod surreal;

#[cfg(any(feature = "app-store", feature = "play"))]
pub(crate) mod jwt;

/// A purchase a provider confirmed, ready to become an entitlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPurchase {
    pub provider: Provider,
    pub product: ProductKey,
    /// The provider's stable id for the purchase: Apple's original
    /// transaction id, Play's purchase token, Stripe's payment or
    /// subscription id. Ownership is keyed on it.
    pub id: String,
    /// Other ids the provider uses for the same purchase (a later Apple
    /// transaction id, a Play order id), claimed together with `id`.
    pub aliases: Vec<String>,
    /// The account token the app attached when it started the purchase, if
    /// any. A purchase made signed out has none.
    pub account_token: Option<String>,
    /// When a subscription's paid period ends; `None` for a one-time
    /// purchase.
    pub expires_at_unix: Option<i64>,
}

/// Why a proof did not verify. The messages name the check, never the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof is malformed or disagrees with itself.
    InvalidProof,
    /// The product is not in the app's catalog for this provider.
    UnknownProduct,
    /// This kind of product is not verified for this provider yet.
    Unsupported,
    /// The provider has no such purchase.
    NotFound,
    /// The provider knows the purchase, but it is not a current purchase of
    /// this product for this app (refunded, pending, another app's, another
    /// product).
    Rejected,
    /// The provider could not be reached or answered with an error. Worth
    /// retrying.
    Unavailable(String),
    /// The server's credentials for the provider are missing or unusable.
    Configuration(String),
}

impl VerifyError {
    /// Whether retrying the same proof later could succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => f.write_str("invalid_purchase_proof"),
            Self::UnknownProduct => f.write_str("unknown_product"),
            Self::Unsupported => f.write_str("unsupported_product_kind"),
            Self::NotFound => f.write_str("purchase_not_found"),
            Self::Rejected => f.write_str("purchase_rejected"),
            Self::Unavailable(detail) => write!(f, "provider_unavailable: {detail}"),
            Self::Configuration(detail) => write!(f, "provider_configuration: {detail}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<reqwest::Error> for VerifyError {
    fn from(error: reqwest::Error) -> Self {
        // The URL can carry a purchase token (Play puts it in the path).
        Self::Unavailable(error.without_url().to_string())
    }
}

/// The HTTP client every provider call uses: a 15 second timeout, and TLS
/// on ring. Installing ring as rustls' default provider is a no-op when the
/// app already installed one.
#[cfg_attr(
    not(any(
        feature = "app-store",
        feature = "play",
        feature = "stripe",
        feature = "license-server"
    )),
    allow(dead_code, reason = "Used by the provider features.")
)]
pub(crate) fn http_client() -> Result<reqwest::Client, VerifyError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| VerifyError::Configuration(error.without_url().to_string()))
}

/// Seconds since the Unix epoch.
#[cfg_attr(
    not(any(
        feature = "app-store",
        feature = "play",
        feature = "stripe",
        feature = "license-server"
    )),
    allow(dead_code, reason = "Used by the provider features.")
)]
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// A required environment variable, with `\n` escapes turned into newlines
/// so a PEM key fits on one line of an env file.
#[cfg_attr(
    not(any(
        feature = "app-store",
        feature = "play",
        feature = "stripe",
        feature = "license-server"
    )),
    allow(dead_code, reason = "Used by the provider features.")
)]
pub(crate) fn env_value(name: &str) -> Result<String, VerifyError> {
    std::env::var(name)
        .ok()
        .map(|value| value.replace("\\n", "\n"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| VerifyError::Configuration(format!("{name} is not set")))
}
