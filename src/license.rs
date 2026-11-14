//! Trials and license keys for apps sold outside an app store.
//!
//! An app without a server of its own (SkiCut, Tally) sells through
//! `g3-payments-server`: the buyer pays in Stripe Checkout and gets a license
//! key; the app activates the key for this machine and keeps the signed
//! license file it gets back. Until then it runs on a 14-day trial.
//!
//! - [`file`]: the signed license file, checked offline with the app's
//!   Ed25519 public key.
//! - [`state`]: what the app keeps in its own data folder (never inside a
//!   document a user shares between machines): the trial clock, this
//!   machine's id, the key and its license file. [`LicenseState::access`]
//!   says what the app may do now.
//! - [`client`]: activation, the periodic re-check and deactivation, against
//!   the server.
//!
//! The re-check locks the app only when the server answers that the license
//! was revoked (a refund, or this machine was deactivated). A server that
//! cannot be reached never locks anyone out.

pub mod client;
pub mod file;
pub mod state;

pub use client::{ActivateError, CheckOutcome, LicenseClient};
pub use file::{LicenseClaims, LicenseFileError, key_id, normalize_key};
pub use state::{Access, LicenseState};

/// How long a trial lasts.
pub const TRIAL_DAYS: i64 = 14;

/// How often a licensed app asks the server whether its license still
/// stands.
pub const RECHECK_SECS: i64 = 30 * DAY_SECS;

pub(crate) const DAY_SECS: i64 = 24 * 60 * 60;

/// Seconds since the Unix epoch, by this machine's clock.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}
