//! The server side: verifying proofs and recording entitlements.
//!
//! Account-bound endpoints stay in each app, as thin server functions that
//! call into this module with the app's own user. Webhooks and license
//! routes need no session, so this module provides them as routes.

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
