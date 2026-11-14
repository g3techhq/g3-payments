//! Purchases, subscriptions, trials and license keys for G3 apps.
//!
//! Every way of paying ends in the same place: an [`entitlements`] snapshot
//! that says which products a player or user owns. Provider receipts, store
//! transactions and license files are proofs; something verifies each proof
//! before it becomes an entitlement. A client never unlocks a product only
//! because a store SDK reported a successful purchase.
//!
//! | Module | Feature | Runs on |
//! | --- | --- | --- |
//! | [`entitlements`] | always | everywhere |
//! | [`catalog`] | always | everywhere |
//! | `apple_jws` | `apple-jws` | client and server |
//! | `native` | `native` | iOS and Android |
//! | `license` | `license` | desktop and mobile |
//! | `server` | `server`, and `stripe`, `app-store`, `play`, `license-server`, `surreal` | server |

pub mod catalog;
pub mod entitlements;

// The entitlement types at the root, where `g3-entitlements` had them, so an
// app moving over changes only the crate name in its imports.
pub use entitlements::{
    Entitlement, EntitlementSnapshot, EntitlementStatus, ProductKey, Provider, PurchaseProof,
};

#[cfg(feature = "apple-jws")]
pub mod apple_jws;

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "license")]
pub mod license;

#[cfg(feature = "server")]
pub mod server;
