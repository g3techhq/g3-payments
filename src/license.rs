//! Trials and license keys for apps sold outside an app store.
//!
//! The trial clock, the offline check of a signed license file, activation,
//! and a periodic re-check. The re-check locks an app only when the server
//! answers that a license was revoked; a server that cannot be reached never
//! locks anyone out.
