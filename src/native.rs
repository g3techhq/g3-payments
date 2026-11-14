//! Store purchases on iOS and Android.
//!
//! A coordinator over g3-native-plugins' StoreKit and Play Billing: each
//! purchase the store reports is checkpointed, verified, recorded, and only
//! then finished with the store. A failure at any step keeps the receipt for
//! retry and finishes nothing.
