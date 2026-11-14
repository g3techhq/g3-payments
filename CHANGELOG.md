# Changelog

All notable changes to `g3-payments` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The crate's modules and features: `entitlements`, `catalog`, `apple-jws`,
  `native`, `license`, and `server` with `stripe`, `app-store`, `play`,
  `license-server` and `surreal`.
- `entitlements`, moved from Swift Circuits' `g3-entitlements` with its JSON
  unchanged, and re-exported at the crate root. New: `Provider::LicenseKey`;
  `Provider::Unknown` and `EntitlementStatus::Unknown` so a snapshot from a
  newer server still reads (an unknown provider's grant counts, an unknown
  status never does); an optional `expires_at_unix` for subscriptions, left
  out of the JSON when empty; `Entitlement::is_active_at` and
  `EntitlementSnapshot::owns_at`.
- `catalog`: `Catalog`, `CatalogProduct` and `PurchaseKind`. A product list
  is refused if a key, Stripe price or store id names two products, whether
  built in code or read from a config file.
- `apple_jws` (feature `apple-jws`): `SignedDataVerifier`, moved from
  Greenside Partee. Checks Apple's signed data to Apple Root CA - G3, and
  builds for the browser and phones as well as the server.
- `server`: `VerifiedPurchase` and `VerifyError`, shared by every provider.
  TLS and every token signature run on ring, so no second crypto backend
  (aws-lc) enters a server build through this crate.
- `server::play` (feature `play`): `PlayClient` verifies one-time Play
  purchases, moved from Swift Circuits. Subscriptions answer `Unsupported`.
- `server::app_store` (feature `app-store`): `AppStoreClient` verifies
  one-time purchases (from Swift Circuits) and subscriptions (from Greenside
  Partee), and routes App Store Server Notifications V2 for both. Unlike
  Swift Circuits' version, the device's transaction and Apple's API answer
  are both checked to Apple Root CA - G3 before they are read.
