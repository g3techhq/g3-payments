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
