# Changelog

All notable changes to `g3-payments` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- README: running `g3-payments-server` for any app (image, settings, Stripe
  setup, routes). The image is labelled with its source repository.
- `license` (feature `license`): the 14-day trial clock, which never runs
  backwards when the clock is set back; the Ed25519-signed license file,
  checked offline and bound to one app and machine; `LicenseState`, kept in
  the app's data folder; and `LicenseClient` for activation, the 30-day
  re-check and deactivation. A re-check locks only on an answer of
  `revoked`; a server that cannot be reached never locks anyone out. Builds
  for the browser and phones too.
- `server::license_keys` (feature `license-server`): license keys
  (`TALLY-XXXXX-...`), machine-limited activation (`Activations`), license
  signing (`LicenseSigner`), and the routes
  `POST /apps/{app}/licenses/{activate,check,deactivate}`. A refund revokes
  the key on every machine.
- `server::surreal` (feature `surreal`): `SurrealStore`, the `Store` and
  `Activations` on SurrealDB, several apps to one database, with its schema
  in `SCHEMA`.
- `StripeClient::checkout_status`, for a Checkout return page.
- `g3-payments-server` (feature `standalone`): Stripe Checkout and license
  keys for apps with no server of their own, several apps per process,
  configured from the environment. `GET /apps/{app}/buy` starts Checkout
  for a new key and `/thanks` shows it once paid; each app has its own
  webhook at `/api/v1/apps/{app}/stripe_webhooks`. `migrate start`, and
  `gen-key` for a new signing key. A Dockerfile builds its image with the
  pinned `ci/server.Cargo.lock`.
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
- `server::stripe` (feature `stripe`): `verify_signature` and
  `Event::verified` for webhooks; `route_event` turns an event into a
  `StripeAction` (grant a paid one-time checkout, revoke on a full refund,
  re-read a subscription) and ignores events tagged for another app;
  `StripeClient` creates checkouts (one-time or subscription, tagged with
  `g3_app`, `user_id` and `product_key`), customers and portal links, and
  reads, finds and cancels subscriptions. Talks to Stripe's REST API
  directly at API version `2026-08-26.dahlia`, retrying network errors, 429s
  and 5xxs only where an idempotency key makes that safe. Reads both apps'
  existing env var names. `CheckoutRequest::params` passes extra top-level
  Checkout parameters, without replacing any the request sets.
- `server::store`: the `Store` trait an app implements over its own
  database (record, update, owner lookups, account tokens, snapshots, event
  de-duplication), and `MemoryStore` for tests. Every write carries its
  provider event time and the newest wins, including an update that arrives
  before the purchase it changes.
- `server::service`: `PaymentsService` ties the catalog, a store and the
  provider clients together: `verify_native` (claimed for a signed-in
  account, or a device-only grant when signed out), `checkout`,
  `handle_stripe_webhook` and `handle_app_store_notification`. A purchase
  another account holds is `NeedsOriginalAccount` or a `Conflict` outcome,
  never a retry.
- `Store::record_stripe_subscription` and `Store::record_app_store`, with
  defaults that do what `PaymentsService` did before, so a store can keep a
  subscription's raw status, scheduled cancellation and auto-renewal, and
  choose the account a subscription event belongs to (Greenside Partee keeps
  them on its `User`). `SubscriptionChange` carries the event.
- `SubscriptionStatus::is_terminal`. A subscription with a `cancel_at` time
  (how the billing portal schedules a cancellation) reads as
  `cancel_at_period_end`, and `StripeClient::find_customer_subscription`
  returns the newest one that is not over among the customer's ten newest,
  as Greenside Partee's gateway did.
- `server::routes`: `POST /stripe_webhooks` and
  `POST /app_store_notifications`, the paths both apps already use, for an
  app to mount under `/api/v1`.
