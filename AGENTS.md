# AGENTS.md

Instructions for coding agents working in this repository (Claude Code, Codex,
Cursor, Copilot, and anything else that reads `AGENTS.md`). Useful for people
too. Follow these over your defaults.

## What this is

**g3-payments** is how every G3 app takes money and decides what a user owns:

- **entitlements**: the shared types (`ProductKey`, `Provider`, `Entitlement`,
  `EntitlementSnapshot`, `PurchaseProof`), moved here from Swift Circuits'
  `g3-entitlements`;
- **catalog**: an app's product list, mapping a product key to its Stripe
  price and store product ids;
- **client** features: Apple signed-data checks, the native store purchase
  coordinator, and trials and license files for apps sold outside a store;
- **server** features: Stripe, the App Store, Google Play, license keys, and
  a `Store` trait with a SurrealDB implementation.

Used by swift-circuits, greenside-partee, skicut, tally and ad-sentinel.

| Piece | Version | Reference |
| --- | --- | --- |
| Rust | edition 2024 | `rust-toolchain.toml` |

## Map

```
src/lib.rs              Exports, features, and the crate docs
src/entitlements.rs     Who owns what
src/catalog.rs          An app's product list
src/apple_jws.rs        Apple Root CA - G3 checks (feature apple-jws)
src/apple_jws/          Apple's real root certificate, shipped in the crate
testdata/app_store/     A synthetic Apple-style signing chain for tests (generate.sh); not shipped
src/native.rs           StoreKit and Play Billing coordinator (feature native)
src/license.rs          Trial clock and license files (feature license)
src/server.rs           PaymentsService, Store, routes (feature server)
src/server/*.rs         One provider per file, each behind its own feature
CHANGELOG.md            Every user-visible change, under [Unreleased] until a release
```

## Commands

```bash
just check        # every feature on its own, all features, and wasm32
just test         # unit and doc tests
just lint-strict  # clippy with warnings as errors, as CI runs it
just pre-push     # format, check, lint, test, typos
```

## Definition of done

1. `just pre-push` passes.
2. A user-visible change has a line under `## [Unreleased]` in `CHANGELOG.md`.
3. A change to what grants, keeps or revokes an entitlement has a test.
4. A change that reaches a provider was exercised in that provider's sandbox
   or test mode, through a consuming app with a `[patch.crates-io]` path
   override removed afterwards.

If you could not do one of these, say which and why.

---

## Rules

### Proofs and grants

- **A provider's word is a proof, never a grant.** A client unlocks a product
  only from a verified snapshot or a signed license file, never because a
  store SDK or a checkout return page reported success.
- A native store transaction is finished only after its grant is recorded.
- Grants and revocations are idempotent: a webhook or a store report can
  arrive twice, late, or out of order.

### Wire format

- `EntitlementSnapshot` is stored on phones and cached by clients. Its JSON
  must stay readable by every released app: new fields are optional and
  skipped when empty, and new enum variants need a catch-all so an older
  client does not fail to read a newer snapshot. A fixture test pins it.

### Features

- Every server dependency is optional and turned on only by `server` or a
  provider feature. A client feature must build for `wasm32`, iOS and Android.
- Each feature builds on its own; `just check` proves it.

### Licenses

- A license re-check locks an app only when the server answers that the
  license is revoked. A server that cannot be reached never locks anyone out.
- A trial that ends never takes away a user's own data; at most it turns off
  editing.

### Releases

- Releases publish from `publish-crates.yml` (crates.io trusted publishing).
  Do not run `cargo publish` by hand, and do not release without the
  maintainer's go-ahead. Apps take `main` by git until Dioxus 0.8.0 ships.
- Local builds are pointed at sibling checkouts by a config outside the
  repository; never commit a `Cargo.lock` that resolves to local paths.
- Commits follow Conventional Commits; lefthook checks them.

## Readability

Follow [docs/code-style.md](docs/code-style.md) for Rust imports, section spacing
and RSX layout. Run `node scripts/rust-style.mjs --staged` before committing.
