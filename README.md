# g3-payments

Purchases, subscriptions, trials and license keys for G3 apps. Every way of
paying (Stripe, the App Store, Google Play, a signed license file) ends in the
same entitlement snapshot, so app code asks one question: does this user own
this product?

**Status: early.** `entitlements`, `catalog` and `apple-jws` work. The
`native`, `license` and `server` features are still empty; their code moves
in from Swift Circuits and Greenside Partee next.

```rust
use g3_payments::{
    EntitlementSnapshot,
    catalog::{Catalog, CatalogProduct, PurchaseKind},
};

let catalog = Catalog::new(vec![
    CatalogProduct::new("full_game", PurchaseKind::OneTime)
        .stripe_price(std::env::var("STRIPE_PRICE_FULL_GAME")?)
        .store_id("com.example.game.full_game"),
])?;

let snapshot: EntitlementSnapshot = /* verified by the server */;
if snapshot.owns("full_game") { /* unlock */ }
```

Use `owns_at(product, now)` wherever a subscription can be involved: `owns`
ignores expiry.

## Features

| Feature | Side | What it adds |
| --- | --- | --- |
| (none) | everywhere | `entitlements` and `catalog`: the shared types |
| `apple-jws` | client and server | Checks Apple's signed data to Apple Root CA - G3 |
| `native` | iOS, Android | Purchase coordinator over g3-native-plugins' StoreKit and Play Billing |
| `license` | desktop, mobile | Trial clock, offline license check, activation |
| `server` | server | `PaymentsService`, the `Store` trait, webhook and license routes |
| `stripe` | server | Checkout, subscriptions, billing portal, webhooks |
| `app-store` | server | App Store Server API and Notifications V2 |
| `play` | server | Google Play Developer API verification |
| `license-server` | server | Issuing, activating and signing licenses |
| `surreal` | server | The `Store` trait on SurrealDB |

Turn on client features in the app's client build and server features in its
`server` feature only, so no server dependency reaches a browser or phone
build.

## Using it

Until Dioxus 0.8.0 ships, apps take `main` by git:

```toml
[dependencies]
g3-payments = { version = "0.1", features = ["native"] }

[patch.crates-io]
g3-payments = { git = "https://github.com/g3techhq/g3-payments", branch = "main" }
```

## License

MIT or Apache-2.0, at your option.
