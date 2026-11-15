# g3-payments

Purchases, subscriptions, trials and license keys for apps. Every way of
paying (Stripe, the App Store, Google Play, a signed license file) ends in the
same entitlement snapshot, so app code asks one question: does this user own
this product? G3 apps use it, and nothing in it is specific to them.

**Status: early.** The shared types, Apple signed-data checks, Stripe, license
keys with trials, the SurrealDB store and the standalone server work. The
`native` store coordinator, `app-store` and `play` are still being filled in.

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
| `standalone` | server | The `g3-payments-server` binary, below |

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

## The standalone server

`g3-payments-server` sells one-time license keys through Stripe Checkout for
apps that have no server of their own, and activates and re-checks them. One
server can sell several apps. It needs SurrealDB 3 and a Stripe account.

```bash
docker pull ghcr.io/g3techhq/g3-payments-server:latest
# or build it from a clean checkout:
git archive HEAD | docker build -t g3-payments-server -
```

The image listens on port 8080 and runs as an unprivileged user.

### Settings

| Variable | |
| --- | --- |
| `PUBLIC_URL` | The server's public origin, such as `https://pay.example.com`. Checkout returns here. |
| `PORT` | Default `8080`. |
| `STRIPE_SECRET_KEY` | A secret key, or a restricted key with Checkout Sessions read and write. |
| `G3_PAYMENTS_APPS` | The app ids it sells, comma separated: lower-case letters, digits and `-`. |
| `SURREALDB_HOST` | Default `ws://127.0.0.1:8000`. |
| `SURREALDB_NAMESPACE`, `SURREALDB_NAME` | Default `g3-payments` and `production`. |
| `SURREALDB_USER`, `SURREALDB_PASSWORD` | Optional sign-in. |
| `SURREALDB_AUTH_LEVEL` | `root` (default), `namespace` or `database`. |

Per app, with its id upper-cased and `-` made `_` (`my-app` → `MY_APP`):

| Variable | |
| --- | --- |
| `<APP>_STRIPE_PRICE` | A one-time Stripe price (`price_...`). |
| `<APP>_STRIPE_WEBHOOK_SECRET` | The signing secret (`whsec_...`) of the app's webhook endpoint. |
| `<APP>_LICENSE_SIGNING_KEY` | The seed from `gen-key`. |
| `<APP>_NAME` | Shown on the buy pages. Default: the id. |
| `<APP>_PRODUCT` | The product key licenses grant. Default `<id>_full`. |
| `<APP>_MACHINE_LIMIT` | Computers one key may activate. Default `3`. |

Every setting that is missing is named at once, and the server will not start
without them.

### Setting up an app

1. `g3-payments-server gen-key` prints a signing seed for the server and the
   public key the app checks licenses with. Keep the seed secret and backed
   up: a new one strands every license issued under the old one.
2. In Stripe, make a product with one one-time price, and a webhook endpoint
   at `<PUBLIC_URL>/api/v1/apps/<app>/stripe_webhooks` for
   `checkout.session.completed`, `checkout.session.async_payment_succeeded`
   and `charge.refunded`.
3. Set the app's variables and start the server. It loads its schema at
   start; `g3-payments-server migrate start` does that on its own, for a
   migration job with more database rights than the server.
4. In the app, with the `license` feature: `LicenseClient::new(PUBLIC_URL, app)`
   activates and re-checks keys (`buy_url()` is the page that starts
   Checkout), and `LicenseState::access(app, public_key, now)` runs the trial
   and verifies the stored license file offline against the public key from
   step 1.

### Routes

| Route | |
| --- | --- |
| `GET /` | The apps on sale |
| `GET /apps/<app>/buy` | Starts Checkout |
| `GET /apps/<app>/thanks`, `/cancelled` | Checkout's return pages; thanks shows the key |
| `POST /api/v1/apps/<app>/stripe_webhooks` | Stripe events; unsigned requests get 400 |
| `POST /api/v1/apps/<app>/licenses/{activate,check,deactivate}` | Used by `LicenseClient` |
| `GET /healthz`, `/api/v1/health/ready` | Liveness, and readiness including the database |

## License

MIT or Apache-2.0, at your option.
