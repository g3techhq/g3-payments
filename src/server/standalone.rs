//! `g3-payments-server`: Stripe Checkout and license keys for apps with no
//! server of their own, several apps per process (feature `standalone`).
//!
//! Configured from the environment, so it fits the same settings files as
//! the other g3 servers:
//!
//! | Variable | |
//! | --- | --- |
//! | `PUBLIC_URL` | the server's origin, such as `https://pay.g3tech.net` |
//! | `PORT` | default `8080` |
//! | `SURREALDB_HOST`, `SURREALDB_USER`, `SURREALDB_PASSWORD`, `SURREALDB_NAMESPACE`, `SURREALDB_NAME` | the database |
//! | `STRIPE_SECRET_KEY` | one Stripe account for every app |
//! | `G3_PAYMENTS_APPS` | the app ids, comma separated: `skicut,tally` |
//!
//! and for each app, its id in upper case with `-` as `_` (`TALLY_...`):
//!
//! | Variable | |
//! | --- | --- |
//! | `<APP>_NAME` | shown on the buy and thanks pages (default: the id) |
//! | `<APP>_PRODUCT` | the product key a license buys (default `<app>_full`) |
//! | `<APP>_STRIPE_PRICE` | its one-time Stripe price |
//! | `<APP>_STRIPE_WEBHOOK_SECRET` | the signing secret of that app's webhook endpoint |
//! | `<APP>_LICENSE_SIGNING_KEY` | the Ed25519 seed, from `g3-payments-server gen-key` |
//! | `<APP>_MACHINE_LIMIT` | machines per key (default 3) |
//!
//! Routes: `GET /healthz`; `GET /apps/{app}/buy` (starts Checkout for a new
//! key), `GET /apps/{app}/thanks` (shows the key once paid); `POST
//! /api/v1/apps/{app}/stripe_webhooks`; and the license routes of
//! [`license_keys::routes`](super::license_keys::routes).

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};

use super::{
    license_keys::{self, LicenseApp, LicenseSigner, generate_key},
    service::{PaymentsService, WebhookFailure},
    stripe::{CheckoutRequest, StripeClient, StripeConfig},
    surreal::SurrealStore,
};
use crate::{
    catalog::{Catalog, CatalogProduct, PurchaseKind},
    entitlements::ProductKey,
};

/// One app on the server, with its store.
pub type App = LicenseApp<SurrealStore, SurrealStore>;

/// Everything the routes need.
pub struct Server {
    pub public_url: String,
    pub apps: Arc<BTreeMap<String, App>>,
    /// Each app's Stripe client, for the thanks page's lookup.
    pub stripe: BTreeMap<String, StripeClient>,
}

/// The settings for one app, before the database is connected.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub id: String,
    pub name: String,
    pub product: String,
    pub stripe_price: String,
    pub webhook_secret: String,
    pub signing_key: String,
    pub machine_limit: u32,
}

/// The server's settings.
#[derive(Clone, Debug)]
pub struct Config {
    pub public_url: String,
    pub port: u16,
    pub stripe_secret: String,
    pub apps: Vec<AppConfig>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required(name: &str, missing: &mut Vec<String>) -> String {
    var(name).unwrap_or_else(|| {
        missing.push(name.to_string());
        String::new()
    })
}

impl Config {
    /// Reads the environment, naming every missing variable at once.
    pub fn from_env() -> Result<Self, String> {
        let mut missing = Vec::new();
        let public_url = required("PUBLIC_URL", &mut missing)
            .trim_end_matches('/')
            .to_string();
        let port = var("PORT").and_then(|p| p.parse().ok()).unwrap_or(8080);
        let stripe_secret = required("STRIPE_SECRET_KEY", &mut missing);
        let ids = required("G3_PAYMENTS_APPS", &mut missing);
        let mut apps = Vec::new();
        for id in ids.split(',').map(str::trim).filter(|id| !id.is_empty()) {
            if !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!(
                    "app id {id:?} must be lower-case letters, digits and -"
                ));
            }
            let prefix = id.to_ascii_uppercase().replace('-', "_");
            let machine_limit = match var(&format!("{prefix}_MACHINE_LIMIT")) {
                Some(limit) => limit
                    .parse()
                    .map_err(|_| format!("{prefix}_MACHINE_LIMIT must be a whole number"))?,
                None => 3,
            };
            apps.push(AppConfig {
                id: id.to_string(),
                name: var(&format!("{prefix}_NAME")).unwrap_or_else(|| id.to_string()),
                product: var(&format!("{prefix}_PRODUCT"))
                    .unwrap_or_else(|| format!("{}_full", id.replace('-', "_"))),
                stripe_price: required(&format!("{prefix}_STRIPE_PRICE"), &mut missing),
                webhook_secret: required(&format!("{prefix}_STRIPE_WEBHOOK_SECRET"), &mut missing),
                signing_key: required(&format!("{prefix}_LICENSE_SIGNING_KEY"), &mut missing),
                machine_limit,
            });
        }
        if !missing.is_empty() {
            return Err(format!("not set: {}", missing.join(", ")));
        }
        if apps.is_empty() {
            return Err("G3_PAYMENTS_APPS names no apps".into());
        }
        Ok(Self {
            public_url,
            port,
            stripe_secret,
            apps,
        })
    }
}

impl Server {
    /// Builds every app's service over `db`.
    pub fn new(
        config: &Config,
        db: surrealdb::Surreal<surrealdb::engine::any::Any>,
    ) -> Result<Self, String> {
        let mut apps = BTreeMap::new();
        let mut clients = BTreeMap::new();
        for app in &config.apps {
            let catalog = Catalog::new(vec![
                CatalogProduct::new(app.product.as_str(), PurchaseKind::OneTime)
                    .stripe_price(app.stripe_price.as_str()),
            ])
            .map_err(|error| format!("{}: {error:?}", app.id))?;
            let stripe = StripeClient::new(StripeConfig {
                secret_key: config.stripe_secret.clone(),
                webhook_secret: app.webhook_secret.clone(),
                app: app.id.clone(),
            });
            clients.insert(app.id.clone(), stripe.clone());
            let store = SurrealStore::new(db.clone(), app.id.as_str());
            apps.insert(
                app.id.clone(),
                LicenseApp {
                    id: app.id.clone(),
                    name: app.name.clone(),
                    product: ProductKey::new(app.product.as_str()),
                    machine_limit: app.machine_limit,
                    signer: LicenseSigner::from_seed(&app.signing_key)
                        .map_err(|error| format!("{}: {error}", app.id))?,
                    service: PaymentsService::new(catalog, store.clone()).with_stripe(stripe),
                    activations: store,
                },
            );
        }
        Ok(Self {
            public_url: config.public_url.clone(),
            apps: Arc::new(apps),
            stripe: clients,
        })
    }

    /// Every route.
    pub fn router(self) -> Router {
        let licenses = license_keys::routes(self.apps.clone());
        let state = Arc::new(self);
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/", get(home))
            .route("/apps/{app}/buy", get(buy))
            .route("/apps/{app}/thanks", get(thanks))
            .route("/apps/{app}/cancelled", get(cancelled))
            .route("/api/v1/apps/{app}/stripe_webhooks", post(webhook))
            .with_state(state)
            .nest("/api/v1", licenses)
    }
}

type Shared = State<Arc<Server>>;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>\
         body{{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#1c1c1e;background:#fff}}\
         @media (prefers-color-scheme:dark){{body{{color:#f2f2f7;background:#1c1c1e}}code{{background:#2c2c2e}}}}\
         code{{display:block;font-size:1.25rem;padding:.75rem 1rem;border-radius:.5rem;background:#f2f2f7;user-select:all;word-break:break-all}}\
         </style></head><body>{body}</body></html>",
        title = escape(title),
    ))
}

async fn home(State(server): Shared) -> Html<String> {
    let names: Vec<String> = server
        .apps
        .values()
        .map(|app| format!("<li>{}</li>", escape(&app.name)))
        .collect();
    page(
        "g3tech payments",
        &format!(
            "<h1>g3tech payments</h1><p>Licenses for:</p><ul>{}</ul>",
            names.join("")
        ),
    )
}

async fn buy(State(server): Shared, Path(app_id): Path<String>) -> Response {
    let Some(app) = server.apps.get(&app_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let key = generate_key(&app.id);
    let base = format!("{}/apps/{}", server.public_url, app.id);
    let request = CheckoutRequest {
        product: app.product.clone(),
        user: key.clone(),
        customer: None,
        success_url: format!("{base}/thanks?session_id={{CHECKOUT_SESSION_ID}}"),
        cancel_url: format!("{base}/cancelled"),
        automatic_tax: false,
        metadata: BTreeMap::new(),
        params: BTreeMap::new(),
        idempotency_key: format!("license-{key}"),
    };
    match app.service.checkout(request).await {
        Ok(session) => Redirect::to(&session.url).into_response(),
        Err(error) => {
            tracing::error!(app = %app.id, %error, "checkout_failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                page(
                    "Try again",
                    "<h1>Checkout is unavailable</h1><p>Please try again in a few minutes.</p>",
                ),
            )
                .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct ThanksQuery {
    session_id: String,
}

async fn thanks(
    State(server): Shared,
    Path(app_id): Path<String>,
    Query(query): Query<ThanksQuery>,
) -> Response {
    let Some(app) = server.apps.get(&app_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(stripe) = server.stripe.get(&app.id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let name = escape(&app.name);
    let status = match stripe.checkout_status(&query.session_id).await {
        Ok(status) if status.app.as_deref() == Some(app.id.as_str()) => status,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!(app = %app.id, %error, "checkout_lookup_failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                page("Try again", "<h1>One moment</h1><p>We couldn't look up your purchase. Reload this page in a minute.</p>"),
            )
                .into_response();
        }
    };
    let (Some(key), true) = (status.user, status.paid) else {
        return page(
            "Payment processing",
            &format!("<h1>Thanks!</h1><p>Your payment for {name} is still processing. Reload this page in a few minutes to get your license key.</p>"),
        )
        .into_response();
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        page(
            &format!("Your {name} license"),
            &format!(
                "<h1>Thanks for buying {name}!</h1><p>Your license key:</p><code>{}</code>\
                 <p>In {name}, open <b>About</b>, choose <b>Enter license key</b>, and paste it. \
                 It works on up to {} computers. Keep this key: bookmark this page or save the key somewhere safe.</p>",
                escape(&key),
                app.machine_limit,
            ),
        ),
    )
        .into_response()
}

async fn cancelled(State(server): Shared, Path(app_id): Path<String>) -> Response {
    let Some(app) = server.apps.get(&app_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    page(
        "Checkout cancelled",
        &format!(
            "<h1>No charge made</h1><p>You can keep using {} and buy whenever you're ready.</p>",
            escape(&app.name)
        ),
    )
    .into_response()
}

async fn webhook(
    State(server): Shared,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(app) = server.apps.get(&app_id) else {
        return StatusCode::NOT_FOUND;
    };
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::BAD_REQUEST;
    };
    match app.service.handle_stripe_webhook(&body, signature).await {
        Ok(outcome) => {
            tracing::info!(app = %app.id, ?outcome, "stripe_webhook");
            StatusCode::OK
        }
        Err(WebhookFailure::Rejected) => StatusCode::BAD_REQUEST,
        Err(WebhookFailure::Retry(error)) => {
            tracing::error!(app = %app.id, %error, "stripe_webhook_failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use base64::Engine;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{
        entitlements::{EntitlementStatus, Provider},
        license::file::LicenseClaims,
        server::store::{PurchaseRecord, Store},
    };

    async fn server() -> (Router, Arc<BTreeMap<String, App>>) {
        let db = surrealdb::engine::any::connect("mem://").await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        SurrealStore::apply_schema(&db).await.unwrap();
        let config = Config {
            public_url: "https://pay.example.com".into(),
            port: 0,
            stripe_secret: "sk_test_x".into(),
            apps: vec![AppConfig {
                id: "tally".into(),
                name: "Tally".into(),
                product: "tally_full".into(),
                stripe_price: "price_tally".into(),
                webhook_secret: "whsec_x".into(),
                signing_key: base64::engine::general_purpose::STANDARD.encode([5u8; 32]),
                machine_limit: 2,
            }],
        };
        let server = Server::new(&config, db).unwrap();
        let apps = server.apps.clone();
        (server.router(), apps)
    }

    async fn post(
        router: &Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn a_paid_key_activates_over_http_and_a_stranger_is_refused() {
        let (router, apps) = server().await;
        let health = router
            .clone()
            .oneshot(
                axum::http::Request::get("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let request =
            serde_json::json!({"key": "TALLY-AAAAA", "machine": "m1", "machine_name": "PC"});
        let (status, body) = post(
            &router,
            "/api/v1/apps/tally/licenses/activate",
            request.clone(),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("unknown_key"))
        );

        let tally = &apps["tally"];
        tally
            .service
            .store()
            .record(
                "TALLY-AAAAA",
                PurchaseRecord {
                    provider: Provider::Stripe,
                    product: ProductKey::new("tally_full"),
                    id: "pi_1".into(),
                    aliases: Vec::new(),
                    status: EntitlementStatus::Active,
                    expires_at_unix: None,
                    event_created: 1,
                },
            )
            .await
            .unwrap();
        let (status, body) = post(&router, "/api/v1/apps/tally/licenses/activate", request).await;
        assert_eq!(status, StatusCode::OK);
        let license = body["license"].as_str().unwrap();
        LicenseClaims::verify(license, tally.signer.public_key(), "tally", "m1").unwrap();

        let (_, body) = post(
            &router,
            "/api/v1/apps/tally/licenses/check",
            serde_json::json!({"key": "tally-aaaaa", "machine": "m1"}),
        )
        .await;
        assert_eq!(body["status"], "active");
        let (status, _) = post(
            &router,
            "/api/v1/apps/nope/licenses/check",
            serde_json::json!({"key": "x", "machine": "m1"}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unsigned_webhook_is_refused() {
        let (router, _) = server().await;
        let response = router
            .oneshot(
                axum::http::Request::post("/api/v1/apps/tally/stripe_webhooks")
                    .header("stripe-signature", "t=1,v1=00")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
