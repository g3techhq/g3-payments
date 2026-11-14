//! Stripe: Checkout for one-time purchases and subscriptions, the billing
//! portal, and verified webhooks.
//!
//! One Stripe account serves every app. Each checkout this crate creates
//! carries `g3_app` in its metadata (on the session, and on the payment or
//! subscription it makes), and [`route_event`] ignores events tagged for
//! another app. Events without the tag predate it and are taken as this
//! app's; they still have to name a product in this app's catalog.
//!
//! A webhook is a trigger, never the state: a one-time payment is granted
//! once Stripe says the checkout is paid, a full refund revokes it, and a
//! subscription event only says which subscription to read again from
//! Stripe ([`StripeClient::subscription`]). That way an event that arrives
//! late, twice or out of order cannot roll a renewal back.
//!
//! Merged from Swift Circuits (one-time Checkout, refunds, the signature
//! check) and Greenside Partee (subscriptions, customers, the billing portal,
//! re-reading state on every event). Both called Stripe their own way; this
//! module speaks to its REST API directly, over the same reqwest and ring as
//! the other providers.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{VerifyError, env_value, http_client};
use crate::{
    catalog::{Catalog, PurchaseKind},
    entitlements::ProductKey,
};

const API: &str = "https://api.stripe.com/v1";

/// The API version every request pins, so a dashboard upgrade cannot change
/// the shapes this module reads.
pub const API_VERSION: &str = "2026-08-26.dahlia";

/// How far a webhook's signed timestamp may be from now, as Stripe's own
/// libraries allow.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// Metadata keys this crate writes and reads.
pub const META_APP: &str = "g3_app";
pub const META_USER: &str = "user_id";
pub const META_PRODUCT: &str = "product_key";

/// The Stripe account and this app's name in it.
#[derive(Clone)]
pub struct StripeConfig {
    /// A secret or restricted key. Restricted keys need Checkout Sessions,
    /// Customers, Subscriptions and the Billing Portal for what an app uses.
    pub secret_key: String,
    /// The webhook endpoint's signing secret (`whsec_...`).
    pub webhook_secret: String,
    /// This app's `g3_app` tag, such as `swift-circuits`.
    pub app: String,
}

impl std::fmt::Debug for StripeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeConfig")
            .field("secret_key", &"[redacted]")
            .field("webhook_secret", &"[redacted]")
            .field("app", &self.app)
            .finish()
    }
}

impl StripeConfig {
    /// The key from `STRIPE_SECRET_KEY` (Greenside) or `STRIPE_RESTRICTED_KEY`
    /// (Swift Circuits), and the signing secret from `STRIPE_WEBHOOK_SECRET`
    /// (Swift Circuits) or `STRIPE_SIGNING_SECRET` (Greenside), so neither
    /// app's deployment has to change.
    pub fn from_env(app: impl Into<String>) -> Result<Self, VerifyError> {
        let either = |first: &str, second: &str| {
            env_value(first).or_else(|_| {
                env_value(second).map_err(|_| {
                    VerifyError::Configuration(format!("{first} or {second} is not set"))
                })
            })
        };
        Ok(Self {
            secret_key: either("STRIPE_SECRET_KEY", "STRIPE_RESTRICTED_KEY")?,
            webhook_secret: either("STRIPE_WEBHOOK_SECRET", "STRIPE_SIGNING_SECRET")?,
            app: app.into(),
        })
    }
}

/// Why a webhook was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// The signature is missing, wrong or too old: answer 400.
    BadSignature,
    /// Signed, but not an event this module can read: answer 400.
    Malformed,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadSignature => "stripe_signature_invalid",
            Self::Malformed => "stripe_event_malformed",
        })
    }
}

impl std::error::Error for WebhookError {}

/// Checks a `Stripe-Signature` header over the exact request body: an
/// HMAC-SHA256 of `"{t}.{body}"` under the signing secret, with `t` within
/// five minutes of `now_unix`. Any one matching `v1` signature passes, as
/// Stripe sends several while a secret is being rolled.
pub fn verify_signature(
    payload: &[u8],
    header: &str,
    secret: &str,
    now_unix: i64,
) -> Result<(), WebhookError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        if let Some(value) = part.trim().strip_prefix("t=") {
            timestamp = value.parse::<i64>().ok();
        } else if let Some(value) = part.trim().strip_prefix("v1=") {
            signatures.push(value);
        }
    }
    let timestamp = timestamp.ok_or(WebhookError::BadSignature)?;
    if (now_unix - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
        return Err(WebhookError::BadSignature);
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut signed = timestamp.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(payload);
    // ring compares in constant time.
    signatures
        .into_iter()
        .filter_map(decode_hex)
        .any(|signature| ring::hmac::verify(&key, &signed, &signature).is_ok())
        .then_some(())
        .ok_or(WebhookError::BadSignature)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(value.get(index..index + 2)?, 16).ok())
        .collect()
}

/// A verified Stripe event: the envelope, and its object as JSON.
#[derive(Clone, Debug, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Seconds since the Unix epoch. Orders grants and revocations of the
    /// same payment.
    pub created: i64,
    pub data: EventData,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventData {
    pub object: serde_json::Value,
}

impl Event {
    /// The event in `payload`, once its signature checks out.
    pub fn verified(
        payload: &[u8],
        signature_header: &str,
        config: &StripeConfig,
    ) -> Result<Self, WebhookError> {
        verify_signature(
            payload,
            signature_header,
            &config.webhook_secret,
            super::now_unix(),
        )?;
        serde_json::from_slice(payload).map_err(|_| WebhookError::Malformed)
    }
}

/// What an event asks of the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StripeAction {
    /// A one-time checkout is paid: grant `product` to `user`. Order it
    /// against other events for `purchase_id` by `created`.
    Grant {
        user: String,
        product: ProductKey,
        /// The PaymentIntent, which a later refund names.
        purchase_id: String,
        customer: Option<String>,
        created: i64,
    },
    /// A one-time payment was fully refunded: revoke what it granted, unless
    /// a later event already changed it.
    Revoke { purchase_id: String, created: i64 },
    /// A subscription changed: read it again with
    /// [`StripeClient::subscription`] and store it. A deleted one cannot be
    /// read again, so its final state comes with the event.
    RefreshSubscription {
        subscription_id: String,
        /// Who the checkout or subscription was made for, if it says.
        user: Option<String>,
        deleted: Option<Subscription>,
        created: i64,
    },
    /// Nothing to do, and why.
    Ignore(&'static str),
}

/// What `event` asks of this app.
pub fn route_event(catalog: &Catalog, app: &str, event: &Event) -> StripeAction {
    let object = &event.data.object;
    let metadata = |object: &serde_json::Value, key: &str| {
        object
            .pointer(&format!("/metadata/{key}"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    if metadata(object, META_APP).is_some_and(|tag| tag != app) {
        return StripeAction::Ignore("other_app");
    }
    let user = metadata(object, META_USER).or_else(|| text(object, "client_reference_id"));

    match event.kind.as_str() {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            match text(object, "mode").as_deref() {
                Some("payment") => one_time_grant(catalog, event, user),
                Some("subscription") => match id_of(object.get("subscription")) {
                    Some(subscription_id) => StripeAction::RefreshSubscription {
                        subscription_id,
                        user,
                        deleted: None,
                        created: event.created,
                    },
                    None => StripeAction::Ignore("no_subscription"),
                },
                _ => StripeAction::Ignore("other_mode"),
            }
        }
        // A refund of part of a payment leaves the purchase standing.
        "charge.refunded" => match (
            object.get("refunded").and_then(serde_json::Value::as_bool),
            id_of(object.get("payment_intent")),
        ) {
            (Some(true), Some(purchase_id)) => StripeAction::Revoke {
                purchase_id,
                created: event.created,
            },
            (Some(true), None) => StripeAction::Ignore("no_payment_intent"),
            _ => StripeAction::Ignore("partial_refund"),
        },
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.paused"
        | "customer.subscription.resumed" => match text(object, "id") {
            Some(subscription_id) => StripeAction::RefreshSubscription {
                subscription_id,
                user,
                deleted: None,
                created: event.created,
            },
            None => StripeAction::Ignore("no_subscription"),
        },
        "customer.subscription.deleted" => match Subscription::from_object(object) {
            Some(mut subscription) => {
                subscription.status = SubscriptionStatus::Canceled;
                StripeAction::RefreshSubscription {
                    subscription_id: subscription.id.clone(),
                    user,
                    deleted: Some(subscription),
                    created: event.created,
                }
            }
            None => StripeAction::Ignore("no_subscription"),
        },
        // Since API version 2025-03-31 an invoice names its subscription
        // under `parent`; older versions put it at the top level.
        "invoice.paid" | "invoice.payment_failed" => match id_of(
            object
                .pointer("/parent/subscription_details/subscription")
                .or_else(|| object.get("subscription")),
        ) {
            Some(subscription_id) => StripeAction::RefreshSubscription {
                subscription_id,
                user: None,
                deleted: None,
                created: event.created,
            },
            None => StripeAction::Ignore("no_subscription"),
        },
        _ => StripeAction::Ignore("unhandled_type"),
    }
}

fn one_time_grant(catalog: &Catalog, event: &Event, user: Option<String>) -> StripeAction {
    let object = &event.data.object;
    // `no_payment_required` (a 100% coupon) is as good as paid; `unpaid`
    // waits for `async_payment_succeeded`.
    if text(object, "payment_status").is_none_or(|status| status == "unpaid") {
        return StripeAction::Ignore("unpaid");
    }
    let Some(user) = user else {
        return StripeAction::Ignore("no_user");
    };
    let Some(product) = object
        .pointer(&format!("/metadata/{META_PRODUCT}"))
        .and_then(serde_json::Value::as_str)
        .map(ProductKey::from)
        .filter(|product| {
            catalog
                .get(product)
                .is_some_and(|product| product.kind == PurchaseKind::OneTime)
        })
    else {
        return StripeAction::Ignore("other_product");
    };
    StripeAction::Grant {
        user,
        product,
        // A free checkout has no PaymentIntent; its session id stands in.
        purchase_id: id_of(object.get("payment_intent"))
            .or_else(|| text(object, "id"))
            .unwrap_or_else(|| event.id.clone()),
        customer: id_of(object.get("customer")),
        created: event.created,
    }
}

fn text(object: &serde_json::Value, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// An id field, whether Stripe sent the id or the expanded object.
fn id_of(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(id) if !id.is_empty() => Some(id.clone()),
        object @ serde_json::Value::Object(_) => text(object, "id"),
        _ => None,
    }
}

/// A subscription's status, as Stripe names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Incomplete,
    IncompleteExpired,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
    /// A status added after this version.
    Unknown,
}

impl SubscriptionStatus {
    fn parse(value: &str) -> Self {
        match value {
            "incomplete" => Self::Incomplete,
            "incomplete_expired" => Self::IncompleteExpired,
            "trialing" => Self::Trialing,
            "active" => Self::Active,
            "past_due" => Self::PastDue,
            "canceled" => Self::Canceled,
            "unpaid" => Self::Unpaid,
            "paused" => Self::Paused,
            _ => Self::Unknown,
        }
    }

    /// Whether Stripe still counts it as paid for: active, trialing, or past
    /// due while Stripe retries the card.
    pub fn grants_access(self) -> bool {
        matches!(self, Self::Active | Self::Trialing | Self::PastDue)
    }
}

/// The fields of a Stripe subscription this crate reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub customer: String,
    pub status: SubscriptionStatus,
    /// The price of its one item.
    pub price: String,
    /// When the current paid period ends.
    pub current_period_end: i64,
    pub cancel_at_period_end: bool,
    pub metadata: BTreeMap<String, String>,
}

impl Subscription {
    /// From a subscription object. Since API version 2025-03-31 the period
    /// lives on the item; older versions put it at the top level. A
    /// subscription with other than one item is not one this crate made.
    pub(crate) fn from_object(object: &serde_json::Value) -> Option<Self> {
        let items = object.pointer("/items/data")?.as_array()?;
        let [item] = items.as_slice() else {
            return None;
        };
        if object
            .pointer("/items/has_more")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return None;
        }
        let current_period_end = item
            .get("current_period_end")
            .or_else(|| object.get("current_period_end"))
            .and_then(serde_json::Value::as_i64)?;
        Some(Self {
            id: text(object, "id")?,
            customer: id_of(object.get("customer"))?,
            status: SubscriptionStatus::parse(&text(object, "status")?),
            price: id_of(item.get("price"))?,
            current_period_end,
            cancel_at_period_end: object
                .get("cancel_at_period_end")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            metadata: object
                .get("metadata")
                .and_then(serde_json::Value::as_object)
                .map(|metadata| {
                    metadata
                        .iter()
                        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// The catalog product its price is, if this app sells it.
    pub fn product<'a>(&self, catalog: &'a Catalog) -> Option<&'a ProductKey> {
        catalog
            .by_stripe_price(&self.price)
            .filter(|product| product.kind == PurchaseKind::Subscription)
            .map(|product| &product.key)
    }

    /// When access ends: the period end while Stripe counts it as paid,
    /// otherwise already.
    pub fn access_until(&self) -> Option<i64> {
        self.status
            .grants_access()
            .then_some(self.current_period_end)
    }
}
/// A Checkout Session to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutRequest {
    pub product: ProductKey,
    /// The app's id for the buyer, written to `client_reference_id` and
    /// `metadata.user_id`.
    pub user: String,
    /// An existing Stripe customer. Subscriptions should always have one, so
    /// the billing portal can find them.
    pub customer: Option<String>,
    pub success_url: String,
    pub cancel_url: String,
    /// Stripe Tax on the session. Swift Circuits turns it on.
    pub automatic_tax: bool,
    /// Extra metadata, written beside the crate's own keys.
    pub metadata: BTreeMap<String, String>,
    /// Extra top-level Checkout Session parameters this crate does not model
    /// (Swift Circuits sends `integration_identifier`). Never `mode`,
    /// `line_items`, `metadata` or the other fields set from this request.
    pub params: BTreeMap<String, String>,
    /// Makes a retried request return the same session. Stripe allows 255
    /// characters.
    pub idempotency_key: String,
}

/// An open Checkout Session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutSession {
    pub id: String,
    /// The hosted page on `checkout.stripe.com`.
    pub url: String,
}

/// Talks to Stripe's API for one app.
#[derive(Clone, Debug)]
pub struct StripeClient {
    config: StripeConfig,
}

impl StripeClient {
    pub fn new(config: StripeConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &StripeConfig {
        &self.config
    }

    /// A Checkout Session for one product in `catalog`: payment mode for a
    /// one-time product, subscription mode for a subscription. The session
    /// and the payment or subscription it makes all carry `g3_app`,
    /// `user_id` and `product_key`.
    pub async fn create_checkout(
        &self,
        catalog: &Catalog,
        request: CheckoutRequest,
    ) -> Result<CheckoutSession, VerifyError> {
        let product = catalog
            .get(&request.product)
            .ok_or(VerifyError::UnknownProduct)?;
        let price = product
            .stripe_price
            .clone()
            .ok_or(VerifyError::UnknownProduct)?;
        let form = checkout_form(&self.config.app, product.kind, &price, &request);
        let session: SessionResponse = self
            .post("/checkout/sessions", &form, Some(&request.idempotency_key))
            .await?;
        if let Some(url) = session.url {
            return Ok(CheckoutSession {
                id: session.id,
                url,
            });
        }
        // The key replayed a session that is no longer open (completed or
        // expired), which has no URL. Start a fresh one so the buyer can.
        let session: SessionResponse = self.post("/checkout/sessions", &form, None).await?;
        Ok(CheckoutSession {
            id: session.id,
            url: session.url.ok_or_else(|| {
                VerifyError::Unavailable("Stripe returned a Checkout Session without a URL".into())
            })?,
        })
    }

    /// A customer for `user`, so subscriptions and the portal have one.
    pub async fn create_customer(
        &self,
        user: &str,
        email: &str,
        idempotency_key: &str,
    ) -> Result<String, VerifyError> {
        let form = vec![
            ("email".to_string(), email.to_string()),
            (format!("metadata[{META_USER}]"), user.to_string()),
            (format!("metadata[{META_APP}]"), self.config.app.clone()),
        ];
        let customer: IdResponse = self
            .post("/customers", &form, Some(idempotency_key))
            .await?;
        Ok(customer.id)
    }

    /// A billing portal link for `customer`.
    pub async fn create_portal(
        &self,
        customer: &str,
        return_url: &str,
    ) -> Result<String, VerifyError> {
        let form = vec![
            ("customer".to_string(), customer.to_string()),
            ("return_url".to_string(), return_url.to_string()),
        ];
        let portal: SessionResponse = self.post("/billing_portal/sessions", &form, None).await?;
        portal.url.ok_or_else(|| {
            VerifyError::Unavailable("Stripe returned a portal without a URL".into())
        })
    }

    /// A subscription as Stripe has it now.
    pub async fn subscription(&self, id: &str) -> Result<Subscription, VerifyError> {
        let object: serde_json::Value = self
            .get(&format!("/subscriptions/{}", path_id(id)?), &[])
            .await?;
        Subscription::from_object(&object).ok_or(VerifyError::Rejected)
    }

    /// The customer's newest subscription to `price`, in any status.
    pub async fn find_customer_subscription(
        &self,
        customer: &str,
        price: &str,
    ) -> Result<Option<Subscription>, VerifyError> {
        #[derive(Deserialize)]
        struct List {
            data: Vec<serde_json::Value>,
        }

        let list: List = self
            .get(
                "/subscriptions",
                &[
                    ("customer", customer),
                    ("price", price),
                    ("status", "all"),
                    ("limit", "1"),
                ],
            )
            .await?;
        Ok(list.data.first().and_then(Subscription::from_object))
    }

    /// Ends a subscription now, not at the period end, for account deletion.
    /// One Stripe no longer has counts as already cancelled, so deletion is
    /// never blocked by billing state that is already gone.
    pub async fn cancel_subscription(&self, id: &str) -> Result<(), VerifyError> {
        let path = format!("/subscriptions/{}", path_id(id)?);
        match self.send(reqwest::Method::DELETE, &path, &[], None).await {
            Ok(_) | Err(VerifyError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(String, String)],
        idempotency_key: Option<&str>,
    ) -> Result<T, VerifyError> {
        let body = self
            .send(reqwest::Method::POST, path, form, idempotency_key)
            .await?;
        serde_json::from_str(&body)
            .map_err(|_| VerifyError::Unavailable("unreadable Stripe response".into()))
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, VerifyError> {
        let query: Vec<(String, String)> = query
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        let body = self.send(reqwest::Method::GET, path, &query, None).await?;
        serde_json::from_str(&body)
            .map_err(|_| VerifyError::Unavailable("unreadable Stripe response".into()))
    }

    /// One request, retried twice on a network error, a 429 or a 5xx. A
    /// retried POST reuses its idempotency key, so Stripe applies it once;
    /// a POST without one is not retried.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        params: &[(String, String)],
        idempotency_key: Option<&str>,
    ) -> Result<String, VerifyError> {
        let client = http_client()?;
        let retries = if method == reqwest::Method::POST && idempotency_key.is_none() {
            0
        } else {
            2
        };
        let mut attempt = 0;
        loop {
            let mut request = client
                .request(method.clone(), format!("{API}{path}"))
                .bearer_auth(&self.config.secret_key)
                .header("Stripe-Version", API_VERSION);
            request = if method == reqwest::Method::POST {
                request.form(params)
            } else {
                request.query(params)
            };
            if let Some(key) = idempotency_key {
                request = request.header("Idempotency-Key", key);
            }
            let outcome = match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    classify(status, body)
                }
                Err(error) => Err(VerifyError::from(error)),
            };
            match outcome {
                Err(VerifyError::Unavailable(_)) if attempt < retries => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(500 << attempt)).await;
                }
                outcome => return outcome,
            }
        }
    }
}

/// A Stripe answer as a body or a [`VerifyError`]. Stripe's own message is
/// kept for the logs; it never quotes the key.
fn classify(status: reqwest::StatusCode, body: String) -> Result<String, VerifyError> {
    if status.is_success() {
        return Ok(body);
    }
    let message = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")?
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("Stripe answered {status}"));
    Err(match status.as_u16() {
        401 | 403 => VerifyError::Configuration(message),
        404 => VerifyError::NotFound,
        400 | 402 => VerifyError::Rejected,
        _ => VerifyError::Unavailable(message),
    })
}

/// Stripe ids are short ASCII words; anything else must not reach a path.
fn path_id(id: &str) -> Result<&str, VerifyError> {
    if id.is_empty()
        || id.len() > 255
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(VerifyError::InvalidProof);
    }
    Ok(id)
}

/// The form fields of a Checkout Session.
fn checkout_form(
    app: &str,
    kind: PurchaseKind,
    price: &str,
    request: &CheckoutRequest,
) -> Vec<(String, String)> {
    let mut metadata = request.metadata.clone();
    metadata.insert(META_APP.into(), app.into());
    metadata.insert(META_USER.into(), request.user.clone());
    metadata.insert(META_PRODUCT.into(), request.product.0.clone());

    let mode = match kind {
        PurchaseKind::OneTime => "payment",
        PurchaseKind::Subscription => "subscription",
    };
    // Refunds and subscription events name the payment or subscription, not
    // the session, so the tags go on those too.
    let carried = match kind {
        PurchaseKind::OneTime => "payment_intent_data",
        PurchaseKind::Subscription => "subscription_data",
    };
    let mut form = vec![
        ("mode".to_string(), mode.to_string()),
        ("line_items[0][price]".into(), price.into()),
        ("line_items[0][quantity]".into(), "1".into()),
        ("success_url".into(), request.success_url.clone()),
        ("cancel_url".into(), request.cancel_url.clone()),
        ("client_reference_id".into(), request.user.clone()),
    ];
    if let Some(customer) = &request.customer {
        form.push(("customer".into(), customer.clone()));
    }
    if request.automatic_tax {
        form.push(("automatic_tax[enabled]".into(), "true".into()));
    }
    for (key, value) in &request.params {
        if !form
            .iter()
            .any(|(name, _)| name == key || name.starts_with(&format!("{key}[")))
        {
            form.push((key.clone(), value.clone()));
        }
    }
    for (key, value) in &metadata {
        form.push((format!("metadata[{key}]"), value.clone()));
        form.push((format!("{carried}[metadata][{key}]"), value.clone()));
    }
    form
}

#[derive(Deserialize)]
struct SessionResponse {
    id: String,
    url: Option<String>,
}

#[derive(Deserialize)]
struct IdResponse {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogProduct;
    use serde_json::{Value, json};

    const SECRET: &str = "whsec_test";
    const NOW: i64 = 1_800_000_000;

    fn catalog() -> Catalog {
        Catalog::new(vec![
            CatalogProduct::new("full_game", PurchaseKind::OneTime).stripe_price("price_full"),
            CatalogProduct::new("membership", PurchaseKind::Subscription)
                .stripe_price("price_annual"),
        ])
        .unwrap()
    }

    fn sign(payload: &[u8], timestamp: i64) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET.as_bytes());
        let mut signed = format!("{timestamp}.").into_bytes();
        signed.extend_from_slice(payload);
        let tag = ring::hmac::sign(&key, &signed);
        let hex: String = tag
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("t={timestamp},v1={hex}")
    }

    fn event(kind: &str, object: Value) -> Event {
        serde_json::from_value(json!({
            "id": "evt_1", "type": kind, "created": NOW, "data": { "object": object },
        }))
        .unwrap()
    }

    fn route(kind: &str, object: Value) -> StripeAction {
        route_event(&catalog(), "swift-circuits", &event(kind, object))
    }

    fn paid_session() -> Value {
        json!({
            "id": "cs_1", "mode": "payment", "payment_status": "paid",
            "payment_intent": "pi_1", "customer": "cus_1",
            "metadata": { "user_id": "user:abc", "product_key": "full_game", "g3_app": "swift-circuits" },
        })
    }

    fn subscription_object() -> Value {
        json!({
            "id": "sub_1", "customer": "cus_1", "status": "active", "cancel_at_period_end": false,
            "items": { "has_more": false, "data": [
                { "price": { "id": "price_annual" }, "current_period_end": NOW + 86_400 },
            ] },
            "metadata": { "user_id": "user:abc" },
        })
    }

    #[test]
    fn stripe_signatures_cover_the_exact_body_and_expire() {
        let payload = br#"{"id":"evt_test"}"#;
        let header = sign(payload, NOW);
        assert_eq!(verify_signature(payload, &header, SECRET, NOW), Ok(()));
        assert_eq!(
            verify_signature(payload, &header, SECRET, NOW + 300),
            Ok(())
        );
        for (body, now) in [
            (&br#"{"id":"changed"}"#[..], NOW),
            (&payload[..], NOW + 301),
            (&payload[..], NOW - 301),
        ] {
            assert_eq!(
                verify_signature(body, &header, SECRET, now),
                Err(WebhookError::BadSignature)
            );
        }
        assert_eq!(
            verify_signature(payload, &header, "whsec_other", NOW),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn any_one_signature_of_several_passes_and_junk_does_not() {
        let payload = br#"{"id":"evt_test"}"#;
        let good = sign(payload, NOW);
        let rolled = format!("{good},v1=00ff,v1=zz,v0=abc");
        assert_eq!(verify_signature(payload, &rolled, SECRET, NOW), Ok(()));
        for header in [
            "",
            "v1=00",
            "t=abc,v1=00",
            &format!("t={NOW}"),
            &format!("t={NOW},v1=0"),
        ] {
            assert_eq!(
                verify_signature(payload, header, SECRET, NOW),
                Err(WebhookError::BadSignature),
                "{header}"
            );
        }
    }

    #[test]
    fn a_verified_event_reads_its_envelope() {
        let config = StripeConfig {
            secret_key: "sk_test".into(),
            webhook_secret: SECRET.into(),
            app: "swift-circuits".into(),
        };
        let payload = serde_json::to_vec(&json!({
            "id": "evt_9", "type": "charge.refunded", "created": 5, "data": { "object": {} },
        }))
        .unwrap();
        let header = sign(&payload, super::super::now_unix());
        let event = Event::verified(&payload, &header, &config).unwrap();
        assert_eq!(
            (event.id.as_str(), event.kind.as_str(), event.created),
            ("evt_9", "charge.refunded", 5)
        );
        let not_an_event = b"[]";
        let header = sign(not_an_event, super::super::now_unix());
        assert_eq!(
            Event::verified(not_an_event, &header, &config).unwrap_err(),
            WebhookError::Malformed
        );
    }

    #[test]
    fn a_paid_one_time_checkout_grants_its_product() {
        for kind in [
            "checkout.session.completed",
            "checkout.session.async_payment_succeeded",
        ] {
            assert_eq!(
                route(kind, paid_session()),
                StripeAction::Grant {
                    user: "user:abc".into(),
                    product: ProductKey::from("full_game"),
                    purchase_id: "pi_1".into(),
                    customer: Some("cus_1".into()),
                    created: NOW,
                },
                "{kind}"
            );
        }
    }

    #[test]
    fn an_unpaid_checkout_waits_and_a_free_one_grants_under_its_session() {
        let mut unpaid = paid_session();
        unpaid["payment_status"] = json!("unpaid");
        assert_eq!(
            route("checkout.session.completed", unpaid),
            StripeAction::Ignore("unpaid")
        );
        let mut free = paid_session();
        free["payment_status"] = json!("no_payment_required");
        free["payment_intent"] = Value::Null;
        let StripeAction::Grant { purchase_id, .. } = route("checkout.session.completed", free)
        else {
            panic!("a free checkout grants");
        };
        assert_eq!(purchase_id, "cs_1");
    }

    #[test]
    fn an_expanded_payment_intent_is_read_by_its_id() {
        let mut session = paid_session();
        session["payment_intent"] = json!({ "id": "pi_expanded", "object": "payment_intent" });
        let StripeAction::Grant { purchase_id, .. } = route("checkout.session.completed", session)
        else {
            panic!("grants");
        };
        assert_eq!(purchase_id, "pi_expanded");
    }

    #[test]
    fn another_apps_events_are_ignored_and_untagged_ones_are_this_apps() {
        let mut other = paid_session();
        other["metadata"]["g3_app"] = json!("tally");
        assert_eq!(
            route("checkout.session.completed", other),
            StripeAction::Ignore("other_app")
        );
        let mut legacy = paid_session();
        legacy["metadata"].as_object_mut().unwrap().remove("g3_app");
        assert!(matches!(
            route("checkout.session.completed", legacy),
            StripeAction::Grant { .. }
        ));
    }

    #[test]
    fn a_checkout_must_name_a_one_time_product_of_this_app_and_a_buyer() {
        for (product, reason) in [
            ("theme.space", "other_product"),
            ("membership", "other_product"),
        ] {
            let mut session = paid_session();
            session["metadata"]["product_key"] = json!(product);
            assert_eq!(
                route("checkout.session.completed", session),
                StripeAction::Ignore(reason)
            );
        }
        let mut anonymous = paid_session();
        anonymous["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("user_id");
        assert_eq!(
            route("checkout.session.completed", anonymous),
            StripeAction::Ignore("no_user")
        );
        // Greenside's checkouts name the buyer in client_reference_id.
        let mut referenced = paid_session();
        referenced["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("user_id");
        referenced["client_reference_id"] = json!("user:ref");
        let StripeAction::Grant { user, .. } = route("checkout.session.completed", referenced)
        else {
            panic!("grants");
        };
        assert_eq!(user, "user:ref");
    }

    #[test]
    fn only_a_full_refund_revokes() {
        assert_eq!(
            route(
                "charge.refunded",
                json!({ "refunded": true, "payment_intent": "pi_1" })
            ),
            StripeAction::Revoke {
                purchase_id: "pi_1".into(),
                created: NOW
            }
        );
        assert_eq!(
            route(
                "charge.refunded",
                json!({ "refunded": false, "payment_intent": "pi_1" })
            ),
            StripeAction::Ignore("partial_refund")
        );
        assert_eq!(
            route("charge.refunded", json!({ "refunded": true })),
            StripeAction::Ignore("no_payment_intent")
        );
    }

    #[test]
    fn subscription_events_ask_for_the_subscription_to_be_read_again() {
        let checkout = json!({
            "mode": "subscription", "subscription": "sub_1", "client_reference_id": "user:abc",
        });
        assert_eq!(
            route("checkout.session.completed", checkout),
            StripeAction::RefreshSubscription {
                subscription_id: "sub_1".into(),
                user: Some("user:abc".into()),
                deleted: None,
                created: NOW,
            }
        );
        for kind in [
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.paused",
            "customer.subscription.resumed",
        ] {
            let StripeAction::RefreshSubscription {
                subscription_id,
                user,
                deleted,
                ..
            } = route(kind, subscription_object())
            else {
                panic!("{kind} refreshes");
            };
            assert_eq!(subscription_id, "sub_1");
            assert_eq!(user.as_deref(), Some("user:abc"));
            assert!(deleted.is_none());
        }
    }

    #[test]
    fn a_deleted_subscription_brings_its_final_state() {
        let StripeAction::RefreshSubscription {
            deleted: Some(deleted),
            ..
        } = route("customer.subscription.deleted", subscription_object())
        else {
            panic!("a deletion refreshes with its state");
        };
        assert_eq!(deleted.status, SubscriptionStatus::Canceled);
        assert_eq!(deleted.access_until(), None);
    }

    #[test]
    fn invoices_name_their_subscription_in_either_api_shape() {
        let current =
            json!({ "parent": { "subscription_details": { "subscription": "sub_new" } } });
        let legacy = json!({ "subscription": "sub_old" });
        for (object, id) in [(current, "sub_new"), (legacy, "sub_old")] {
            let StripeAction::RefreshSubscription {
                subscription_id, ..
            } = route("invoice.paid", object)
            else {
                panic!("an invoice refreshes");
            };
            assert_eq!(subscription_id, id);
        }
        assert_eq!(
            route("invoice.payment_failed", json!({})),
            StripeAction::Ignore("no_subscription")
        );
        assert_eq!(
            route("customer.created", json!({})),
            StripeAction::Ignore("unhandled_type")
        );
    }

    #[test]
    fn a_subscription_reads_its_period_from_the_item_or_the_top_level() {
        let current = Subscription::from_object(&subscription_object()).unwrap();
        assert_eq!(current.current_period_end, NOW + 86_400);
        assert_eq!(
            current.product(&catalog()),
            Some(&ProductKey::from("membership"))
        );
        assert_eq!(current.access_until(), Some(NOW + 86_400));
        assert_eq!(
            current.metadata.get("user_id").map(String::as_str),
            Some("user:abc")
        );

        let mut legacy = subscription_object();
        legacy["current_period_end"] = json!(NOW + 7);
        legacy["items"]["data"][0]
            .as_object_mut()
            .unwrap()
            .remove("current_period_end");
        legacy["items"]["data"][0]["price"] = json!("price_full");
        let legacy = Subscription::from_object(&legacy).unwrap();
        assert_eq!(legacy.current_period_end, NOW + 7);
        // A one-time price is not a subscription product.
        assert_eq!(legacy.product(&catalog()), None);

        let mut two_items = subscription_object();
        let item = two_items["items"]["data"][0].clone();
        two_items["items"]["data"]
            .as_array_mut()
            .unwrap()
            .push(item);
        assert!(Subscription::from_object(&two_items).is_none());
    }

    #[test]
    fn only_paid_statuses_grant_access() {
        for (status, grants) in [
            ("active", true),
            ("trialing", true),
            ("past_due", true),
            ("incomplete", false),
            ("incomplete_expired", false),
            ("canceled", false),
            ("unpaid", false),
            ("paused", false),
            ("something_new", false),
        ] {
            assert_eq!(
                SubscriptionStatus::parse(status).grants_access(),
                grants,
                "{status}"
            );
        }
    }

    fn request() -> CheckoutRequest {
        CheckoutRequest {
            product: ProductKey::from("full_game"),
            user: "user:abc".into(),
            customer: None,
            success_url: "https://example.com/ok".into(),
            cancel_url: "https://example.com/no".into(),
            automatic_tax: true,
            metadata: BTreeMap::from([
                ("purchase_origin".to_string(), "web".to_string()),
                ("g3_app".to_string(), "forged".to_string()),
            ]),
            params: BTreeMap::from([
                (
                    "integration_identifier".to_string(),
                    "swift-circuits-test".to_string(),
                ),
                ("mode".to_string(), "setup".to_string()),
                ("line_items".to_string(), "forged".to_string()),
            ]),
            idempotency_key: "key".into(),
        }
    }

    fn field<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
        form.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn a_one_time_checkout_tags_the_session_and_its_payment() {
        let form = checkout_form(
            "swift-circuits",
            PurchaseKind::OneTime,
            "price_full",
            &request(),
        );
        assert_eq!(field(&form, "mode"), Some("payment"));
        assert_eq!(field(&form, "line_items[0][price]"), Some("price_full"));
        assert_eq!(field(&form, "automatic_tax[enabled]"), Some("true"));
        assert_eq!(field(&form, "client_reference_id"), Some("user:abc"));
        assert_eq!(field(&form, "customer"), None);
        for prefix in ["metadata", "payment_intent_data[metadata]"] {
            assert_eq!(
                field(&form, &format!("{prefix}[g3_app]")),
                Some("swift-circuits"),
                "{prefix}"
            );
            assert_eq!(
                field(&form, &format!("{prefix}[user_id]")),
                Some("user:abc")
            );
            assert_eq!(
                field(&form, &format!("{prefix}[product_key]")),
                Some("full_game")
            );
            assert_eq!(
                field(&form, &format!("{prefix}[purchase_origin]")),
                Some("web")
            );
        }
        assert!(field(&form, "subscription_data[metadata][g3_app]").is_none());
        assert_eq!(
            field(&form, "integration_identifier"),
            Some("swift-circuits-test")
        );
        // A parameter the request sets itself cannot be replaced.
        assert_eq!(field(&form, "mode"), Some("payment"));
        assert_eq!(form.iter().filter(|(name, _)| name == "mode").count(), 1);
        assert!(field(&form, "line_items").is_none());
    }

    #[test]
    fn a_subscription_checkout_tags_its_subscription() {
        let mut request = request();
        request.product = ProductKey::from("membership");
        request.customer = Some("cus_1".into());
        request.automatic_tax = false;
        let form = checkout_form(
            "greenside-partee",
            PurchaseKind::Subscription,
            "price_annual",
            &request,
        );
        assert_eq!(field(&form, "mode"), Some("subscription"));
        assert_eq!(field(&form, "customer"), Some("cus_1"));
        assert_eq!(field(&form, "automatic_tax[enabled]"), None);
        assert_eq!(
            field(&form, "subscription_data[metadata][g3_app]"),
            Some("greenside-partee")
        );
        assert!(field(&form, "payment_intent_data[metadata][g3_app]").is_none());
    }

    #[tokio::test]
    async fn a_product_without_a_web_price_cannot_be_checked_out() {
        let catalog = Catalog::new(vec![
            CatalogProduct::new("theme.space", PurchaseKind::OneTime).store_id("com.example.space"),
        ])
        .unwrap();
        let client = StripeClient::new(StripeConfig {
            secret_key: "sk_test".into(),
            webhook_secret: SECRET.into(),
            app: "swift-circuits".into(),
        });
        let mut request = request();
        request.product = ProductKey::from("theme.space");
        assert_eq!(
            client.create_checkout(&catalog, request.clone()).await,
            Err(VerifyError::UnknownProduct)
        );
        request.product = ProductKey::from("unknown");
        assert_eq!(
            client.create_checkout(&catalog, request).await,
            Err(VerifyError::UnknownProduct)
        );
    }

    #[test]
    fn stripe_answers_map_to_errors() {
        let body = r#"{"error":{"message":"No such subscription"}}"#.to_string();
        assert_eq!(
            classify(reqwest::StatusCode::OK, "{}".into()),
            Ok("{}".into())
        );
        assert_eq!(
            classify(reqwest::StatusCode::NOT_FOUND, body.clone()),
            Err(VerifyError::NotFound)
        );
        assert_eq!(
            classify(reqwest::StatusCode::BAD_REQUEST, body.clone()),
            Err(VerifyError::Rejected)
        );
        assert_eq!(
            classify(reqwest::StatusCode::UNAUTHORIZED, body.clone()),
            Err(VerifyError::Configuration("No such subscription".into()))
        );
        assert!(
            classify(reqwest::StatusCode::TOO_MANY_REQUESTS, body.clone())
                .unwrap_err()
                .is_retryable()
        );
        assert!(
            classify(reqwest::StatusCode::BAD_GATEWAY, String::new())
                .unwrap_err()
                .is_retryable()
        );
    }

    #[test]
    fn ids_reach_a_url_path_only_when_they_are_plain_words() {
        assert!(path_id("sub_1MowQVLkdIwHu7ixeRlqHVzs").is_ok());
        for bad in ["", "sub/1", "../x", "sub 1", "sub?x"] {
            assert_eq!(path_id(bad), Err(VerifyError::InvalidProof), "{bad}");
        }
    }

    #[test]
    fn keys_never_reach_debug_output() {
        let config = StripeConfig {
            secret_key: "sk_test_redaction_canary".into(),
            webhook_secret: "whsec_secret".into(),
            app: "swift-circuits".into(),
        };
        let debug = format!("{:?}", StripeClient::new(config));
        assert!(!debug.contains("sk_test_redaction_canary") && !debug.contains("whsec_secret"));
    }
}
