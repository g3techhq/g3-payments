//! The App Store: verifying a StoreKit purchase through the App Store Server
//! API, keeping subscriptions current, and App Store Server Notifications V2.
//!
//! Apple's word is taken only from JWS that [`SignedDataVerifier`] has
//! verified to Apple Root CA - G3, whether it came from the device, from a
//! notification or from Apple's own API. A purchase's state always comes from
//! the API, so a notification that arrives late or twice cannot roll a
//! renewal or a refund back.
//!
//! Merged from Swift Circuits (one-time purchases, through Get Transaction
//! Info) and Greenside Partee (subscriptions, through Get All Subscription
//! Statuses, and notifications).

use rustls_pki_types::UnixTime;
use serde::{Deserialize, Serialize};

use super::{VerifiedPurchase, VerifyError, env_value, http_client, jwt, now_unix};
use crate::{
    apple_jws::SignedDataVerifier,
    catalog::{Catalog, CatalogProduct, PurchaseKind},
    entitlements::{ProductKey, Provider, PurchaseProof},
};

const PRODUCTION_API: &str = "https://api.storekit.itunes.apple.com";
const SANDBOX_API: &str = "https://api.storekit-sandbox.itunes.apple.com";

/// Longest signed transaction a device may submit.
const MAX_PROOF_LEN: usize = 256 * 1024;

/// Where a transaction was made. App Review buys in the sandbox against the
/// production server, so both are honoured; anything else (Xcode's local
/// StoreKit testing) is signed by a local certificate and never verifies.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Environment {
    Production,
    Sandbox,
    #[serde(other)]
    Other,
}

impl Environment {
    fn api_origins(environment: Option<Self>) -> [&'static str; 2] {
        match environment {
            Some(Self::Sandbox) => [SANDBOX_API, PRODUCTION_API],
            _ => [PRODUCTION_API, SANDBOX_API],
        }
    }
}

/// `JWSTransactionDecodedPayload`, the fields this module reads.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionInfo {
    transaction_id: String,
    original_transaction_id: String,
    bundle_id: String,
    product_id: String,
    app_account_token: Option<String>,
    expires_date: Option<i64>,
    revocation_date: Option<i64>,
    environment: Option<Environment>,
}

/// `JWSRenewalInfoDecodedPayload`, the fields this module reads.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewalInfo {
    original_transaction_id: Option<String>,
    /// 1 renews at the end of the period, 0 the user turned it off.
    auto_renew_status: Option<i32>,
    /// Set while a failed renewal is in its billing grace period, during
    /// which Apple says to keep access.
    grace_period_expires_date: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationPayload {
    notification_type: String,
    data: Option<NotificationData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationData {
    bundle_id: Option<String>,
    app_apple_id: Option<i64>,
    environment: Option<Environment>,
    signed_transaction_info: Option<String>,
}

/// Get Transaction Info's response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionInfoResponse {
    signed_transaction_info: String,
}

/// Get All Subscription Statuses' response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    #[serde(default)]
    data: Vec<SubscriptionGroupStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionGroupStatus {
    #[serde(default)]
    last_transactions: Vec<LastTransaction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LastTransaction {
    original_transaction_id: String,
    signed_transaction_info: String,
    signed_renewal_info: Option<String>,
}

/// The app on the App Store, and the API key to ask about it.
#[derive(Clone)]
pub struct AppStoreConfig {
    pub issuer_id: String,
    pub key_id: String,
    /// The API key's PKCS#8 PEM (`AuthKey_<key id>.p8`).
    pub private_key_pem: String,
    pub bundle_id: String,
    /// The app's Apple ID in App Store Connect. Optional, but when set a
    /// production notification must name it, as Apple's libraries require.
    pub app_apple_id: Option<i64>,
}

impl std::fmt::Debug for AppStoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStoreConfig")
            .field("issuer_id", &self.issuer_id)
            .field("key_id", &self.key_id)
            .field("private_key_pem", &"[redacted]")
            .field("bundle_id", &self.bundle_id)
            .field("app_apple_id", &self.app_apple_id)
            .finish()
    }
}

impl AppStoreConfig {
    /// From `APP_STORE_ISSUER_ID`, `APP_STORE_KEY_ID`, `APP_STORE_PRIVATE_KEY`,
    /// `APP_STORE_BUNDLE_ID` and the optional `APP_STORE_APP_APPLE_ID`, the
    /// names both apps already deploy with.
    pub fn from_env() -> Result<Self, VerifyError> {
        let app_apple_id = match std::env::var("APP_STORE_APP_APPLE_ID") {
            Ok(id) if !id.trim().is_empty() => Some(id.trim().parse().map_err(|_| {
                VerifyError::Configuration("APP_STORE_APP_APPLE_ID is not a number".into())
            })?),
            _ => None,
        };
        Ok(Self {
            issuer_id: env_value("APP_STORE_ISSUER_ID")?,
            key_id: env_value("APP_STORE_KEY_ID")?,
            private_key_pem: env_value("APP_STORE_PRIVATE_KEY")?,
            bundle_id: env_value("APP_STORE_BUNDLE_ID")?,
            app_apple_id,
        })
    }

    fn authorization(&self) -> Result<String, VerifyError> {
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            iat: i64,
            exp: i64,
            aud: &'static str,
            bid: &'a str,
        }

        let now = now_unix();
        jwt::es256(
            &Claims {
                iss: &self.issuer_id,
                iat: now,
                exp: now + 10 * 60,
                aud: "appstoreconnect-v1",
                bid: &self.bundle_id,
            },
            &self.private_key_pem,
            Some(&self.key_id),
        )
    }
}

/// A purchase's state according to Apple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppStorePurchase {
    pub product: ProductKey,
    pub kind: PurchaseKind,
    pub original_transaction_id: String,
    pub transaction_id: String,
    pub account_token: Option<String>,
    /// When a subscription's access ends, its billing grace period included.
    /// `None` for a one-time purchase.
    pub expires_at_unix: Option<i64>,
    /// Set while Apple has refunded or revoked it; cleared when Apple reverses
    /// a refund.
    pub revoked_at_unix: Option<i64>,
    /// A subscription renews at the end of its period. A refunded one never
    /// does, whatever its renewal info says.
    pub will_auto_renew: bool,
}

impl AppStorePurchase {
    /// Whether it grants its product at `now_unix`.
    pub fn is_active_at(&self, now_unix: i64) -> bool {
        self.revoked_at_unix.is_none()
            && match self.kind {
                PurchaseKind::OneTime => true,
                PurchaseKind::Subscription => self
                    .expires_at_unix
                    .is_some_and(|expires| now_unix < expires),
            }
    }

    /// As a purchase to grant, or [`VerifyError::Rejected`] while revoked.
    /// An expired subscription still converts: its expiry says it is not
    /// owned, and linking it lets a later renewal reach the same account.
    pub fn into_verified(self) -> Result<VerifiedPurchase, VerifyError> {
        if self.revoked_at_unix.is_some() {
            return Err(VerifyError::Rejected);
        }
        let aliases = if self.transaction_id == self.original_transaction_id {
            Vec::new()
        } else {
            vec![self.transaction_id]
        };
        Ok(VerifiedPurchase {
            provider: Provider::AppStore,
            product: self.product,
            id: self.original_transaction_id,
            aliases,
            account_token: self.account_token,
            expires_at_unix: self.expires_at_unix,
        })
    }
}

/// What a notification asks of the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotificationAction {
    /// Re-read this purchase from Apple with [`AppStoreClient::current`], and
    /// store it on the account it is linked to.
    Refresh(PurchaseRef),
    /// Nothing to do: a TEST ping, another app's or product's notification,
    /// or a type with no transaction.
    Ignore(&'static str),
}

/// Enough to look a purchase up again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurchaseRef {
    pub product: ProductKey,
    pub original_transaction_id: String,
    pub transaction_id: String,
    pub environment: Option<Environment>,
}

/// Apple's ids are decimal; anything else must not reach a URL path.
fn path_transaction_id(id: &str) -> Result<&str, VerifyError> {
    if id.is_empty() || id.len() > 32 || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(VerifyError::InvalidProof);
    }
    Ok(id)
}

/// Apple's dates are milliseconds; entitlements keep seconds.
fn seconds(milliseconds: i64) -> i64 {
    milliseconds.div_euclid(1_000)
}
/// Verifies App Store purchases for one app.
pub struct AppStoreClient {
    config: AppStoreConfig,
    verifier: SignedDataVerifier,
}

impl std::fmt::Debug for AppStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStoreClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AppStoreClient {
    /// Trusts only Apple Root CA - G3.
    pub fn new(config: AppStoreConfig) -> Self {
        Self {
            config,
            verifier: SignedDataVerifier::apple(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_verifier(config: AppStoreConfig, verifier: SignedDataVerifier) -> Self {
        Self { config, verifier }
    }

    /// The purchase a device reports, as Apple has it now. The device's signed
    /// transaction must verify and name a product in `catalog`; the state then
    /// comes from the App Store Server API. Writes nothing.
    pub async fn verify(
        &self,
        catalog: &Catalog,
        proof: &PurchaseProof,
    ) -> Result<AppStorePurchase, VerifyError> {
        let purchase = self.submitted(catalog, proof, UnixTime::now())?;
        self.current(catalog, &purchase).await
    }

    /// Checks a device's proof without calling Apple.
    fn submitted(
        &self,
        catalog: &Catalog,
        proof: &PurchaseProof,
        now: UnixTime,
    ) -> Result<PurchaseRef, VerifyError> {
        if proof.provider != Provider::AppStore || proof.token.len() > MAX_PROOF_LEN {
            return Err(VerifyError::InvalidProof);
        }
        let submitted: TransactionInfo = self
            .verifier
            .verify(&proof.token, now)
            .map_err(|_| VerifyError::InvalidProof)?;
        path_transaction_id(&submitted.transaction_id)?;
        path_transaction_id(&submitted.original_transaction_id)?;
        if submitted.transaction_id != proof.transaction_id {
            return Err(VerifyError::InvalidProof);
        }
        let product = self.product_of(catalog, &submitted)?;
        if product.key != proof.product {
            return Err(VerifyError::Rejected);
        }
        Ok(PurchaseRef {
            product: product.key.clone(),
            original_transaction_id: submitted.original_transaction_id,
            transaction_id: submitted.transaction_id,
            environment: submitted.environment,
        })
    }

    /// The purchase's state right now, according to Apple.
    pub async fn current(
        &self,
        catalog: &Catalog,
        purchase: &PurchaseRef,
    ) -> Result<AppStorePurchase, VerifyError> {
        let product = catalog
            .get(&purchase.product)
            .ok_or(VerifyError::UnknownProduct)?;
        let now = UnixTime::now();
        match product.kind {
            PurchaseKind::OneTime => {
                let path = format!(
                    "/inApps/v1/transactions/{}",
                    path_transaction_id(&purchase.transaction_id)?
                );
                let response: TransactionInfoResponse =
                    self.get(&path, purchase.environment).await?;
                let transaction: TransactionInfo = self
                    .verifier
                    .verify(&response.signed_transaction_info, now)
                    .map_err(|_| VerifyError::Rejected)?;
                self.one_time_state(catalog, purchase, transaction)
            }
            PurchaseKind::Subscription => {
                let path = format!(
                    "/inApps/v1/subscriptions/{}",
                    path_transaction_id(&purchase.original_transaction_id)?
                );
                let status: StatusResponse = self.get(&path, purchase.environment).await?;
                self.subscription_state(catalog, purchase, &status, now)
            }
        }
    }

    /// Verifies a notification's `signedPayload` and its transaction, and
    /// says which purchase it is about. An `Err` is a forged or broken
    /// payload, to answer with a 400.
    pub fn route_notification(
        &self,
        catalog: &Catalog,
        signed_payload: &str,
    ) -> Result<NotificationAction, VerifyError> {
        self.route_notification_at(catalog, signed_payload, UnixTime::now())
    }

    fn route_notification_at(
        &self,
        catalog: &Catalog,
        signed_payload: &str,
        now: UnixTime,
    ) -> Result<NotificationAction, VerifyError> {
        let payload: NotificationPayload = self
            .verifier
            .verify(signed_payload, now)
            .map_err(|_| VerifyError::InvalidProof)?;
        if payload.notification_type == "TEST" {
            return Ok(NotificationAction::Ignore("test"));
        }
        let Some(data) = payload.data else {
            return Ok(NotificationAction::Ignore("no_data"));
        };
        if data.bundle_id.as_deref() != Some(self.config.bundle_id.as_str()) {
            return Ok(NotificationAction::Ignore("other_bundle"));
        }
        if data.environment == Some(Environment::Production)
            && self
                .config
                .app_apple_id
                .is_some_and(|expected| data.app_apple_id != Some(expected))
        {
            return Ok(NotificationAction::Ignore("other_app"));
        }
        let Some(signed_transaction) = data.signed_transaction_info else {
            return Ok(NotificationAction::Ignore("no_transaction"));
        };
        let transaction: TransactionInfo = self
            .verifier
            .verify(&signed_transaction, now)
            .map_err(|_| VerifyError::InvalidProof)?;
        let Ok(product) = self.product_of(catalog, &transaction) else {
            return Ok(NotificationAction::Ignore("other_product"));
        };
        Ok(NotificationAction::Refresh(PurchaseRef {
            product: product.key.clone(),
            original_transaction_id: transaction.original_transaction_id,
            transaction_id: transaction.transaction_id,
            environment: data.environment.or(transaction.environment),
        }))
    }

    /// The catalog product a verified transaction of this app is for.
    fn product_of<'a>(
        &self,
        catalog: &'a Catalog,
        transaction: &TransactionInfo,
    ) -> Result<&'a CatalogProduct, VerifyError> {
        if transaction.bundle_id != self.config.bundle_id {
            return Err(VerifyError::Rejected);
        }
        catalog
            .by_app_store_id(&transaction.product_id)
            .ok_or(VerifyError::UnknownProduct)
    }

    fn one_time_state(
        &self,
        catalog: &Catalog,
        purchase: &PurchaseRef,
        transaction: TransactionInfo,
    ) -> Result<AppStorePurchase, VerifyError> {
        let product = self.product_of(catalog, &transaction)?;
        if transaction.transaction_id != purchase.transaction_id
            || transaction.original_transaction_id != purchase.original_transaction_id
            || product.key != purchase.product
        {
            return Err(VerifyError::Rejected);
        }
        Ok(AppStorePurchase {
            product: product.key.clone(),
            kind: PurchaseKind::OneTime,
            original_transaction_id: transaction.original_transaction_id,
            transaction_id: transaction.transaction_id,
            account_token: transaction.app_account_token,
            expires_at_unix: None,
            revoked_at_unix: transaction.revocation_date.map(seconds),
            will_auto_renew: false,
        })
    }

    /// The subscription's state from a status response, from its verified
    /// transaction and renewal info. A renewal moves `expiresDate` forward,
    /// an expiry leaves it in the past, a refund sets `revocationDate`
    /// (cleared again when Apple reverses it), and a billing grace period
    /// extends access to its end.
    fn subscription_state(
        &self,
        catalog: &Catalog,
        purchase: &PurchaseRef,
        status: &StatusResponse,
        now: UnixTime,
    ) -> Result<AppStorePurchase, VerifyError> {
        let original = purchase.original_transaction_id.as_str();
        let last = status
            .data
            .iter()
            .flat_map(|group| &group.last_transactions)
            .find(|last| last.original_transaction_id == original)
            .ok_or(VerifyError::NotFound)?;
        let transaction: TransactionInfo = self
            .verifier
            .verify(&last.signed_transaction_info, now)
            .map_err(|_| VerifyError::Rejected)?;
        let product = self.product_of(catalog, &transaction)?;
        if transaction.original_transaction_id != original || product.key != purchase.product {
            return Err(VerifyError::Rejected);
        }
        let renewal: Option<RenewalInfo> = last
            .signed_renewal_info
            .as_deref()
            .map(|jws| self.verifier.verify(jws, now))
            .transpose()
            .map_err(|_| VerifyError::Rejected)?;
        if renewal
            .as_ref()
            .and_then(|renewal| renewal.original_transaction_id.as_deref())
            .is_some_and(|id| id != original)
        {
            return Err(VerifyError::Rejected);
        }
        let grace = renewal
            .as_ref()
            .and_then(|renewal| renewal.grace_period_expires_date);
        let revoked_at_unix = transaction.revocation_date.map(seconds);
        Ok(AppStorePurchase {
            product: product.key.clone(),
            kind: PurchaseKind::Subscription,
            original_transaction_id: transaction.original_transaction_id,
            transaction_id: transaction.transaction_id,
            account_token: transaction.app_account_token,
            expires_at_unix: transaction.expires_date.max(grace).map(seconds),
            revoked_at_unix,
            will_auto_renew: revoked_at_unix.is_none()
                && renewal.and_then(|renewal| renewal.auto_renew_status) == Some(1),
        })
    }

    /// A GET against whichever environment knows the purchase: the one it
    /// names first, then the other.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        environment: Option<Environment>,
    ) -> Result<T, VerifyError> {
        let client = http_client()?;
        let authorization = self.config.authorization()?;
        for origin in Environment::api_origins(environment) {
            let response = client
                .get(format!("{origin}{path}"))
                .bearer_auth(&authorization)
                .send()
                .await?;
            match response.status() {
                reqwest::StatusCode::NOT_FOUND => continue,
                status if status.is_success() => return Ok(response.json().await?),
                reqwest::StatusCode::UNAUTHORIZED => {
                    return Err(VerifyError::Configuration(
                        "Apple refused the App Store API key".into(),
                    ));
                }
                status => {
                    return Err(VerifyError::Unavailable(format!(
                        "App Store answered {status}"
                    )));
                }
            }
        }
        Err(VerifyError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{apple_jws::testing, catalog::CatalogProduct};
    use serde_json::{Value, json};

    const BUNDLE: &str = "com.example.app";
    const ANNUAL: &str = "com.example.app.annual";
    const FULL_GAME: &str = "com.example.app.full_game";
    const ORIGINAL: &str = "2000000000000";
    const LATEST: &str = "2000000000009";
    /// Inside the synthetic chain's validity, as `testing::now()`.
    const NOW_MS: i64 = 1_800_000_000_000;
    const NOW: i64 = 1_800_000_000;
    const DAY_MS: i64 = 86_400_000;

    fn catalog() -> Catalog {
        Catalog::new(vec![
            CatalogProduct::new("membership", PurchaseKind::Subscription).app_store_id(ANNUAL),
            CatalogProduct::new("full_game", PurchaseKind::OneTime).app_store_id(FULL_GAME),
        ])
        .unwrap()
    }

    fn client() -> AppStoreClient {
        AppStoreClient::with_verifier(
            AppStoreConfig {
                issuer_id: "issuer".into(),
                key_id: "key".into(),
                private_key_pem: String::new(),
                bundle_id: BUNDLE.into(),
                app_apple_id: Some(1_234_567_890),
            },
            testing::verifier(),
        )
    }

    fn subscription(expires_ms: i64) -> Value {
        json!({
            "transactionId": LATEST, "originalTransactionId": ORIGINAL,
            "bundleId": BUNDLE, "productId": ANNUAL,
            "expiresDate": expires_ms, "environment": "Production",
        })
    }

    fn one_time() -> Value {
        json!({
            "transactionId": ORIGINAL, "originalTransactionId": ORIGINAL,
            "bundleId": BUNDLE, "productId": FULL_GAME,
            "appAccountToken": "0b5f6c1e-7d2a-4a7e-9b1c-3f8e2d4a6b10",
            "environment": "Production",
        })
    }

    fn renewal(auto_renew: bool) -> Value {
        json!({ "originalTransactionId": ORIGINAL, "autoRenewStatus": i32::from(auto_renew) })
    }

    fn membership_ref() -> PurchaseRef {
        PurchaseRef {
            product: ProductKey::from("membership"),
            original_transaction_id: ORIGINAL.into(),
            transaction_id: LATEST.into(),
            environment: None,
        }
    }

    fn status(transaction: &Value, renewal: Option<&Value>) -> StatusResponse {
        StatusResponse {
            data: vec![SubscriptionGroupStatus {
                last_transactions: vec![LastTransaction {
                    original_transaction_id: ORIGINAL.into(),
                    signed_transaction_info: testing::sign(transaction),
                    signed_renewal_info: renewal.map(testing::sign),
                }],
            }],
        }
    }

    fn state(
        transaction: &Value,
        renewal: Option<&Value>,
    ) -> Result<AppStorePurchase, VerifyError> {
        client().subscription_state(
            &catalog(),
            &membership_ref(),
            &status(transaction, renewal),
            testing::now(),
        )
    }

    fn info(value: Value) -> TransactionInfo {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_renewal_moves_the_membership_to_the_new_period() {
        let renewed = state(&subscription(NOW_MS + 300 * DAY_MS), Some(&renewal(true))).unwrap();
        assert!(renewed.is_active_at(NOW));
        assert_eq!(renewed.expires_at_unix, Some(NOW + 300 * 86_400));
        assert!(renewed.will_auto_renew);
        let verified = renewed.into_verified().unwrap();
        assert_eq!(verified.id, ORIGINAL);
        assert_eq!(verified.aliases, vec![LATEST.to_string()]);
    }

    #[test]
    fn an_expired_subscription_is_not_active_but_still_links() {
        let expired = state(&subscription(NOW_MS - DAY_MS), Some(&renewal(false))).unwrap();
        assert!(!expired.is_active_at(NOW));
        let verified = expired.into_verified().unwrap();
        assert_eq!(verified.expires_at_unix, Some(NOW - 86_400));
    }

    #[test]
    fn turning_off_auto_renew_keeps_access_until_the_period_ends() {
        let cancelled = state(&subscription(NOW_MS + DAY_MS), Some(&renewal(false))).unwrap();
        assert!(cancelled.is_active_at(NOW));
        assert!(!cancelled.is_active_at(NOW + 86_400));
        assert!(!cancelled.will_auto_renew);
    }

    #[test]
    fn a_refund_revokes_access_at_once_and_a_reversal_restores_it() {
        let mut refunded = subscription(NOW_MS + 300 * DAY_MS);
        refunded["revocationDate"] = json!(NOW_MS - 1_000);
        let revoked = state(&refunded, Some(&renewal(true))).unwrap();
        assert!(!revoked.is_active_at(NOW));
        assert!(!revoked.will_auto_renew);
        assert_eq!(revoked.into_verified(), Err(VerifyError::Rejected));
        refunded.as_object_mut().unwrap().remove("revocationDate");
        assert!(
            state(&refunded, Some(&renewal(true)))
                .unwrap()
                .is_active_at(NOW)
        );
    }

    #[test]
    fn the_billing_grace_period_keeps_access_until_it_ends() {
        let grace = json!({
            "originalTransactionId": ORIGINAL, "autoRenewStatus": 1,
            "gracePeriodExpiresDate": NOW_MS + 6 * DAY_MS,
        });
        let in_grace = state(&subscription(NOW_MS - DAY_MS), Some(&grace)).unwrap();
        assert!(in_grace.is_active_at(NOW));
        assert_eq!(in_grace.expires_at_unix, Some(NOW + 6 * 86_400));
    }

    #[test]
    fn a_status_for_another_product_or_app_is_refused() {
        let mut other_product = subscription(NOW_MS + DAY_MS);
        other_product["productId"] = json!("com.example.app.monthly");
        assert_eq!(
            state(&other_product, None),
            Err(VerifyError::UnknownProduct)
        );
        let mut other_app = subscription(NOW_MS + DAY_MS);
        other_app["bundleId"] = json!("com.example.other");
        assert_eq!(state(&other_app, None), Err(VerifyError::Rejected));
        let foreign_renewal = json!({ "originalTransactionId": "2000000000777" });
        assert_eq!(
            state(&subscription(NOW_MS + DAY_MS), Some(&foreign_renewal)),
            Err(VerifyError::Rejected)
        );
    }

    #[test]
    fn a_status_that_does_not_verify_or_lacks_the_subscription_is_refused() {
        let mut forged = status(&subscription(NOW_MS + DAY_MS), None);
        forged.data[0].last_transactions[0].signed_transaction_info = "e30.e30.e30".into();
        assert_eq!(
            client().subscription_state(&catalog(), &membership_ref(), &forged, testing::now()),
            Err(VerifyError::Rejected)
        );
        let empty = StatusResponse { data: Vec::new() };
        assert_eq!(
            client().subscription_state(&catalog(), &membership_ref(), &empty, testing::now()),
            Err(VerifyError::NotFound)
        );
    }

    #[test]
    fn a_one_time_purchase_is_active_until_revoked() {
        let reference = PurchaseRef {
            product: ProductKey::from("full_game"),
            original_transaction_id: ORIGINAL.into(),
            transaction_id: ORIGINAL.into(),
            environment: None,
        };
        let bought = client()
            .one_time_state(&catalog(), &reference, info(one_time()))
            .unwrap();
        assert!(bought.is_active_at(i64::MAX));
        let verified = bought.into_verified().unwrap();
        assert_eq!(verified.provider, Provider::AppStore);
        assert!(verified.aliases.is_empty());
        assert_eq!(
            verified.account_token.as_deref(),
            Some("0b5f6c1e-7d2a-4a7e-9b1c-3f8e2d4a6b10")
        );
        let mut refunded = one_time();
        refunded["revocationDate"] = json!(NOW_MS);
        let revoked = client()
            .one_time_state(&catalog(), &reference, info(refunded))
            .unwrap();
        assert_eq!(revoked.revoked_at_unix, Some(NOW));
        assert!(!revoked.is_active_at(NOW));
        let mut another = one_time();
        another["transactionId"] = json!("2000000000123");
        assert_eq!(
            client().one_time_state(&catalog(), &reference, info(another)),
            Err(VerifyError::Rejected)
        );
    }

    #[test]
    fn a_device_proof_must_verify_and_match_its_product() {
        let proof = |claims: &Value, product: &str, transaction: &str| PurchaseProof {
            provider: Provider::AppStore,
            product: ProductKey::from(product),
            token: testing::sign(claims),
            transaction_id: transaction.into(),
        };
        let submitted = client()
            .submitted(
                &catalog(),
                &proof(&one_time(), "full_game", ORIGINAL),
                testing::now(),
            )
            .unwrap();
        assert_eq!(submitted.product, ProductKey::from("full_game"));
        for (bad, expected) in [
            (
                proof(&one_time(), "full_game", LATEST),
                VerifyError::InvalidProof,
            ),
            (
                proof(&one_time(), "membership", ORIGINAL),
                VerifyError::Rejected,
            ),
        ] {
            assert_eq!(
                client().submitted(&catalog(), &bad, testing::now()),
                Err(expected)
            );
        }
        let mut unsigned = proof(&one_time(), "full_game", ORIGINAL);
        unsigned.token = "e30.e30.e30".into();
        assert_eq!(
            client().submitted(&catalog(), &unsigned, testing::now()),
            Err(VerifyError::InvalidProof)
        );
        let mut other_store = proof(&one_time(), "full_game", ORIGINAL);
        other_store.provider = Provider::PlayStore;
        assert_eq!(
            client().submitted(&catalog(), &other_store, testing::now()),
            Err(VerifyError::InvalidProof)
        );
    }

    fn notification(kind: &str, data: Value) -> String {
        testing::sign(&json!({ "notificationType": kind, "data": data }))
    }

    fn route(payload: &str) -> Result<NotificationAction, VerifyError> {
        client().route_notification_at(&catalog(), payload, testing::now())
    }

    #[test]
    fn a_renewal_or_refund_notification_refreshes_its_purchase() {
        let renewed = notification(
            "DID_RENEW",
            json!({
                "bundleId": BUNDLE, "appAppleId": 1_234_567_890, "environment": "Production",
                "signedTransactionInfo": testing::sign(&subscription(NOW_MS + DAY_MS)),
            }),
        );
        assert_eq!(
            route(&renewed),
            Ok(NotificationAction::Refresh(PurchaseRef {
                environment: Some(Environment::Production),
                ..membership_ref()
            }))
        );
        let refund = notification(
            "REFUND",
            json!({
                "bundleId": BUNDLE, "appAppleId": 1_234_567_890, "environment": "Production",
                "signedTransactionInfo": testing::sign(&one_time()),
            }),
        );
        let Ok(NotificationAction::Refresh(reference)) = route(&refund) else {
            panic!("a refund refreshes the purchase");
        };
        assert_eq!(reference.product, ProductKey::from("full_game"));
    }

    #[test]
    fn a_sandbox_notification_is_honoured_for_app_review() {
        let sandbox = notification(
            "SUBSCRIBED",
            json!({
                "bundleId": BUNDLE, "environment": "Sandbox",
                "signedTransactionInfo": testing::sign(&subscription(NOW_MS + DAY_MS)),
            }),
        );
        let Ok(NotificationAction::Refresh(reference)) = route(&sandbox) else {
            panic!("a sandbox notification refreshes the purchase");
        };
        assert_eq!(reference.environment, Some(Environment::Sandbox));
    }

    #[test]
    fn notifications_that_are_not_this_apps_are_ignored() {
        let transaction = testing::sign(&subscription(NOW_MS + DAY_MS));
        let mut other_product = subscription(NOW_MS + DAY_MS);
        other_product["productId"] = json!("com.example.app.monthly");
        for (payload, reason) in [
            (
                testing::sign(&json!({ "notificationType": "TEST" })),
                "test",
            ),
            (
                testing::sign(&json!({ "notificationType": "DID_RENEW" })),
                "no_data",
            ),
            (
                notification("DID_RENEW", json!({ "bundleId": "com.example.other" })),
                "other_bundle",
            ),
            (
                notification(
                    "DID_RENEW",
                    json!({
                        "bundleId": BUNDLE, "appAppleId": 42, "environment": "Production",
                        "signedTransactionInfo": transaction,
                    }),
                ),
                "other_app",
            ),
            (
                notification("DID_RENEW", json!({ "bundleId": BUNDLE })),
                "no_transaction",
            ),
            (
                notification(
                    "DID_RENEW",
                    json!({
                        "bundleId": BUNDLE, "signedTransactionInfo": testing::sign(&other_product),
                    }),
                ),
                "other_product",
            ),
        ] {
            assert_eq!(
                route(&payload),
                Ok(NotificationAction::Ignore(reason)),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_notification_that_does_not_verify_is_refused() {
        assert_eq!(route("e30.e30.e30"), Err(VerifyError::InvalidProof));
        let production = AppStoreClient::new(client().config.clone());
        assert_eq!(
            production.route_notification(&catalog(), &notification("TEST", json!({}))),
            Err(VerifyError::InvalidProof),
            "the production verifier trusts only the real Apple root"
        );
    }

    #[test]
    fn transaction_ids_must_be_numeric_before_reaching_a_url() {
        assert!(path_transaction_id("2000000000000").is_ok());
        let too_long = "9".repeat(33);
        for bad in ["", "12/34", "../1", "1?x", too_long.as_str()] {
            assert_eq!(
                path_transaction_id(bad),
                Err(VerifyError::InvalidProof),
                "{bad}"
            );
        }
    }

    #[test]
    fn apple_dates_convert_from_milliseconds() {
        assert_eq!(seconds(1_800_000_000_999), 1_800_000_000);
        assert_eq!(seconds(-1), -1);
    }

    #[test]
    fn the_api_key_never_reaches_debug_output() {
        assert!(format!("{:?}", client()).contains("[redacted]"));
    }
}
