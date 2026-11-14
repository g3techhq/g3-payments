//! [`PaymentsService`]: the providers an app uses, its catalog and its
//! [`Store`], tied together.
//!
//! An app builds one at startup and calls it from its own server functions
//! (verifying a store purchase, starting a checkout) with its own user, and
//! mounts [`routes`](super::routes) for the webhooks that need no session.

use super::{
    VerifiedPurchase, VerifyError, now_unix,
    store::{PurchaseRecord, Store, StoreError},
};
use crate::{
    catalog::Catalog,
    entitlements::{Entitlement, EntitlementSnapshot, EntitlementStatus, Provider, PurchaseProof},
};

#[cfg(feature = "app-store")]
use super::app_store::{AppStoreClient, NotificationAction};
#[cfg(feature = "play")]
use super::play::PlayClient;
#[cfg(feature = "stripe")]
use super::stripe::{
    CheckoutRequest, CheckoutSession, Event, StripeAction, StripeClient, route_event,
};

/// Why a request to the service failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentsError {
    Verify(VerifyError),
    Store(StoreError),
    /// The purchase was made by, or is claimed by, another account. Sign in
    /// to that account, or ask support to review it.
    NeedsOriginalAccount,
    /// The service has no client for this provider.
    NotConfigured(Provider),
}

impl PaymentsError {
    /// Whether retrying the same request later could succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Verify(error) => error.is_retryable(),
            Self::Store(StoreError::Unavailable(_)) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for PaymentsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
            Self::NeedsOriginalAccount => f.write_str("purchase_needs_original_account"),
            Self::NotConfigured(provider) => write!(f, "provider_not_configured: {provider:?}"),
        }
    }
}

impl std::error::Error for PaymentsError {}

impl From<VerifyError> for PaymentsError {
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

impl From<StoreError> for PaymentsError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::ClaimedByAnother => Self::NeedsOriginalAccount,
            error => Self::Store(error),
        }
    }
}

/// What handling a webhook or notification did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookOutcome {
    /// Stored.
    Handled,
    /// Already handled once.
    Duplicate,
    /// Nothing to do, and why.
    Ignored(&'static str),
    /// About a purchase no account has claimed yet. Its own verification
    /// will store it.
    Unlinked,
    /// About a purchase another account holds. Retrying cannot help; worth
    /// logging for support.
    Conflict,
}

/// Why a webhook or notification was not handled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookFailure {
    /// It did not verify, or could not be read: answer 400.
    Rejected,
    /// The provider, the store or the configuration failed: answer 500, so
    /// the provider sends it again.
    Retry(String),
}

impl From<StoreError> for WebhookFailure {
    fn from(error: StoreError) -> Self {
        Self::Retry(error.to_string())
    }
}

/// An app's payments.
pub struct PaymentsService<S> {
    catalog: Catalog,
    store: S,
    #[cfg(feature = "stripe")]
    stripe: Option<StripeClient>,
    #[cfg(feature = "app-store")]
    app_store: Option<AppStoreClient>,
    #[cfg(feature = "play")]
    play: Option<PlayClient>,
}

impl<S: Store> PaymentsService<S> {
    pub fn new(catalog: Catalog, store: S) -> Self {
        Self {
            catalog,
            store,
            #[cfg(feature = "stripe")]
            stripe: None,
            #[cfg(feature = "app-store")]
            app_store: None,
            #[cfg(feature = "play")]
            play: None,
        }
    }

    #[cfg(feature = "stripe")]
    pub fn with_stripe(mut self, client: StripeClient) -> Self {
        self.stripe = Some(client);
        self
    }

    #[cfg(feature = "app-store")]
    pub fn with_app_store(mut self, client: AppStoreClient) -> Self {
        self.app_store = Some(client);
        self
    }

    #[cfg(feature = "play")]
    pub fn with_play(mut self, client: PlayClient) -> Self {
        self.play = Some(client);
        self
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// What `owner` has.
    pub async fn snapshot(&self, owner: &str) -> Result<EntitlementSnapshot, PaymentsError> {
        Ok(self.store.snapshot(owner).await?)
    }

    /// Verifies a store purchase a device reports.
    ///
    /// Signed in (`owner` set), the purchase is claimed for that account and
    /// its whole snapshot comes back. Signed out, nothing is written: the
    /// snapshot holds just the verified product, for the device to keep, as
    /// App Review requires buying and Restore to work without an account.
    pub async fn verify_native(
        &self,
        owner: Option<&str>,
        proof: &PurchaseProof,
    ) -> Result<EntitlementSnapshot, PaymentsError> {
        let purchase = self.verify_proof(proof).await?;
        let Some(owner) = owner else {
            return Ok(device_grant(&purchase, now_unix()));
        };
        if let (Some(theirs), Some(ours)) = (
            purchase.account_token.as_deref(),
            self.store.account_token(owner).await?,
        ) && !theirs.eq_ignore_ascii_case(&ours)
        {
            return Err(PaymentsError::NeedsOriginalAccount);
        }
        self.store
            .record(owner, active_record(purchase, now_unix()))
            .await?;
        self.snapshot(owner).await
    }

    async fn verify_proof(&self, proof: &PurchaseProof) -> Result<VerifiedPurchase, PaymentsError> {
        match proof.provider {
            #[cfg(feature = "app-store")]
            Provider::AppStore => {
                let client = self
                    .app_store
                    .as_ref()
                    .ok_or(PaymentsError::NotConfigured(Provider::AppStore))?;
                Ok(client.verify(&self.catalog, proof).await?.into_verified()?)
            }
            #[cfg(feature = "play")]
            Provider::PlayStore => {
                let client = self
                    .play
                    .as_ref()
                    .ok_or(PaymentsError::NotConfigured(Provider::PlayStore))?;
                Ok(client.verify(&self.catalog, proof).await?)
            }
            provider => Err(PaymentsError::NotConfigured(provider)),
        }
    }

    /// A Stripe Checkout Session for `request`.
    #[cfg(feature = "stripe")]
    pub async fn checkout(
        &self,
        request: CheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        let client = self
            .stripe
            .as_ref()
            .ok_or(PaymentsError::NotConfigured(Provider::Stripe))?;
        Ok(client.create_checkout(&self.catalog, request).await?)
    }

    /// Handles one Stripe webhook delivery: the raw body and its
    /// `Stripe-Signature` header.
    #[cfg(feature = "stripe")]
    pub async fn handle_stripe_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<WebhookOutcome, WebhookFailure> {
        let client = self
            .stripe
            .as_ref()
            .ok_or_else(|| WebhookFailure::Retry("Stripe is not configured".into()))?;
        let event = Event::verified(payload, signature, client.config())
            .map_err(|_| WebhookFailure::Rejected)?;
        if self.store.event_seen(Provider::Stripe, &event.id).await? {
            return Ok(WebhookOutcome::Duplicate);
        }
        let outcome = self.apply_stripe(client, &event).await?;
        // Marked only once handled, so a failure is retried by Stripe.
        self.store.mark_event(Provider::Stripe, &event.id).await?;
        Ok(outcome)
    }

    #[cfg(feature = "stripe")]
    async fn apply_stripe(
        &self,
        client: &StripeClient,
        event: &Event,
    ) -> Result<WebhookOutcome, WebhookFailure> {
        match route_event(&self.catalog, &client.config().app, event) {
            StripeAction::Grant {
                user,
                product,
                purchase_id,
                created,
                ..
            } => {
                let record = PurchaseRecord {
                    provider: Provider::Stripe,
                    product,
                    id: purchase_id,
                    aliases: Vec::new(),
                    status: EntitlementStatus::Active,
                    expires_at_unix: None,
                    event_created: created,
                };
                stored(self.store.record(&user, record).await)
            }
            StripeAction::Revoke {
                purchase_id,
                created,
            } => {
                let owner = self
                    .store
                    .update(
                        Provider::Stripe,
                        &purchase_id,
                        EntitlementStatus::Revoked,
                        None,
                        created,
                    )
                    .await?;
                Ok(owner.map_or(WebhookOutcome::Unlinked, |_| WebhookOutcome::Handled))
            }
            StripeAction::RefreshSubscription {
                subscription_id,
                user,
                deleted,
                created,
            } => {
                let subscription = match deleted {
                    Some(subscription) => subscription,
                    None => client
                        .subscription(&subscription_id)
                        .await
                        .map_err(|error| WebhookFailure::Retry(error.to_string()))?,
                };
                let Some(product) = subscription.product(&self.catalog).cloned() else {
                    return Ok(WebhookOutcome::Ignored("other_product"));
                };
                let owner = match user {
                    Some(user) => Some(user),
                    None => match self
                        .store
                        .owner_of(Provider::Stripe, &subscription.id)
                        .await?
                    {
                        Some(owner) => Some(owner),
                        None => self.store.owner_of_customer(&subscription.customer).await?,
                    },
                };
                let Some(owner) = owner else {
                    return Ok(WebhookOutcome::Unlinked);
                };
                // Lapsed: owned until no later than the event that said so.
                let expires = subscription
                    .access_until()
                    .unwrap_or(created.min(subscription.current_period_end));
                let record = PurchaseRecord {
                    provider: Provider::Stripe,
                    product,
                    id: subscription.id,
                    aliases: Vec::new(),
                    status: EntitlementStatus::Active,
                    expires_at_unix: Some(expires),
                    event_created: created,
                };
                stored(self.store.record(&owner, record).await)
            }
            StripeAction::Ignore(reason) => Ok(WebhookOutcome::Ignored(reason)),
        }
    }

    /// Handles one App Store Server Notification V2: its `signedPayload`.
    #[cfg(feature = "app-store")]
    pub async fn handle_app_store_notification(
        &self,
        signed_payload: &str,
    ) -> Result<WebhookOutcome, WebhookFailure> {
        let client = self
            .app_store
            .as_ref()
            .ok_or_else(|| WebhookFailure::Retry("the App Store is not configured".into()))?;
        let reference = match client.route_notification(&self.catalog, signed_payload) {
            Ok(NotificationAction::Refresh(reference)) => reference,
            Ok(NotificationAction::Ignore(reason)) => return Ok(WebhookOutcome::Ignored(reason)),
            Err(_) => return Err(WebhookFailure::Rejected),
        };
        let Some(owner) = self
            .store
            .owner_of(Provider::AppStore, &reference.original_transaction_id)
            .await?
        else {
            return Ok(WebhookOutcome::Unlinked);
        };
        let purchase = client
            .current(&self.catalog, &reference)
            .await
            .map_err(|error| WebhookFailure::Retry(error.to_string()))?;
        let record = PurchaseRecord {
            provider: Provider::AppStore,
            product: purchase.product.clone(),
            id: purchase.original_transaction_id.clone(),
            aliases: if purchase.transaction_id == purchase.original_transaction_id {
                Vec::new()
            } else {
                vec![purchase.transaction_id.clone()]
            },
            status: if purchase.revoked_at_unix.is_some() {
                EntitlementStatus::Revoked
            } else {
                EntitlementStatus::Active
            },
            expires_at_unix: purchase.expires_at_unix,
            event_created: now_unix(),
        };
        stored(self.store.record(&owner, record).await)
    }
}

/// A write's result as an outcome: a claim conflict will not resolve on a
/// retry, so it is reported rather than failed.
#[cfg_attr(
    not(any(feature = "stripe", feature = "app-store")),
    allow(dead_code, reason = "Used by the webhook handlers.")
)]
fn stored(result: Result<(), StoreError>) -> Result<WebhookOutcome, WebhookFailure> {
    match result {
        Ok(()) => Ok(WebhookOutcome::Handled),
        Err(StoreError::ClaimedByAnother) => Ok(WebhookOutcome::Conflict),
        Err(error) => Err(error.into()),
    }
}

fn active_record(purchase: VerifiedPurchase, now: i64) -> PurchaseRecord {
    PurchaseRecord {
        provider: purchase.provider,
        product: purchase.product,
        id: purchase.id,
        aliases: purchase.aliases,
        status: EntitlementStatus::Active,
        expires_at_unix: purchase.expires_at_unix,
        event_created: now,
    }
}

/// The device's record of one verified purchase: the product and its
/// store, never the receipt or a purchase id.
fn device_grant(purchase: &VerifiedPurchase, verified_at: i64) -> EntitlementSnapshot {
    let mut snapshot = EntitlementSnapshot {
        revision: 1,
        ..Default::default()
    };
    snapshot.items.insert(
        purchase.product.clone(),
        Entitlement {
            product: purchase.product.clone(),
            provider: purchase.provider,
            status: EntitlementStatus::Active,
            provider_purchase_id: String::new(),
            granted_at_unix: verified_at,
            expires_at_unix: purchase.expires_at_unix,
        },
    );
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        catalog::{CatalogProduct, PurchaseKind},
        entitlements::ProductKey,
        server::store::MemoryStore,
    };

    fn catalog() -> Catalog {
        Catalog::new(vec![
            CatalogProduct::new("full_game", PurchaseKind::OneTime)
                .stripe_price("price_full")
                .store_id("com.example.app.full_game"),
            CatalogProduct::new("membership", PurchaseKind::Subscription)
                .stripe_price("price_annual")
                .app_store_id("com.example.app.annual"),
        ])
        .unwrap()
    }

    fn record(id: &str, created: i64) -> PurchaseRecord {
        PurchaseRecord {
            provider: Provider::Stripe,
            product: ProductKey::from("full_game"),
            id: id.into(),
            aliases: vec![format!("{id}_alias")],
            status: EntitlementStatus::Active,
            expires_at_unix: None,
            event_created: created,
        }
    }

    #[tokio::test]
    async fn a_purchase_and_its_aliases_belong_to_the_first_account_that_claims_them() {
        let store = MemoryStore::new();
        store.record("alice", record("pi_1", 10)).await.unwrap();
        assert_eq!(
            store.record("bob", record("pi_1", 11)).await,
            Err(StoreError::ClaimedByAnother)
        );
        let mut by_alias = record("pi_2", 11);
        by_alias.aliases = vec!["pi_1_alias".into()];
        assert_eq!(
            store.record("bob", by_alias).await,
            Err(StoreError::ClaimedByAnother)
        );
        assert_eq!(
            store
                .owner_of(Provider::Stripe, "pi_1_alias")
                .await
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        // The same account may record it again.
        store.record("alice", record("pi_1", 12)).await.unwrap();
    }

    #[tokio::test]
    async fn an_older_event_never_overwrites_a_newer_one() {
        let store = MemoryStore::new();
        store.record("alice", record("pi_1", 10)).await.unwrap();
        store
            .update(
                Provider::Stripe,
                "pi_1",
                EntitlementStatus::Revoked,
                None,
                20,
            )
            .await
            .unwrap();
        // A late copy of the original grant arrives.
        store.record("alice", record("pi_1", 10)).await.unwrap();
        assert!(!store.snapshot("alice").await.unwrap().owns("full_game"));
        // So does a late revocation, after a newer grant.
        store.record("alice", record("pi_1", 30)).await.unwrap();
        store
            .update(
                Provider::Stripe,
                "pi_1",
                EntitlementStatus::Revoked,
                None,
                25,
            )
            .await
            .unwrap();
        assert!(store.snapshot("alice").await.unwrap().owns("full_game"));
        assert_eq!(
            store
                .update(
                    Provider::Stripe,
                    "pi_unknown",
                    EntitlementStatus::Revoked,
                    None,
                    40
                )
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn an_active_grant_outranks_a_revoked_one_of_the_same_product() {
        let store = MemoryStore::new();
        store.record("alice", record("pi_1", 10)).await.unwrap();
        store
            .update(
                Provider::Stripe,
                "pi_1",
                EntitlementStatus::Revoked,
                None,
                20,
            )
            .await
            .unwrap();
        let mut from_the_store = record("2000000000000", 30);
        from_the_store.provider = Provider::AppStore;
        store.record("alice", from_the_store).await.unwrap();
        let snapshot = store.snapshot("alice").await.unwrap();
        assert!(snapshot.owns("full_game"));
        assert_eq!(
            snapshot.items[&ProductKey::from("full_game")].provider,
            Provider::AppStore
        );
        assert!(store.snapshot("bob").await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn a_provider_without_a_client_is_not_configured() {
        let service = PaymentsService::new(catalog(), MemoryStore::new());
        let proof = PurchaseProof {
            provider: Provider::Stripe,
            product: ProductKey::from("full_game"),
            token: "x".into(),
            transaction_id: "x".into(),
        };
        assert_eq!(
            service.verify_native(Some("alice"), &proof).await,
            Err(PaymentsError::NotConfigured(Provider::Stripe))
        );
    }

    #[test]
    fn a_device_grant_names_only_the_verified_product_and_no_receipt() {
        let purchase = VerifiedPurchase {
            provider: Provider::PlayStore,
            product: ProductKey::from("theme.space"),
            id: "synthetic-private-token".into(),
            aliases: vec!["GPA.1".into()],
            account_token: None,
            expires_at_unix: None,
        };
        let grant = device_grant(&purchase, 42);
        assert!(grant.owns("theme.space"));
        assert_eq!(grant.active_products().count(), 1);
        let item = &grant.items[&ProductKey::from("theme.space")];
        assert_eq!(item.provider, Provider::PlayStore);
        assert_eq!(item.granted_at_unix, 42);
        assert!(
            !serde_json::to_string(&grant)
                .unwrap()
                .contains("synthetic-private-token")
        );
    }

    #[test]
    fn a_claim_conflict_is_an_outcome_and_a_database_failure_is_a_retry() {
        assert_eq!(stored(Ok(())), Ok(WebhookOutcome::Handled));
        assert_eq!(
            stored(Err(StoreError::ClaimedByAnother)),
            Ok(WebhookOutcome::Conflict)
        );
        assert!(matches!(
            stored(Err(StoreError::Unavailable("down".into()))),
            Err(WebhookFailure::Retry(_))
        ));
        assert_eq!(
            PaymentsError::from(StoreError::ClaimedByAnother),
            PaymentsError::NeedsOriginalAccount
        );
    }

    #[cfg(feature = "stripe")]
    mod stripe {
        use super::*;
        use crate::server::stripe::StripeConfig;
        use serde_json::{Value, json};

        const SECRET: &str = "whsec_test";

        fn service() -> PaymentsService<MemoryStore> {
            PaymentsService::new(catalog(), MemoryStore::new()).with_stripe(StripeClient::new(
                StripeConfig {
                    secret_key: "sk_test".into(),
                    webhook_secret: SECRET.into(),
                    app: "swift-circuits".into(),
                },
            ))
        }

        fn delivery(id: &str, kind: &str, created: i64, object: Value) -> (Vec<u8>, String) {
            let payload = serde_json::to_vec(&json!({
                "id": id, "type": kind, "created": created, "data": { "object": object },
            }))
            .unwrap();
            let timestamp = now_unix();
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET.as_bytes());
            let mut signed = format!("{timestamp}.").into_bytes();
            signed.extend_from_slice(&payload);
            let tag = ring::hmac::sign(&key, &signed);
            let hex: String = tag
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            (payload, format!("t={timestamp},v1={hex}"))
        }

        fn paid(user: &str) -> Value {
            json!({
                "id": "cs_1", "mode": "payment", "payment_status": "paid", "payment_intent": "pi_1",
                "metadata": { "user_id": user, "product_key": "full_game", "g3_app": "swift-circuits" },
            })
        }

        async fn deliver(
            service: &PaymentsService<MemoryStore>,
            (payload, header): (Vec<u8>, String),
        ) -> Result<WebhookOutcome, WebhookFailure> {
            service.handle_stripe_webhook(&payload, &header).await
        }

        #[tokio::test]
        async fn a_paid_checkout_grants_and_a_full_refund_revokes() {
            let service = service();
            let granted = deliver(
                &service,
                delivery("evt_1", "checkout.session.completed", 10, paid("alice")),
            )
            .await;
            assert_eq!(granted, Ok(WebhookOutcome::Handled));
            assert!(service.snapshot("alice").await.unwrap().owns("full_game"));

            let refund = json!({ "refunded": true, "payment_intent": "pi_1" });
            let revoked = deliver(&service, delivery("evt_2", "charge.refunded", 20, refund)).await;
            assert_eq!(revoked, Ok(WebhookOutcome::Handled));
            assert!(!service.snapshot("alice").await.unwrap().owns("full_game"));
        }

        #[tokio::test]
        async fn a_repeated_event_is_handled_once_and_a_forged_one_is_refused() {
            let service = service();
            let first = delivery("evt_1", "checkout.session.completed", 10, paid("alice"));
            assert_eq!(
                deliver(&service, first.clone()).await,
                Ok(WebhookOutcome::Handled)
            );
            assert_eq!(
                deliver(&service, first.clone()).await,
                Ok(WebhookOutcome::Duplicate)
            );
            let (payload, _) = first;
            assert_eq!(
                service.handle_stripe_webhook(&payload, "t=1,v1=00").await,
                Err(WebhookFailure::Rejected)
            );
        }

        #[tokio::test]
        async fn a_refund_that_arrives_first_is_not_undone_by_its_late_grant() {
            let service = service();
            let refund = json!({ "refunded": true, "payment_intent": "pi_1" });
            // Nobody holds the purchase yet; the store keeps the refund for it.
            assert_eq!(
                deliver(&service, delivery("evt_2", "charge.refunded", 20, refund)).await,
                Ok(WebhookOutcome::Unlinked)
            );
            deliver(
                &service,
                delivery("evt_1", "checkout.session.completed", 10, paid("alice")),
            )
            .await
            .unwrap();
            assert!(!service.snapshot("alice").await.unwrap().owns("full_game"));
        }

        #[tokio::test]
        async fn a_payment_another_account_holds_is_a_conflict_not_a_retry() {
            let service = service();
            deliver(
                &service,
                delivery("evt_1", "checkout.session.completed", 10, paid("alice")),
            )
            .await
            .unwrap();
            assert_eq!(
                deliver(
                    &service,
                    delivery("evt_2", "checkout.session.completed", 11, paid("bob"))
                )
                .await,
                Ok(WebhookOutcome::Conflict)
            );
            assert!(!service.snapshot("bob").await.unwrap().owns("full_game"));
        }

        #[tokio::test]
        async fn a_deleted_subscription_ends_access_for_its_customer() {
            let service = service();
            service.store().set_customer("cus_1", "carol");
            let subscription = json!({
                "id": "sub_1", "customer": "cus_1", "status": "active",
                "items": { "data": [ { "price": "price_annual", "current_period_end": 5_000 } ] },
            });
            let outcome = deliver(
                &service,
                delivery(
                    "evt_1",
                    "customer.subscription.deleted",
                    1_000,
                    subscription,
                ),
            )
            .await;
            assert_eq!(outcome, Ok(WebhookOutcome::Handled));
            let (owner, record) = service.store().get(Provider::Stripe, "sub_1").unwrap();
            assert_eq!(owner, "carol");
            assert_eq!(record.expires_at_unix, Some(1_000));
            assert!(
                !service
                    .snapshot("carol")
                    .await
                    .unwrap()
                    .owns_at("membership", 1_000)
            );
            assert!(
                service
                    .snapshot("carol")
                    .await
                    .unwrap()
                    .owns_at("membership", 999)
            );
        }

        #[tokio::test]
        async fn another_apps_event_is_ignored() {
            let service = service();
            let mut other = paid("alice");
            other["metadata"]["g3_app"] = json!("tally");
            assert_eq!(
                deliver(
                    &service,
                    delivery("evt_1", "checkout.session.completed", 10, other)
                )
                .await,
                Ok(WebhookOutcome::Ignored("other_app"))
            );
            assert!(service.snapshot("alice").await.unwrap().items.is_empty());
        }
    }

    #[cfg(feature = "app-store")]
    mod app_store {
        use super::*;
        use crate::{
            apple_jws::testing,
            server::app_store::{AppStoreClient, AppStoreConfig},
        };
        use serde_json::json;

        fn service() -> PaymentsService<MemoryStore> {
            PaymentsService::new(catalog(), MemoryStore::new()).with_app_store(
                AppStoreClient::with_verifier(
                    AppStoreConfig {
                        issuer_id: "issuer".into(),
                        key_id: "key".into(),
                        private_key_pem: String::new(),
                        bundle_id: "com.example.app".into(),
                        app_apple_id: None,
                    },
                    testing::verifier(),
                ),
            )
        }

        #[tokio::test]
        async fn notifications_are_refused_ignored_or_left_for_their_purchase_to_link() {
            let service = service();
            assert_eq!(
                service.handle_app_store_notification("e30.e30.e30").await,
                Err(WebhookFailure::Rejected)
            );
            let test = testing::sign(&json!({ "notificationType": "TEST" }));
            assert_eq!(
                service.handle_app_store_notification(&test).await,
                Ok(WebhookOutcome::Ignored("test"))
            );
        }

        #[tokio::test]
        async fn a_notification_for_a_purchase_nobody_claimed_is_unlinked() {
            // `route_notification` checks certificates against the real clock,
            // which is inside the synthetic chain's validity until 2126.
            let transaction = testing::sign(&json!({
                "transactionId": "2000000000000", "originalTransactionId": "2000000000000",
                "bundleId": "com.example.app", "productId": "com.example.app.annual",
                "expiresDate": 1_900_000_000_000_i64,
            }));
            let notification = testing::sign(&json!({
                "notificationType": "DID_RENEW",
                "data": { "bundleId": "com.example.app", "environment": "Sandbox", "signedTransactionInfo": transaction },
            }));
            assert_eq!(
                service().handle_app_store_notification(&notification).await,
                Ok(WebhookOutcome::Unlinked)
            );
        }
    }
}
