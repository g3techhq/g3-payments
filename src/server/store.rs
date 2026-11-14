//! Where an app keeps purchases: the [`Store`] trait, and [`MemoryStore`]
//! for tests.
//!
//! Each app implements `Store` over its own database and account rules.
//! Swift Circuits keeps its privacy functions and entitlement table;
//! Greenside Partee keeps its subscription fields on `User`. The crate's
//! `surreal` feature has one for apps without rules of their own.
//!
//! Every write carries the provider event time it came from, and a store
//! drops a write older than what it holds, so a late or repeated webhook
//! cannot undo a newer one.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Mutex,
};

use crate::entitlements::{
    Entitlement, EntitlementSnapshot, EntitlementStatus, ProductKey, Provider,
};

/// One purchase as a provider last reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurchaseRecord {
    pub provider: Provider,
    pub product: ProductKey,
    /// The provider's stable id for the purchase. Ownership is keyed on it.
    pub id: String,
    /// Other ids for the same purchase, claimed with `id`.
    pub aliases: Vec<String>,
    pub status: EntitlementStatus,
    /// When a subscription's access ends; `None` for a one-time purchase.
    pub expires_at_unix: Option<i64>,
    /// The provider's time for the event this came from. A store keeps the
    /// newest.
    pub event_created: i64,
}

/// A Stripe subscription as Stripe has it after an event, for
/// [`Store::record_stripe_subscription`].
#[cfg(feature = "stripe")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionChange {
    pub product: ProductKey,
    pub subscription: super::stripe::Subscription,
    /// The account the event names (`metadata.user_id`, or the checkout's
    /// `client_reference_id`), if it names one. Unchecked: any Stripe
    /// object's metadata can say it.
    pub user: Option<String>,
    pub event_id: String,
    pub event_kind: String,
    pub event_created: i64,
}

#[cfg(feature = "stripe")]
impl SubscriptionChange {
    /// As a purchase record: owned until the period end while Stripe counts
    /// it as paid, and no later than the event that said otherwise.
    pub fn record(&self) -> PurchaseRecord {
        let subscription = &self.subscription;
        PurchaseRecord {
            provider: Provider::Stripe,
            product: self.product.clone(),
            id: subscription.id.clone(),
            aliases: Vec::new(),
            status: EntitlementStatus::Active,
            expires_at_unix: Some(
                subscription
                    .access_until()
                    .unwrap_or(self.event_created.min(subscription.current_period_end)),
            ),
            event_created: self.event_created,
        }
    }
}

/// Why a store refused or failed a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The purchase, or one of its ids, belongs to another account. A
    /// purchase never moves between accounts on its own.
    ClaimedByAnother,
    /// The account cannot take purchases (deleted, or being deleted).
    AccountUnavailable,
    /// The database failed. Worth retrying.
    Unavailable(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimedByAnother => f.write_str("purchase_claimed_by_another_account"),
            Self::AccountUnavailable => f.write_str("account_unavailable"),
            Self::Unavailable(detail) => write!(f, "store_unavailable: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// An app's purchase records. Owners are the app's own user ids, as text.
pub trait Store: Send + Sync {
    /// Claims `record` (its id and every alias) for `owner` and stores it,
    /// unless the store holds a newer event for the same purchase. Refuses
    /// with [`StoreError::ClaimedByAnother`] if any id is another account's.
    fn record(
        &self,
        owner: &str,
        record: PurchaseRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Changes the status and expiry of a purchase wherever it is linked,
    /// unless the store holds a newer event. Returns its owner, or `None` if
    /// no account has claimed it yet.
    ///
    /// A store must remember an update to a purchase it does not hold yet
    /// and apply it when [`record`](Self::record) brings an older event for
    /// that purchase: Stripe can deliver a refund before the checkout it
    /// refunds, and sends neither twice once answered.
    fn update(
        &self,
        provider: Provider,
        id: &str,
        status: EntitlementStatus,
        expires_at_unix: Option<i64>,
        event_created: i64,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    /// The account that claimed a purchase id or alias.
    fn owner_of(
        &self,
        provider: Provider,
        id: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    /// The account a Stripe customer belongs to, for a subscription event
    /// that names no user. Stores that do not track customers keep the
    /// default.
    fn owner_of_customer(
        &self,
        customer: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        let _ = customer;
        async { Ok(None) }
    }

    /// The account token `owner` hands to StoreKit and Play
    /// (`appAccountToken`, `obfuscatedAccountId`), if the app uses them. A
    /// verified purchase carrying another token needs its original account.
    fn account_token(
        &self,
        owner: &str,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        let _ = owner;
        async { Ok(None) }
    }

    /// Stores a subscription's state after a Stripe event, and returns the
    /// account it was stored for, or `None` if no account has it yet.
    ///
    /// The default finds the account the way most apps want (the account
    /// the event names, else the one holding the subscription, else the
    /// customer's) and [`record`](Self::record)s [`SubscriptionChange::record`].
    /// A store that keeps more of the subscription (its raw status, a
    /// scheduled cancellation) or chooses the account its own way overrides
    /// it.
    #[cfg(feature = "stripe")]
    fn record_stripe_subscription(
        &self,
        change: SubscriptionChange,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send {
        async move {
            let owner = match change.user.clone() {
                Some(user) => Some(user),
                None => match self
                    .owner_of(Provider::Stripe, &change.subscription.id)
                    .await?
                {
                    Some(owner) => Some(owner),
                    None => {
                        self.owner_of_customer(&change.subscription.customer)
                            .await?
                    }
                },
            };
            let Some(owner) = owner else {
                return Ok(None);
            };
            self.record(&owner, change.record()).await?;
            Ok(Some(owner))
        }
    }

    /// Stores an App Store purchase as Apple has it now, for `owner`.
    /// `record` is what the default [`record`](Self::record)s; a store that
    /// keeps more (auto-renewal, the revocation time) reads `purchase` too.
    #[cfg(feature = "app-store")]
    fn record_app_store(
        &self,
        owner: &str,
        purchase: &super::app_store::AppStorePurchase,
        record: PurchaseRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let _ = purchase;
        self.record(owner, record)
    }

    /// What `owner` has, for its clients.
    fn snapshot(
        &self,
        owner: &str,
    ) -> impl Future<Output = Result<EntitlementSnapshot, StoreError>> + Send;

    /// Whether a provider event was already handled.
    fn event_seen(
        &self,
        provider: Provider,
        event_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Marks a provider event handled, once handling it succeeded.
    fn mark_event(
        &self,
        provider: Provider,
        event_id: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// A store in memory, for tests and examples. Not durable.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    /// (provider, purchase id) to its owner and record.
    purchases: BTreeMap<(Provider, String), (String, PurchaseRecord)>,
    /// (provider, alias) to the purchase id it names.
    aliases: BTreeMap<(Provider, String), String>,
    /// Updates to purchases not recorded yet: (provider, id) to the status,
    /// expiry and event time to apply when they are.
    pending: BTreeMap<(Provider, String), (EntitlementStatus, Option<i64>, i64)>,
    customers: BTreeMap<String, String>,
    account_tokens: BTreeMap<String, String>,
    events: BTreeSet<(Provider, String)>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Links a Stripe customer to an account.
    pub fn set_customer(&self, customer: &str, owner: &str) {
        self.lock()
            .customers
            .insert(customer.to_string(), owner.to_string());
    }

    /// Gives an account its StoreKit and Play account token.
    pub fn set_account_token(&self, owner: &str, token: &str) {
        self.lock()
            .account_tokens
            .insert(owner.to_string(), token.to_string());
    }

    /// The record stored for a purchase id.
    pub fn get(&self, provider: Provider, id: &str) -> Option<(String, PurchaseRecord)> {
        self.lock()
            .purchases
            .get(&(provider, id.to_string()))
            .cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl MemoryState {
    fn purchase_id(&self, provider: Provider, id: &str) -> Option<String> {
        let key = (provider, id.to_string());
        if self.purchases.contains_key(&key) {
            return Some(id.to_string());
        }
        self.aliases.get(&key).cloned()
    }
}

impl Store for MemoryStore {
    async fn record(&self, owner: &str, mut record: PurchaseRecord) -> Result<(), StoreError> {
        let mut state = self.lock();
        let ids = std::iter::once(&record.id).chain(&record.aliases);
        for id in ids.clone() {
            let claimed = state
                .purchase_id(record.provider, id)
                .and_then(|purchase| state.purchases.get(&(record.provider, purchase)))
                .map(|(claimant, _)| claimant.clone());
            if claimed.is_some_and(|claimant| claimant != owner) {
                return Err(StoreError::ClaimedByAnother);
            }
        }
        let key = (record.provider, record.id.clone());
        if state
            .purchases
            .get(&key)
            .is_some_and(|(_, held)| held.event_created > record.event_created)
        {
            return Ok(());
        }
        // An update that arrived before this purchase, and is newer, wins.
        for id in std::iter::once(record.id.clone()).chain(record.aliases.clone()) {
            if let Some((status, expires, created)) = state.pending.remove(&(record.provider, id))
                && created >= record.event_created
            {
                record.status = status;
                record.expires_at_unix = expires;
                record.event_created = created;
            }
        }
        for alias in &record.aliases {
            state
                .aliases
                .insert((record.provider, alias.clone()), record.id.clone());
        }
        state.purchases.insert(key, (owner.to_string(), record));
        Ok(())
    }

    async fn update(
        &self,
        provider: Provider,
        id: &str,
        status: EntitlementStatus,
        expires_at_unix: Option<i64>,
        event_created: i64,
    ) -> Result<Option<String>, StoreError> {
        let mut state = self.lock();
        let Some(purchase) = state.purchase_id(provider, id) else {
            let pending = state.pending.entry((provider, id.to_string())).or_insert((
                status,
                expires_at_unix,
                event_created,
            ));
            if pending.2 < event_created {
                *pending = (status, expires_at_unix, event_created);
            }
            return Ok(None);
        };
        let Some((owner, held)) = state.purchases.get_mut(&(provider, purchase)) else {
            return Ok(None);
        };
        if held.event_created <= event_created {
            held.status = status;
            held.expires_at_unix = expires_at_unix;
            held.event_created = event_created;
        }
        Ok(Some(owner.clone()))
    }

    async fn owner_of(&self, provider: Provider, id: &str) -> Result<Option<String>, StoreError> {
        let state = self.lock();
        Ok(state
            .purchase_id(provider, id)
            .and_then(|purchase| state.purchases.get(&(provider, purchase)))
            .map(|(owner, _)| owner.clone()))
    }

    async fn owner_of_customer(&self, customer: &str) -> Result<Option<String>, StoreError> {
        Ok(self.lock().customers.get(customer).cloned())
    }

    async fn account_token(&self, owner: &str) -> Result<Option<String>, StoreError> {
        Ok(self.lock().account_tokens.get(owner).cloned())
    }

    async fn snapshot(&self, owner: &str) -> Result<EntitlementSnapshot, StoreError> {
        let state = self.lock();
        let mut snapshot = EntitlementSnapshot::default();
        for (claimant, record) in state.purchases.values() {
            if claimant != owner {
                continue;
            }
            let entitlement = Entitlement {
                product: record.product.clone(),
                provider: record.provider,
                status: record.status,
                provider_purchase_id: record.id.clone(),
                granted_at_unix: record.event_created,
                expires_at_unix: record.expires_at_unix,
            };
            // An active grant of a product outranks a revoked one.
            let keep = snapshot
                .items
                .get(&record.product)
                .is_none_or(|held| held.status != EntitlementStatus::Active);
            if keep {
                snapshot.items.insert(record.product.clone(), entitlement);
            }
        }
        snapshot.revision = snapshot.items.len() as u64;
        Ok(snapshot)
    }

    async fn event_seen(&self, provider: Provider, event_id: &str) -> Result<bool, StoreError> {
        Ok(self
            .lock()
            .events
            .contains(&(provider, event_id.to_string())))
    }

    async fn mark_event(&self, provider: Provider, event_id: &str) -> Result<(), StoreError> {
        self.lock().events.insert((provider, event_id.to_string()));
        Ok(())
    }
}
