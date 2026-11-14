//! Who owns what: products, providers, entitlements and snapshots.
//!
//! Provider receipts are proofs. The server verifies those proofs and emits
//! this provider-neutral snapshot; clients never grant an entitlement merely
//! because a store SDK reported a successful purchase.
//!
//! Moved here from Swift Circuits' `g3-entitlements` crate. Phones store and
//! cache these snapshots, so the JSON stays readable both ways: by released
//! apps that know only the original fields and variants, and by this crate
//! when a newer server sends a provider or status it does not know yet.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProductKey(pub String);

impl ProductKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl From<&str> for ProductKey {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Stripe,
    AppStore,
    PlayStore,
    Developer,
    /// A signed license file, for an app sold outside an app store.
    LicenseKey,
    /// A provider added after this version. Its grants still count: the
    /// server that sent them verified them.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementStatus {
    Active,
    Revoked,
    /// A status added after this version. Never owned.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlement {
    pub product: ProductKey,
    pub provider: Provider,
    pub status: EntitlementStatus,
    /// Private backend reference. The wire field remains an empty string for
    /// older clients; incoming cached references are discarded as well.
    #[serde(default, with = "private_purchase_reference")]
    pub provider_purchase_id: String,
    pub granted_at_unix: i64,
    /// When a subscription's paid period ends. `None` for a permanent
    /// purchase, and then left out of the JSON so the shape stays the one
    /// released apps read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

impl Entitlement {
    /// Whether this grants its product at `now_unix`: active, and either
    /// permanent or not yet expired.
    pub fn is_active_at(&self, now_unix: i64) -> bool {
        self.status == EntitlementStatus::Active
            && self
                .expires_at_unix
                .is_none_or(|expires| now_unix < expires)
    }
}

mod private_purchase_reference {
    use serde::{Deserialize, Deserializer, Serializer, de::IgnoredAny};

    pub fn serialize<S: Serializer>(_: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("")
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        IgnoredAny::deserialize(deserializer)?;
        Ok(String::new())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    pub revision: u64,
    pub items: BTreeMap<ProductKey, Entitlement>,
}

impl EntitlementSnapshot {
    /// Whether the product is active, ignoring any expiry. Right for
    /// permanent purchases; use [`owns_at`](Self::owns_at) wherever a
    /// subscription can be involved.
    pub fn owns(&self, product: impl Into<ProductKey>) -> bool {
        self.items
            .get(&product.into())
            .is_some_and(|item| item.status == EntitlementStatus::Active)
    }

    /// Whether the product is active and, for a subscription, not expired at
    /// `now_unix`.
    pub fn owns_at(&self, product: impl Into<ProductKey>, now_unix: i64) -> bool {
        self.items
            .get(&product.into())
            .is_some_and(|item| item.is_active_at(now_unix))
    }

    pub fn active_products(&self) -> impl Iterator<Item = &ProductKey> {
        self.items
            .values()
            .filter(|item| item.status == EntitlementStatus::Active)
            .map(|item| &item.product)
    }

    /// Record the active entitlements of a provider-verified snapshot, such as
    /// the one a server returns for a store purchase on this device. Only grants
    /// are taken: a device record is additive, and an incoming revocation does
    /// not remove another verified grant of the same product. Purchase
    /// references are dropped. Returns whether
    /// anything changed, bumping `revision` when it did.
    pub fn record_active(&mut self, verified: &EntitlementSnapshot) -> bool {
        let mut changed = false;
        for item in verified
            .items
            .values()
            .filter(|item| item.status == EntitlementStatus::Active)
        {
            if self.owns(item.product.clone()) {
                continue;
            }
            // A device record keeps the unlock, never the purchase reference.
            let mut item = item.clone();
            item.provider_purchase_id.clear();
            self.items.insert(item.product.clone(), item);
            changed = true;
        }
        if changed {
            self.revision = self.revision.wrapping_add(1);
        }
        changed
    }

    /// What this player may use: everything active in either snapshot. An
    /// account's verified grants and a device's store purchases are separate
    /// sources, and neither can revoke what the other grants.
    pub fn union(&self, other: &EntitlementSnapshot) -> EntitlementSnapshot {
        let mut merged = self.clone();
        for (product, item) in &other.items {
            match merged.items.get(product) {
                Some(existing) if existing.status == EntitlementStatus::Active => {}
                Some(_) if item.status != EntitlementStatus::Active => {}
                _ => {
                    merged.items.insert(product.clone(), item.clone());
                }
            }
        }
        merged.revision = self.revision.max(other.revision);
        merged
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseProof {
    pub provider: Provider,
    pub product: ProductKey,
    /// App Store signed transaction JWS or Google Play purchase token.
    pub token: String,
    pub transaction_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_items_are_not_owned() {
        let product = ProductKey::from("full_game");
        let mut snapshot = EntitlementSnapshot::default();
        snapshot.items.insert(
            product.clone(),
            Entitlement {
                product: product.clone(),
                provider: Provider::Stripe,
                status: EntitlementStatus::Revoked,
                provider_purchase_id: "pi_123".into(),
                granted_at_unix: 1,
                expires_at_unix: None,
            },
        );
        assert!(!snapshot.owns(product));
    }

    fn item(product: &str, provider: Provider, status: EntitlementStatus) -> Entitlement {
        Entitlement {
            product: ProductKey::from(product),
            provider,
            status,
            provider_purchase_id: String::new(),
            granted_at_unix: 10,
            expires_at_unix: None,
        }
    }

    fn snapshot(items: &[Entitlement]) -> EntitlementSnapshot {
        EntitlementSnapshot {
            revision: 0,
            items: items
                .iter()
                .map(|item| (item.product.clone(), item.clone()))
                .collect(),
        }
    }

    #[test]
    fn a_device_record_only_gains_verified_grants() {
        let mut device = EntitlementSnapshot::default();
        let bought = snapshot(&[item(
            "full_game",
            Provider::AppStore,
            EntitlementStatus::Active,
        )]);
        assert!(device.record_active(&bought));
        assert!(device.owns("full_game"));
        assert_eq!(device.revision, 1);

        // Restoring the same purchase again changes nothing and keeps the revision.
        assert!(!device.record_active(&bought));
        assert_eq!(device.revision, 1);

        // A revoked result never becomes a grant, and never removes one.
        let refunded = snapshot(&[
            item("full_game", Provider::AppStore, EntitlementStatus::Revoked),
            item(
                "theme.space",
                Provider::AppStore,
                EntitlementStatus::Revoked,
            ),
        ]);
        assert!(!device.record_active(&refunded));
        assert!(device.owns("full_game"));
        assert!(!device.owns("theme.space"));
        assert!(!device.items.contains_key(&ProductKey::from("theme.space")));
    }

    #[test]
    fn a_device_record_does_not_keep_purchase_identifiers() {
        let mut device = EntitlementSnapshot::default();
        let mut bought = item("full_game", Provider::PlayStore, EntitlementStatus::Active);
        bought.provider_purchase_id = "synthetic-private-token".into();
        device.record_active(&snapshot(&[bought]));
        assert!(
            device.items[&ProductKey::from("full_game")]
                .provider_purchase_id
                .is_empty()
        );
        let stored = serde_json::to_string(&device).unwrap();
        assert!(!stored.contains("synthetic-private-token"));
        let reloaded: EntitlementSnapshot = serde_json::from_str(&stored).unwrap();
        assert!(reloaded.owns("full_game"));
    }

    #[test]
    fn account_and_device_entitlements_add_up_and_neither_revokes_the_other() {
        let account = snapshot(&[
            item("theme_bundle", Provider::Stripe, EntitlementStatus::Active),
            item("full_game", Provider::Stripe, EntitlementStatus::Revoked),
        ]);
        let device = snapshot(&[
            item("full_game", Provider::AppStore, EntitlementStatus::Active),
            item(
                "theme.space",
                Provider::AppStore,
                EntitlementStatus::Revoked,
            ),
        ]);
        for merged in [account.union(&device), device.union(&account)] {
            assert!(merged.owns("full_game"));
            assert!(merged.owns("theme_bundle"));
            assert!(!merged.owns("theme.space"));
            assert_eq!(merged.active_products().count(), 2);
        }
        assert_eq!(
            account.union(&device).items[&ProductKey::from("full_game")].provider,
            Provider::AppStore
        );
        // Signed out there is no account snapshot: the device record stands alone.
        let alone = EntitlementSnapshot::default().union(&device);
        assert!(alone.owns("full_game"));
        assert!(!alone.owns("theme_bundle"));
    }

    #[test]
    fn snapshots_keep_unlocks_and_legacy_shape_without_shipping_purchase_identifiers() {
        for provider in [
            Provider::Stripe,
            Provider::AppStore,
            Provider::PlayStore,
            Provider::Developer,
            Provider::LicenseKey,
        ] {
            let product = ProductKey::from("full_game");
            let mut snapshot = EntitlementSnapshot {
                revision: 1,
                ..Default::default()
            };
            snapshot.items.insert(
                product.clone(),
                Entitlement {
                    product: product.clone(),
                    provider,
                    status: EntitlementStatus::Active,
                    provider_purchase_id: "synthetic-private-purchase-canary".into(),
                    granted_at_unix: 100,
                    expires_at_unix: None,
                },
            );
            let encoded = serde_json::to_string(&snapshot).unwrap();
            assert!(!encoded.contains("synthetic-private-purchase-canary"));
            let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(value["items"]["full_game"]["provider_purchase_id"], "");
            let decoded: EntitlementSnapshot = serde_json::from_str(&encoded).unwrap();
            assert!(decoded.owns(product.clone()));
            assert_eq!(decoded.items[&product].provider, provider);
            assert_eq!(decoded.items[&product].granted_at_unix, 100);
            assert_eq!(decoded.revision, 1);
        }
    }

    #[test]
    fn old_cached_references_are_discarded_without_changing_revocation_or_native_proofs() {
        let mut stored = serde_json::json!({
            "product":"full_game", "provider":"play_store", "status":"revoked",
            "provider_purchase_id":"old-private-cache-canary", "granted_at_unix":100,
        });
        let entitlement: Entitlement = serde_json::from_value(stored.clone()).unwrap();
        assert!(entitlement.provider_purchase_id.is_empty());
        assert_eq!(entitlement.status, EntitlementStatus::Revoked);
        stored
            .as_object_mut()
            .unwrap()
            .remove("provider_purchase_id");
        let missing: Entitlement = serde_json::from_value(stored).unwrap();
        assert!(missing.provider_purchase_id.is_empty());
        let proof = PurchaseProof {
            provider: Provider::PlayStore,
            product: ProductKey::from("full_game"),
            token: "synthetic-native-proof".into(),
            transaction_id: "synthetic-transaction".into(),
        };
        let encoded = serde_json::to_string(&proof).unwrap();
        let decoded: PurchaseProof = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    /// A Swift Circuits device purchase record as released apps write it
    /// (`swift-circuits-device-purchases-v1`). Both directions must keep
    /// working: this crate reads it, and writes exactly these bytes back.
    const RELEASED_DEVICE_RECORD: &str = r#"{"revision":2,"items":{"full_game":{"product":"full_game","provider":"app_store","status":"active","provider_purchase_id":"","granted_at_unix":1762000000},"theme.space":{"product":"theme.space","provider":"play_store","status":"revoked","provider_purchase_id":"","granted_at_unix":1762000100}}}"#;

    #[test]
    fn the_released_wire_format_reads_and_writes_byte_for_byte() {
        let snapshot: EntitlementSnapshot = serde_json::from_str(RELEASED_DEVICE_RECORD).unwrap();
        assert!(snapshot.owns("full_game"));
        assert!(!snapshot.owns("theme.space"));
        assert_eq!(
            snapshot.items[&ProductKey::from("full_game")].expires_at_unix,
            None
        );
        assert_eq!(
            serde_json::to_string(&snapshot).unwrap(),
            RELEASED_DEVICE_RECORD
        );
    }

    #[test]
    fn a_newer_provider_still_grants_and_a_newer_status_never_does() {
        let snapshot: EntitlementSnapshot = serde_json::from_value(serde_json::json!({
            "revision": 1,
            "items": {
                "full_game": {
                    "product": "full_game", "provider": "microsoft_store", "status": "active",
                    "provider_purchase_id": "", "granted_at_unix": 1,
                },
                "theme_bundle": {
                    "product": "theme_bundle", "provider": "stripe", "status": "paused",
                    "provider_purchase_id": "", "granted_at_unix": 1,
                },
            },
        }))
        .unwrap();
        let full_game = &snapshot.items[&ProductKey::from("full_game")];
        assert_eq!(full_game.provider, Provider::Unknown);
        assert!(snapshot.owns("full_game"));
        let bundle = &snapshot.items[&ProductKey::from("theme_bundle")];
        assert_eq!(bundle.status, EntitlementStatus::Unknown);
        assert!(!snapshot.owns("theme_bundle"));
        assert!(!snapshot.owns_at("theme_bundle", 0));
    }

    #[test]
    fn license_key_is_its_own_wire_name() {
        assert_eq!(
            serde_json::to_value(Provider::LicenseKey).unwrap(),
            "license_key"
        );
    }

    #[test]
    fn a_subscription_is_owned_until_it_expires() {
        let mut membership = item("membership", Provider::Stripe, EntitlementStatus::Active);
        membership.expires_at_unix = Some(1_000);
        let snapshot = snapshot(&[membership]);
        assert!(snapshot.owns_at("membership", 999));
        assert!(!snapshot.owns_at("membership", 1_000));
        // `owns` ignores expiry, which is why subscriptions go through `owns_at`.
        assert!(snapshot.owns("membership"));
        // A permanent purchase never expires.
        let permanent = self::snapshot(&[item(
            "full_game",
            Provider::AppStore,
            EntitlementStatus::Active,
        )]);
        assert!(permanent.owns_at("full_game", i64::MAX));
    }

    #[test]
    fn an_expiry_is_written_only_when_there_is_one() {
        let mut membership = item("membership", Provider::AppStore, EntitlementStatus::Active);
        let permanent = serde_json::to_value(&membership).unwrap();
        assert!(permanent.get("expires_at_unix").is_none());
        membership.expires_at_unix = Some(1_000);
        let subscription = serde_json::to_value(&membership).unwrap();
        assert_eq!(subscription["expires_at_unix"], 1_000);
        let decoded: Entitlement = serde_json::from_value(subscription).unwrap();
        assert_eq!(decoded.expires_at_unix, Some(1_000));
    }
}
