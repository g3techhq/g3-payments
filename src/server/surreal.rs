//! The [`Store`] and license [`Activations`] on SurrealDB, for apps without
//! purchase rules of their own and for `g3-payments-server`.
//!
//! One database can hold several apps: every row carries its app, and a
//! [`SurrealStore`] reads and writes only its own. Owners are plain text
//! (on the license server, the license key). Load [`SCHEMA`] once at
//! startup; every definition is `IF NOT EXISTS`, so loading it again is a
//! no-op.

use surrealdb::{Surreal, engine::any::Any};
use surrealdb_types::SurrealValue;

use super::store::{PurchaseRecord, Store, StoreError};
use crate::entitlements::{
    Entitlement, EntitlementSnapshot, EntitlementStatus, ProductKey, Provider,
};

#[cfg(feature = "license-server")]
use super::license_keys::{Activation, Activations, Added};

/// The tables, for `db.query(SCHEMA)` at startup.
pub const SCHEMA: &str = include_str!("surreal.surql");

/// One app's purchases and activations in a SurrealDB database.
#[derive(Clone)]
pub struct SurrealStore {
    db: Surreal<Any>,
    app: String,
}

impl SurrealStore {
    pub fn new(db: Surreal<Any>, app: impl Into<String>) -> Self {
        Self {
            db,
            app: app.into(),
        }
    }

    /// Loads [`SCHEMA`].
    pub async fn apply_schema(db: &Surreal<Any>) -> Result<(), StoreError> {
        db.query(SCHEMA)
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
        Ok(())
    }
}

fn unavailable(error: surrealdb::Error) -> StoreError {
    let message = error.to_string();
    if message.contains("Purchase is already linked to another account") {
        StoreError::ClaimedByAnother
    } else {
        StoreError::Unavailable(message)
    }
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Stripe => "stripe",
        Provider::AppStore => "app_store",
        Provider::PlayStore => "play_store",
        Provider::Developer => "developer",
        Provider::LicenseKey => "license_key",
        Provider::Unknown => "unknown",
    }
}

fn provider_from(name: &str) -> Provider {
    match name {
        "stripe" => Provider::Stripe,
        "app_store" => Provider::AppStore,
        "play_store" => Provider::PlayStore,
        "developer" => Provider::Developer,
        "license_key" => Provider::LicenseKey,
        _ => Provider::Unknown,
    }
}

fn status_name(status: EntitlementStatus) -> &'static str {
    if status == EntitlementStatus::Active {
        "active"
    } else {
        "revoked"
    }
}

/// Claims every reference for the owner and keeps the newest event. A
/// pending update that arrived before the purchase, and is newer, wins.
const RECORD: &str = r#"
    BEGIN TRANSACTION;
    IF count(SELECT id FROM pay_purchase WHERE app = $app AND provider = $provider
        AND owner != $owner AND array::len(array::intersect(refs, $refs)) > 0) > 0 {
        THROW "Purchase is already linked to another account";
    };
    LET $pending = SELECT status, expires_at, event_created FROM pay_pending
        WHERE app = $app AND provider = $provider AND purchase_id IN $refs AND event_created >= $created
        ORDER BY event_created DESC LIMIT 1;
    LET $status = IF count($pending) > 0 { array::first($pending).status } ELSE { $status };
    LET $expires = IF count($pending) > 0 { array::first($pending).expires_at } ELSE { $expires };
    LET $created = IF count($pending) > 0 { array::first($pending).event_created } ELSE { $created };
    DELETE pay_pending WHERE app = $app AND provider = $provider AND purchase_id IN $refs;
    LET $existing = SELECT event_created FROM pay_purchase
        WHERE app = $app AND provider = $provider AND purchase_id = $purchase LIMIT 1;
    IF count($existing) = 0 OR array::first($existing).event_created <= $created {
        UPSERT pay_purchase SET app = $app, provider = $provider, purchase_id = $purchase,
            refs = $refs, owner = $owner, product = $product, status = $status,
            expires_at = $expires, event_created = $created
            WHERE app = $app AND provider = $provider AND purchase_id = $purchase;
    };
    COMMIT TRANSACTION;
"#;

/// Changes a purchase wherever it is, or keeps the change for a purchase not
/// recorded yet. Returns its owner.
const UPDATE: &str = r#"
    BEGIN TRANSACTION;
    LET $held = SELECT id FROM pay_purchase WHERE app = $app AND provider = $provider AND $purchase IN refs;
    IF count($held) = 0 {
        LET $pending = SELECT event_created FROM pay_pending
            WHERE app = $app AND provider = $provider AND purchase_id = $purchase LIMIT 1;
        IF count($pending) = 0 OR array::first($pending).event_created < $created {
            UPSERT pay_pending SET app = $app, provider = $provider, purchase_id = $purchase,
                status = $status, expires_at = $expires, event_created = $created
                WHERE app = $app AND provider = $provider AND purchase_id = $purchase;
        };
    } ELSE {
        UPDATE pay_purchase SET status = $status, expires_at = $expires, event_created = $created
            WHERE app = $app AND provider = $provider AND $purchase IN refs AND event_created <= $created;
    };
    COMMIT TRANSACTION;
    SELECT VALUE owner FROM pay_purchase WHERE app = $app AND provider = $provider AND $purchase IN refs LIMIT 1;
"#;

#[derive(SurrealValue)]
struct Row {
    product: String,
    provider: String,
    purchase_id: String,
    status: String,
    expires_at: Option<i64>,
    event_created: i64,
}

impl Store for SurrealStore {
    async fn record(&self, owner: &str, record: PurchaseRecord) -> Result<(), StoreError> {
        let mut refs = vec![record.id.clone()];
        refs.extend(record.aliases);
        refs.sort();
        refs.dedup();
        self.db
            .query(RECORD)
            .bind(("app", self.app.clone()))
            .bind(("provider", provider_name(record.provider)))
            .bind(("purchase", record.id))
            .bind(("refs", refs))
            .bind(("owner", owner.to_string()))
            .bind(("product", record.product.0))
            .bind(("status", status_name(record.status)))
            .bind(("expires", record.expires_at_unix))
            .bind(("created", record.event_created))
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
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
        let mut response = self
            .db
            .query(UPDATE)
            .bind(("app", self.app.clone()))
            .bind(("provider", provider_name(provider)))
            .bind(("purchase", id.to_string()))
            .bind(("status", status_name(status)))
            .bind(("expires", expires_at_unix))
            .bind(("created", event_created))
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
        let last = response.num_statements() - 1;
        let owners: Vec<String> = response.take(last).map_err(unavailable)?;
        Ok(owners.into_iter().next())
    }

    async fn owner_of(&self, provider: Provider, id: &str) -> Result<Option<String>, StoreError> {
        let mut response = self
            .db
            .query("SELECT VALUE owner FROM pay_purchase WHERE app = $app AND provider = $provider AND $purchase IN refs LIMIT 1;")
            .bind(("app", self.app.clone()))
            .bind(("provider", provider_name(provider)))
            .bind(("purchase", id.to_string()))
            .await
            .map_err(unavailable)?;
        let owners: Vec<String> = response.take(0).map_err(unavailable)?;
        Ok(owners.into_iter().next())
    }

    async fn snapshot(&self, owner: &str) -> Result<EntitlementSnapshot, StoreError> {
        let mut response = self
            .db
            .query("SELECT product, provider, purchase_id, status, expires_at, event_created FROM pay_purchase WHERE app = $app AND owner = $owner;")
            .bind(("app", self.app.clone()))
            .bind(("owner", owner.to_string()))
            .await
            .map_err(unavailable)?;
        let rows: Vec<Row> = response.take(0).map_err(unavailable)?;
        let mut snapshot = EntitlementSnapshot::default();
        for row in rows {
            let product = ProductKey::new(row.product);
            let status = if row.status == "active" {
                EntitlementStatus::Active
            } else {
                EntitlementStatus::Revoked
            };
            // An active grant of a product outranks a revoked one.
            if snapshot
                .items
                .get(&product)
                .is_some_and(|held| held.status == EntitlementStatus::Active)
            {
                continue;
            }
            snapshot.items.insert(
                product.clone(),
                Entitlement {
                    product,
                    provider: provider_from(&row.provider),
                    status,
                    provider_purchase_id: row.purchase_id,
                    granted_at_unix: row.event_created,
                    expires_at_unix: row.expires_at,
                },
            );
        }
        snapshot.revision = snapshot.items.len() as u64;
        Ok(snapshot)
    }

    async fn event_seen(&self, provider: Provider, event_id: &str) -> Result<bool, StoreError> {
        let mut response = self
            .db
            .query("SELECT VALUE event_id FROM pay_event WHERE app = $app AND provider = $provider AND event_id = $event LIMIT 1;")
            .bind(("app", self.app.clone()))
            .bind(("provider", provider_name(provider)))
            .bind(("event", event_id.to_string()))
            .await
            .map_err(unavailable)?;
        let seen: Vec<String> = response.take(0).map_err(unavailable)?;
        Ok(!seen.is_empty())
    }

    async fn mark_event(&self, provider: Provider, event_id: &str) -> Result<(), StoreError> {
        self.db
            .query("UPSERT pay_event SET app = $app, provider = $provider, event_id = $event, handled_at = time::now() WHERE app = $app AND provider = $provider AND event_id = $event;")
            .bind(("app", self.app.clone()))
            .bind(("provider", provider_name(provider)))
            .bind(("event", event_id.to_string()))
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
        Ok(())
    }
}

#[cfg(feature = "license-server")]
#[derive(SurrealValue)]
struct ActivationRow {
    machine: String,
    name: String,
    activated_at: i64,
}

#[cfg(feature = "license-server")]
impl Activations for SurrealStore {
    async fn activations(&self, key_id: &str) -> Result<Vec<Activation>, StoreError> {
        let mut response = self
            .db
            .query("SELECT machine, name, activated_at FROM license_activation WHERE app = $app AND key_id = $key ORDER BY activated_at;")
            .bind(("app", self.app.clone()))
            .bind(("key", key_id.to_string()))
            .await
            .map_err(unavailable)?;
        let rows: Vec<ActivationRow> = response.take(0).map_err(unavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| Activation {
                machine: row.machine,
                name: row.name,
                activated_at: row.activated_at,
            })
            .collect())
    }

    async fn add(
        &self,
        key_id: &str,
        activation: Activation,
        limit: u32,
    ) -> Result<Added, StoreError> {
        let mut response = self
            .db
            .query(
                r#"
                BEGIN TRANSACTION;
                LET $here = SELECT id FROM license_activation WHERE app = $app AND key_id = $key AND machine = $machine;
                LET $count = count(SELECT id FROM license_activation WHERE app = $app AND key_id = $key);
                LET $added = IF count($here) > 0 { true } ELSE IF $count < $limit {
                    CREATE license_activation SET app = $app, key_id = $key, machine = $machine,
                        name = $name, activated_at = $at;
                    true
                } ELSE { false };
                COMMIT TRANSACTION;
                RETURN $added;
                "#,
            )
            .bind(("app", self.app.clone()))
            .bind(("key", key_id.to_string()))
            .bind(("machine", activation.machine))
            .bind(("name", activation.name))
            .bind(("at", activation.activated_at))
            .bind(("limit", i64::from(limit)))
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
        let last = response.num_statements() - 1;
        let added: Option<bool> = response.take(last).map_err(unavailable)?;
        Ok(if added.unwrap_or(false) {
            Added::Active
        } else {
            Added::Full
        })
    }

    async fn remove(&self, key_id: &str, machine: &str) -> Result<(), StoreError> {
        self.db
            .query("DELETE license_activation WHERE app = $app AND key_id = $key AND machine = $machine;")
            .bind(("app", self.app.clone()))
            .bind(("key", key_id.to_string()))
            .bind(("machine", machine.to_string()))
            .await
            .map_err(unavailable)?
            .check()
            .map_err(unavailable)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store(app: &str) -> SurrealStore {
        let db = surrealdb::engine::any::connect("mem://").await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        SurrealStore::apply_schema(&db).await.unwrap();
        SurrealStore::new(db, app)
    }

    fn purchase(id: &str, created: i64) -> PurchaseRecord {
        PurchaseRecord {
            provider: Provider::Stripe,
            product: ProductKey::new("full"),
            id: id.into(),
            aliases: vec![format!("{id}_alias")],
            status: EntitlementStatus::Active,
            expires_at_unix: None,
            event_created: created,
        }
    }

    #[tokio::test]
    async fn a_purchase_is_owned_once_and_kept_per_app() {
        let store = store("tally").await;
        store.record("KEY-1", purchase("pi_1", 10)).await.unwrap();
        assert!(store.snapshot("KEY-1").await.unwrap().owns("full"));
        assert_eq!(
            store
                .owner_of(Provider::Stripe, "pi_1_alias")
                .await
                .unwrap()
                .as_deref(),
            Some("KEY-1")
        );
        assert_eq!(
            store.record("KEY-2", purchase("pi_1", 11)).await,
            Err(StoreError::ClaimedByAnother)
        );

        let other = SurrealStore::new(store.db.clone(), "skicut");
        assert!(other.snapshot("KEY-1").await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn a_refund_before_its_checkout_still_revokes() {
        let store = store("tally").await;
        assert_eq!(
            store
                .update(
                    Provider::Stripe,
                    "pi_1",
                    EntitlementStatus::Revoked,
                    None,
                    20
                )
                .await
                .unwrap(),
            None
        );
        store.record("KEY-1", purchase("pi_1", 10)).await.unwrap();
        assert!(!store.snapshot("KEY-1").await.unwrap().owns("full"));

        // And a late, older grant does not undo a newer refund.
        let store = self::tests::store("tally").await;
        store.record("KEY-1", purchase("pi_2", 10)).await.unwrap();
        assert_eq!(
            store
                .update(
                    Provider::Stripe,
                    "pi_2",
                    EntitlementStatus::Revoked,
                    None,
                    20
                )
                .await
                .unwrap()
                .as_deref(),
            Some("KEY-1")
        );
        store.record("KEY-1", purchase("pi_2", 15)).await.unwrap();
        assert!(!store.snapshot("KEY-1").await.unwrap().owns("full"));
    }

    #[tokio::test]
    async fn events_are_handled_once() {
        let store = store("tally").await;
        assert!(!store.event_seen(Provider::Stripe, "evt_1").await.unwrap());
        store.mark_event(Provider::Stripe, "evt_1").await.unwrap();
        store.mark_event(Provider::Stripe, "evt_1").await.unwrap();
        assert!(store.event_seen(Provider::Stripe, "evt_1").await.unwrap());
        let other = SurrealStore::new(store.db.clone(), "skicut");
        assert!(!other.event_seen(Provider::Stripe, "evt_1").await.unwrap());
    }

    #[cfg(feature = "license-server")]
    #[tokio::test]
    async fn activations_stop_at_the_limit() {
        let store = store("tally").await;
        let machine = |id: &str| Activation {
            machine: id.into(),
            name: "PC".into(),
            activated_at: 1,
        };
        assert_eq!(
            store.add("k", machine("m1"), 2).await.unwrap(),
            Added::Active
        );
        assert_eq!(
            store.add("k", machine("m1"), 2).await.unwrap(),
            Added::Active
        );
        assert_eq!(
            store.add("k", machine("m2"), 2).await.unwrap(),
            Added::Active
        );
        assert_eq!(store.add("k", machine("m3"), 2).await.unwrap(), Added::Full);
        store.remove("k", "m1").await.unwrap();
        assert_eq!(
            store.add("k", machine("m3"), 2).await.unwrap(),
            Added::Active
        );
        let held: Vec<String> = store
            .activations("k")
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.machine)
            .collect();
        assert_eq!(held, ["m2", "m3"]);
    }
}
