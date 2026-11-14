//! License keys: issuing a key for a paid checkout, activating it on a
//! limited number of machines, and signing the license file the app checks
//! offline.
//!
//! A key is the buyer's identity on the license server: the checkout is
//! made for the key (`client_reference_id`), so the [`Store`] holds the
//! purchase under the key, and a refund revokes it like any other purchase.
//! Activations are kept per key in [`Activations`].

use std::{collections::BTreeMap, future::Future, sync::Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{
    now_unix,
    service::PaymentsService,
    store::{Store, StoreError},
};
use crate::{
    entitlements::{EntitlementStatus, ProductKey},
    license::{
        client::wire,
        file::{CLAIMS_VERSION, LicenseClaims, key_id, normalize_key},
    },
};

/// Signs license files with an app's Ed25519 key.
pub struct LicenseSigner {
    pair: Ed25519KeyPair,
    public: String,
}

impl std::fmt::Debug for LicenseSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseSigner")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl LicenseSigner {
    /// From the 32-byte seed, base64 (what [`generate_seed`] prints).
    pub fn from_seed(seed: &str) -> Result<Self, String> {
        let bytes = STANDARD
            .decode(seed.trim())
            .map_err(|_| "the license signing key is not base64".to_string())?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&bytes)
            .map_err(|_| "the license signing key must be 32 bytes".to_string())?;
        let public = STANDARD.encode(pair.public_key().as_ref());
        Ok(Self { pair, public })
    }

    /// The public key an app ships, base64.
    pub fn public_key(&self) -> &str {
        &self.public
    }

    /// The license file for `claims`.
    pub fn sign(&self, claims: &LicenseClaims) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = claims.payload();
        let signature = self.pair.sign(payload.as_bytes());
        format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}

/// A new random signing seed, base64.
pub fn generate_seed() -> String {
    STANDARD.encode(random_bytes::<32>())
}

/// A new license key: the app's prefix and 100 random bits in four groups of
/// five Crockford base32 characters, such as `TALLY-8F3KQ-2M9XA-...`.
pub fn generate_key(prefix: &str) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes = random_bytes::<20>();
    let chars: Vec<char> = bytes
        .iter()
        .map(|byte| ALPHABET[(*byte & 31) as usize] as char)
        .collect();
    let groups: Vec<String> = chars
        .chunks(5)
        .take(4)
        .map(|g| g.iter().collect())
        .collect();
    format!("{}-{}", normalize_key(prefix), groups.join("-"))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness");
    bytes
}

/// One machine a key is active on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub machine: String,
    pub name: String,
    pub activated_at: i64,
}

/// What [`Activations::add`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// Newly added, or already there.
    Active,
    /// The key is active on `limit` other machines.
    Full,
}

/// Where a license server keeps activations, by [`key_id`].
pub trait Activations: Send + Sync {
    fn activations(
        &self,
        key_id: &str,
    ) -> impl Future<Output = Result<Vec<Activation>, StoreError>> + Send;

    /// Adds `activation` unless the key is on `limit` other machines. Adding
    /// a machine that is already there succeeds and changes nothing.
    fn add(
        &self,
        key_id: &str,
        activation: Activation,
        limit: u32,
    ) -> impl Future<Output = Result<Added, StoreError>> + Send;

    fn remove(
        &self,
        key_id: &str,
        machine: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Activations in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryActivations {
    keys: Mutex<BTreeMap<String, Vec<Activation>>>,
}

impl Activations for MemoryActivations {
    async fn activations(&self, key_id: &str) -> Result<Vec<Activation>, StoreError> {
        Ok(self
            .keys
            .lock()
            .expect("activations lock")
            .get(key_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn add(
        &self,
        key_id: &str,
        activation: Activation,
        limit: u32,
    ) -> Result<Added, StoreError> {
        let mut keys = self.keys.lock().expect("activations lock");
        let machines = keys.entry(key_id.to_string()).or_default();
        if machines
            .iter()
            .any(|held| held.machine == activation.machine)
        {
            return Ok(Added::Active);
        }
        if machines.len() >= limit as usize {
            return Ok(Added::Full);
        }
        machines.push(activation);
        Ok(Added::Active)
    }

    async fn remove(&self, key_id: &str, machine: &str) -> Result<(), StoreError> {
        if let Some(machines) = self.keys.lock().expect("activations lock").get_mut(key_id) {
            machines.retain(|held| held.machine != machine);
        }
        Ok(())
    }
}

/// Why a license request was refused. Each maps to a [`wire`] error code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No paid purchase for this key (yet).
    UnknownKey,
    Revoked,
    MachineLimit(u32),
    BadRequest,
    Unavailable(String),
}

impl Refusal {
    /// The HTTP status and JSON body to answer with.
    pub fn answer(&self) -> (u16, wire::ErrorResponse) {
        let (status, error, limit) = match self {
            Self::UnknownKey => (404, wire::UNKNOWN_KEY, None),
            Self::Revoked => (403, wire::REVOKED, None),
            Self::MachineLimit(limit) => (409, wire::MACHINE_LIMIT, Some(*limit)),
            Self::BadRequest => (400, wire::BAD_REQUEST, None),
            Self::Unavailable(_) => (503, "unavailable", None),
        };
        (
            status,
            wire::ErrorResponse {
                error: error.into(),
                limit,
            },
        )
    }
}

impl From<StoreError> for Refusal {
    fn from(error: StoreError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

/// One app on a license server.
pub struct LicenseApp<S, A> {
    /// The app's id in URLs and license files, such as `tally`.
    pub id: String,
    /// Its name on the buy and thanks pages.
    pub name: String,
    /// The one product a key buys.
    pub product: ProductKey,
    /// How many machines one key may be active on.
    pub machine_limit: u32,
    pub signer: LicenseSigner,
    pub service: PaymentsService<S>,
    pub activations: A,
}

impl<S: Store, A: Activations> LicenseApp<S, A> {
    /// Whether the key's purchase stands: `Ok(true)` paid, `Ok(false)`
    /// revoked, `UnknownKey` with no purchase.
    async fn paid(&self, key: &str) -> Result<bool, Refusal> {
        let snapshot = self.service.store().snapshot(key).await?;
        match snapshot.items.get(&self.product) {
            Some(item) if item.status == EntitlementStatus::Active => Ok(true),
            Some(_) => Ok(false),
            None => Err(Refusal::UnknownKey),
        }
    }

    /// Activates a key on a machine and signs its license file.
    pub async fn activate(&self, request: &wire::ActivateRequest) -> Result<String, Refusal> {
        let key = normalize_key(&request.key);
        let machine = request.machine.trim();
        if key.is_empty() || machine.is_empty() || machine.len() > 128 {
            return Err(Refusal::BadRequest);
        }
        if !self.paid(&key).await? {
            return Err(Refusal::Revoked);
        }
        let id = key_id(&key);
        let activation = Activation {
            machine: machine.to_string(),
            name: request.machine_name.chars().take(100).collect(),
            activated_at: now_unix(),
        };
        if self
            .activations
            .add(&id, activation, self.machine_limit)
            .await?
            == Added::Full
        {
            return Err(Refusal::MachineLimit(self.machine_limit));
        }
        Ok(self.signer.sign(&LicenseClaims {
            v: CLAIMS_VERSION,
            app: self.id.clone(),
            product: self.product.clone(),
            key_id: id,
            machine: machine.to_string(),
            issued_at: now_unix(),
        }))
    }

    /// `active` while the purchase stands and the machine is activated;
    /// `revoked` after a refund or once the machine was deactivated.
    pub async fn check(&self, request: &wire::MachineRequest) -> Result<&'static str, Refusal> {
        let key = normalize_key(&request.key);
        if !self.paid(&key).await? {
            return Ok("revoked");
        }
        let machines = self.activations.activations(&key_id(&key)).await?;
        Ok(
            if machines.iter().any(|held| held.machine == request.machine) {
                "active"
            } else {
                "revoked"
            },
        )
    }

    /// Frees a machine's activation.
    pub async fn deactivate(&self, request: &wire::MachineRequest) -> Result<(), Refusal> {
        let key = normalize_key(&request.key);
        self.paid(&key).await?;
        self.activations
            .remove(&key_id(&key), &request.machine)
            .await?;
        Ok(())
    }
}

/// The license routes for several apps, to mount under `/api/v1`:
/// `POST /apps/{app}/licenses/{activate,check,deactivate}`.
pub fn routes<S: Store + 'static, A: Activations + 'static>(
    apps: std::sync::Arc<BTreeMap<String, LicenseApp<S, A>>>,
) -> axum::Router {
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
    };
    type Apps<S, A> = std::sync::Arc<BTreeMap<String, LicenseApp<S, A>>>;

    fn refused(refusal: Refusal) -> Response {
        let (status, body) = refusal.answer();
        (
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(body),
        )
            .into_response()
    }

    async fn activate<S: Store + 'static, A: Activations + 'static>(
        State(apps): State<Apps<S, A>>,
        Path(app): Path<String>,
        Json(request): Json<wire::ActivateRequest>,
    ) -> Response {
        let Some(app) = apps.get(&app) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match app.activate(&request).await {
            Ok(license) => Json(wire::ActivateResponse { license }).into_response(),
            Err(refusal) => refused(refusal),
        }
    }

    async fn check<S: Store + 'static, A: Activations + 'static>(
        State(apps): State<Apps<S, A>>,
        Path(app): Path<String>,
        Json(request): Json<wire::MachineRequest>,
    ) -> Response {
        let Some(app) = apps.get(&app) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match app.check(&request).await {
            Ok(status) => Json(wire::CheckResponse {
                status: status.into(),
            })
            .into_response(),
            Err(refusal) => refused(refusal),
        }
    }

    async fn deactivate<S: Store + 'static, A: Activations + 'static>(
        State(apps): State<Apps<S, A>>,
        Path(app): Path<String>,
        Json(request): Json<wire::MachineRequest>,
    ) -> Response {
        let Some(app) = apps.get(&app) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match app.deactivate(&request).await {
            Ok(()) => Json(serde_json::json!({})).into_response(),
            Err(refusal) => refused(refusal),
        }
    }

    Router::new()
        .route("/apps/{app}/licenses/activate", post(activate::<S, A>))
        .route("/apps/{app}/licenses/check", post(check::<S, A>))
        .route("/apps/{app}/licenses/deactivate", post(deactivate::<S, A>))
        .with_state(apps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        catalog::{Catalog, CatalogProduct, PurchaseKind},
        entitlements::Provider,
        server::store::{MemoryStore, PurchaseRecord},
    };

    fn app(limit: u32) -> LicenseApp<MemoryStore, MemoryActivations> {
        let catalog = Catalog::new(vec![
            CatalogProduct::new("tally_full", PurchaseKind::OneTime).stripe_price("price_tally"),
        ])
        .unwrap();
        LicenseApp {
            id: "tally".into(),
            name: "Tally".into(),
            product: ProductKey::new("tally_full"),
            machine_limit: limit,
            signer: LicenseSigner::from_seed(&STANDARD.encode([7u8; 32])).unwrap(),
            service: PaymentsService::new(catalog, MemoryStore::default()),
            activations: MemoryActivations::default(),
        }
    }

    async fn pay(app: &LicenseApp<MemoryStore, MemoryActivations>, key: &str) {
        app.service
            .store()
            .record(
                key,
                PurchaseRecord {
                    provider: Provider::Stripe,
                    product: ProductKey::new("tally_full"),
                    id: format!("pi_{key}"),
                    aliases: Vec::new(),
                    status: EntitlementStatus::Active,
                    expires_at_unix: None,
                    event_created: 10,
                },
            )
            .await
            .unwrap();
    }

    fn activation(key: &str, machine: &str) -> wire::ActivateRequest {
        wire::ActivateRequest {
            key: key.into(),
            machine: machine.into(),
            machine_name: "PC".into(),
        }
    }

    fn machine(key: &str, machine: &str) -> wire::MachineRequest {
        wire::MachineRequest {
            key: key.into(),
            machine: machine.into(),
        }
    }

    #[test]
    fn keys_carry_the_prefix_and_never_repeat() {
        let key = generate_key("tally");
        assert!(key.starts_with("TALLY-"));
        assert_eq!(key.len(), "TALLY-".len() + 4 * 5 + 3);
        assert_ne!(key, generate_key("tally"));
        assert_eq!(normalize_key(&key), key);
    }

    #[tokio::test]
    async fn a_paid_key_activates_and_its_license_verifies_offline() {
        let app = app(2);
        let key = generate_key("tally");
        assert_eq!(
            app.activate(&activation(&key, "m1")).await,
            Err(Refusal::UnknownKey)
        );
        pay(&app, &key).await;

        let file = app
            .activate(&activation(&key.to_lowercase(), "m1"))
            .await
            .unwrap();
        let claims = LicenseClaims::verify(&file, app.signer.public_key(), "tally", "m1").unwrap();
        assert_eq!(claims.key_id, key_id(&key));
        assert_eq!(claims.product, ProductKey::new("tally_full"));
        assert_eq!(app.check(&machine(&key, "m1")).await, Ok("active"));
    }

    #[tokio::test]
    async fn a_key_stops_at_its_machine_limit_until_one_is_deactivated() {
        let app = app(2);
        let key = generate_key("tally");
        pay(&app, &key).await;
        app.activate(&activation(&key, "m1")).await.unwrap();
        app.activate(&activation(&key, "m2")).await.unwrap();
        // The same machine again is not a new activation.
        app.activate(&activation(&key, "m1")).await.unwrap();
        assert_eq!(
            app.activate(&activation(&key, "m3")).await,
            Err(Refusal::MachineLimit(2))
        );

        app.deactivate(&machine(&key, "m2")).await.unwrap();
        assert_eq!(app.check(&machine(&key, "m2")).await, Ok("revoked"));
        app.activate(&activation(&key, "m3")).await.unwrap();
    }

    #[tokio::test]
    async fn a_refund_revokes_the_key_everywhere() {
        let app = app(3);
        let key = generate_key("tally");
        pay(&app, &key).await;
        app.activate(&activation(&key, "m1")).await.unwrap();
        app.service
            .store()
            .update(
                Provider::Stripe,
                &format!("pi_{key}"),
                EntitlementStatus::Revoked,
                None,
                20,
            )
            .await
            .unwrap();
        assert_eq!(app.check(&machine(&key, "m1")).await, Ok("revoked"));
        assert_eq!(
            app.activate(&activation(&key, "m2")).await,
            Err(Refusal::Revoked)
        );
    }

    #[test]
    fn refusals_answer_with_their_wire_codes() {
        assert_eq!(Refusal::UnknownKey.answer().0, 404);
        let (status, body) = Refusal::MachineLimit(3).answer();
        assert_eq!(
            (status, body.error.as_str(), body.limit),
            (409, wire::MACHINE_LIMIT, Some(3))
        );
    }
}
