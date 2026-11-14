//! Google Play: verifying a purchase token through the Android Publisher API.
//!
//! The server signs in to Google as a service account (an RS256 assertion
//! exchanged for an access token), then reads the one-time product purchase
//! the token names. Only a purchased, not cancelled or pending, purchase of
//! a product in the app's catalog verifies.

use serde::{Deserialize, Serialize};

use super::{VerifiedPurchase, VerifyError, env_value, http_client, jwt, now_unix};
use crate::{
    catalog::{Catalog, PurchaseKind},
    entitlements::{Provider, PurchaseProof},
};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const PUBLISHER_SCOPE: &str = "https://www.googleapis.com/auth/androidpublisher";
const PUBLISHER_URL: &str =
    "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/";

/// Longest purchase token accepted. Google's are a few hundred characters.
const MAX_TOKEN_LEN: usize = 8192;

/// A Google Cloud service account with access to the app in Play Console.
#[derive(Clone)]
pub struct PlayConfig {
    pub service_account_email: String,
    /// The service account's PKCS#8 PEM private key.
    pub private_key_pem: String,
    /// The app's package name, such as `com.g3tech.swiftcircuits`.
    pub package_name: String,
}

impl std::fmt::Debug for PlayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlayConfig")
            .field("service_account_email", &self.service_account_email)
            .field("private_key_pem", &"[redacted]")
            .field("package_name", &self.package_name)
            .finish()
    }
}

impl PlayConfig {
    /// From `GOOGLE_PLAY_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_PLAY_PRIVATE_KEY` and
    /// `ANDROID_PACKAGE_NAME`, the names Swift Circuits already deploys with.
    pub fn from_env() -> Result<Self, VerifyError> {
        Ok(Self {
            service_account_email: env_value("GOOGLE_PLAY_SERVICE_ACCOUNT_EMAIL")?,
            private_key_pem: env_value("GOOGLE_PLAY_PRIVATE_KEY")?,
            package_name: env_value("ANDROID_PACKAGE_NAME")?,
        })
    }
}

/// Verifies Play purchases for one app.
#[derive(Clone, Debug)]
pub struct PlayClient {
    config: PlayConfig,
}

impl PlayClient {
    pub fn new(config: PlayConfig) -> Self {
        Self { config }
    }

    /// The purchase `proof` names, once Google confirms it is a current
    /// purchase of that product. Writes nothing.
    pub async fn verify(
        &self,
        catalog: &Catalog,
        proof: &PurchaseProof,
    ) -> Result<VerifiedPurchase, VerifyError> {
        checked_proof(proof)?;
        let product = catalog
            .get(&proof.product)
            .ok_or(VerifyError::UnknownProduct)?;
        let product_id = product
            .play_id
            .as_deref()
            .ok_or(VerifyError::UnknownProduct)?;
        if product.kind != PurchaseKind::OneTime {
            // Subscriptions are read from purchases.subscriptionsv2, which
            // no app sells through Play yet.
            return Err(VerifyError::Unsupported);
        }

        let client = http_client()?;
        let access_token = self.access_token(&client).await?;
        let response = client
            .get(purchase_url(
                &self.config.package_name,
                product_id,
                &proof.token,
            )?)
            .bearer_auth(access_token)
            .send()
            .await?;
        match response.status() {
            status if status.is_success() => {}
            // Google answers 400 for a token it never issued, 404 for an
            // unknown purchase or product, 410 for one gone for good.
            reqwest::StatusCode::BAD_REQUEST
            | reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::GONE => return Err(VerifyError::NotFound),
            status => return Err(VerifyError::Unavailable(format!("Play answered {status}"))),
        }
        let purchase: ProductPurchase = response.json().await?;
        verified_purchase(purchase, proof)
    }

    async fn access_token(&self, client: &reqwest::Client) -> Result<String, VerifyError> {
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: &'static str,
            aud: &'static str,
            iat: i64,
            exp: i64,
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        let now = now_unix();
        let assertion = jwt::rs256(
            &Claims {
                iss: &self.config.service_account_email,
                scope: PUBLISHER_SCOPE,
                aud: TOKEN_URL,
                iat: now,
                exp: now + 3600,
            },
            &self.config.private_key_pem,
        )?;
        let response = client
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            // A refused assertion is a credentials problem, not a purchase one.
            return Err(VerifyError::Configuration(format!(
                "Google refused the service account ({})",
                response.status()
            )));
        }
        Ok(response.json::<TokenResponse>().await?.access_token)
    }
}

/// The fields of Google's `ProductPurchase` this check reads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductPurchase {
    /// 0 purchased, 1 cancelled, 2 pending.
    purchase_state: Option<i32>,
    order_id: Option<String>,
    obfuscated_external_account_id: Option<String>,
}

/// A Play proof carries the purchase token twice: as the token, and as the
/// transaction id the client keys its checkpoint on.
fn checked_proof(proof: &PurchaseProof) -> Result<(), VerifyError> {
    if proof.provider != Provider::PlayStore
        || proof.token.is_empty()
        || proof.token.len() > MAX_TOKEN_LEN
        || proof.transaction_id != proof.token
    {
        return Err(VerifyError::InvalidProof);
    }
    Ok(())
}

/// `.../applications/{package}/purchases/products/{product}/tokens/{token}`,
/// each part escaped as one path segment.
fn purchase_url(package: &str, product_id: &str, token: &str) -> Result<reqwest::Url, VerifyError> {
    let mut url = reqwest::Url::parse(PUBLISHER_URL)
        .map_err(|_| VerifyError::Configuration("invalid Play endpoint".into()))?;
    url.path_segments_mut()
        .map_err(|_| VerifyError::Configuration("invalid Play endpoint".into()))?
        .pop_if_empty()
        .extend([
            package,
            "purchases",
            "products",
            product_id,
            "tokens",
            token,
        ]);
    Ok(url)
}

fn verified_purchase(
    purchase: ProductPurchase,
    proof: &PurchaseProof,
) -> Result<VerifiedPurchase, VerifyError> {
    // A missing state is not taken as purchased.
    if purchase.purchase_state != Some(0) {
        return Err(VerifyError::Rejected);
    }
    Ok(VerifiedPurchase {
        provider: Provider::PlayStore,
        product: proof.product.clone(),
        id: proof.token.clone(),
        aliases: purchase
            .order_id
            .filter(|order| !order.is_empty())
            .into_iter()
            .collect(),
        account_token: purchase
            .obfuscated_external_account_id
            .filter(|token| !token.is_empty()),
        expires_at_unix: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{catalog::CatalogProduct, entitlements::ProductKey};

    fn proof(token: &str) -> PurchaseProof {
        PurchaseProof {
            provider: Provider::PlayStore,
            product: ProductKey::from("full_game"),
            token: token.into(),
            transaction_id: token.into(),
        }
    }

    fn client() -> PlayClient {
        PlayClient::new(PlayConfig {
            service_account_email: "verifier@example.iam.gserviceaccount.com".into(),
            private_key_pem: jwt::testing::RSA_KEY_PEM.into(),
            package_name: "com.example.game".into(),
        })
    }

    #[test]
    fn a_proof_must_be_a_play_token_matching_its_transaction_id() {
        assert!(checked_proof(&proof("token-1")).is_ok());
        let mut other_store = proof("token-1");
        other_store.provider = Provider::AppStore;
        let mut mismatched = proof("token-1");
        mismatched.transaction_id = "token-2".into();
        for bad in [
            proof(""),
            proof(&"x".repeat(MAX_TOKEN_LEN + 1)),
            other_store,
            mismatched,
        ] {
            assert_eq!(checked_proof(&bad), Err(VerifyError::InvalidProof));
        }
    }

    #[test]
    fn every_part_of_the_purchase_url_is_one_escaped_segment() {
        let url = purchase_url("com.example.game", "full_game", "a/b?c#d").unwrap();
        assert_eq!(
            url.as_str(),
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/com.example.game/purchases/products/full_game/tokens/a%2Fb%3Fc%23d"
        );
    }

    #[test]
    fn only_a_purchased_state_verifies() {
        let purchased = ProductPurchase {
            purchase_state: Some(0),
            order_id: Some("GPA.1234".into()),
            obfuscated_external_account_id: Some("0b5f6c1e-7d2a-4a7e-9b1c-3f8e2d4a6b10".into()),
        };
        let verified = verified_purchase(purchased, &proof("token-1")).unwrap();
        assert_eq!(verified.provider, Provider::PlayStore);
        assert_eq!(verified.id, "token-1");
        assert_eq!(verified.aliases, vec!["GPA.1234".to_string()]);
        assert_eq!(
            verified.account_token.as_deref(),
            Some("0b5f6c1e-7d2a-4a7e-9b1c-3f8e2d4a6b10")
        );
        assert_eq!(verified.expires_at_unix, None);

        for state in [None, Some(1), Some(2)] {
            let purchase = ProductPurchase {
                purchase_state: state,
                ..Default::default()
            };
            assert_eq!(
                verified_purchase(purchase, &proof("token-1")),
                Err(VerifyError::Rejected),
                "{state:?}"
            );
        }
    }

    #[test]
    fn empty_order_and_account_ids_are_dropped() {
        let purchase = ProductPurchase {
            purchase_state: Some(0),
            order_id: Some(String::new()),
            obfuscated_external_account_id: Some(String::new()),
        };
        let verified = verified_purchase(purchase, &proof("token-1")).unwrap();
        assert!(verified.aliases.is_empty());
        assert!(verified.account_token.is_none());
    }

    #[tokio::test]
    async fn products_outside_the_catalog_or_play_are_refused_before_any_request() {
        let catalog = Catalog::new(vec![
            CatalogProduct::new("web_only", PurchaseKind::OneTime).stripe_price("price_1"),
            CatalogProduct::new("membership", PurchaseKind::Subscription).play_id("membership"),
        ])
        .unwrap();
        let mut unknown = proof("token-1");
        unknown.product = ProductKey::from("full_game");
        assert_eq!(
            client().verify(&catalog, &unknown).await,
            Err(VerifyError::UnknownProduct)
        );
        let mut web_only = proof("token-1");
        web_only.product = ProductKey::from("web_only");
        assert_eq!(
            client().verify(&catalog, &web_only).await,
            Err(VerifyError::UnknownProduct)
        );
        let mut membership = proof("token-1");
        membership.product = ProductKey::from("membership");
        assert_eq!(
            client().verify(&catalog, &membership).await,
            Err(VerifyError::Unsupported)
        );
    }

    #[test]
    fn the_private_key_never_reaches_debug_output() {
        let debug = format!("{:?}", client());
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("PRIVATE KEY"));
    }
}
