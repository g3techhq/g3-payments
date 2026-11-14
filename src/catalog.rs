//! An app's product list.
//!
//! Each app supplies the data: a product key, whether it is a one-time
//! purchase or a subscription, and where it is sold (its Stripe price and its
//! App Store and Google Play product ids). Everything else in this crate looks
//! products up here, so a store id or price the app does not list is never
//! mapped to a product.
//!
//! Stripe price ids usually come from the server's environment, so a catalog
//! is built at startup rather than written as constants. It also reads from a
//! config file: it deserializes from a list of products and is checked the
//! same way as [`Catalog::new`].

use serde::{Deserialize, Serialize};

use crate::entitlements::ProductKey;

/// How a product is paid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseKind {
    /// Bought once, owned for good.
    OneTime,
    /// Renews until cancelled; owned while its paid period lasts.
    Subscription,
}

/// One product and the places it is sold. A product a storefront does not
/// sell leaves that id out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogProduct {
    pub key: ProductKey,
    pub kind: PurchaseKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stripe_price: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub play_id: Option<String>,
}

impl CatalogProduct {
    pub fn new(key: impl Into<ProductKey>, kind: PurchaseKind) -> Self {
        Self {
            key: key.into(),
            kind,
            stripe_price: None,
            app_store_id: None,
            play_id: None,
        }
    }

    pub fn stripe_price(mut self, price: impl Into<String>) -> Self {
        self.stripe_price = Some(price.into());
        self
    }

    pub fn app_store_id(mut self, id: impl Into<String>) -> Self {
        self.app_store_id = Some(id.into());
        self
    }

    pub fn play_id(mut self, id: impl Into<String>) -> Self {
        self.play_id = Some(id.into());
        self
    }

    /// The same id in both stores, the common case.
    pub fn store_id(self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.app_store_id(id.clone()).play_id(id)
    }
}

/// Why a product list was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// Two products share a key.
    DuplicateKey(ProductKey),
    /// Two products share a Stripe price or store id, so a purchase of it
    /// could not say which product it bought.
    DuplicateProviderId(String),
    /// A key or provider id is empty.
    Empty,
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateKey(key) => write!(f, "product `{}` is listed twice", key.0),
            Self::DuplicateProviderId(id) => {
                write!(f, "`{id}` is the price or store id of two products")
            }
            Self::Empty => f.write_str("a product key or provider id is empty"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// An app's products, checked so every key and provider id names one product.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<CatalogProduct>", into = "Vec<CatalogProduct>")]
pub struct Catalog {
    products: Vec<CatalogProduct>,
}

impl Catalog {
    pub fn new(products: Vec<CatalogProduct>) -> Result<Self, CatalogError> {
        let mut keys = std::collections::BTreeSet::new();
        for product in &products {
            if product.key.0.is_empty() {
                return Err(CatalogError::Empty);
            }
            if !keys.insert(&product.key) {
                return Err(CatalogError::DuplicateKey(product.key.clone()));
            }
        }
        // Each provider's ids are checked on their own: the App Store and
        // Play usually share an id for the same product, which is fine.
        let providers: [fn(&CatalogProduct) -> Option<&String>; 3] = [
            |product| product.stripe_price.as_ref(),
            |product| product.app_store_id.as_ref(),
            |product| product.play_id.as_ref(),
        ];
        for id_of in providers {
            let mut seen = std::collections::BTreeSet::new();
            for id in products.iter().filter_map(id_of) {
                if id.is_empty() {
                    return Err(CatalogError::Empty);
                }
                if !seen.insert(id) {
                    return Err(CatalogError::DuplicateProviderId(id.clone()));
                }
            }
        }
        Ok(Self { products })
    }

    pub fn products(&self) -> &[CatalogProduct] {
        &self.products
    }

    pub fn get(&self, key: &ProductKey) -> Option<&CatalogProduct> {
        self.products.iter().find(|product| &product.key == key)
    }

    pub fn by_stripe_price(&self, price: &str) -> Option<&CatalogProduct> {
        self.find(|product| product.stripe_price.as_deref() == Some(price))
    }

    pub fn by_app_store_id(&self, id: &str) -> Option<&CatalogProduct> {
        self.find(|product| product.app_store_id.as_deref() == Some(id))
    }

    pub fn by_play_id(&self, id: &str) -> Option<&CatalogProduct> {
        self.find(|product| product.play_id.as_deref() == Some(id))
    }

    fn find(&self, matches: impl Fn(&CatalogProduct) -> bool) -> Option<&CatalogProduct> {
        self.products.iter().find(|product| matches(product))
    }
}

impl TryFrom<Vec<CatalogProduct>> for Catalog {
    type Error = CatalogError;

    fn try_from(products: Vec<CatalogProduct>) -> Result<Self, Self::Error> {
        Self::new(products)
    }
}

impl From<Catalog> for Vec<CatalogProduct> {
    fn from(catalog: Catalog) -> Self {
        catalog.products
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swift_circuits() -> Catalog {
        Catalog::new(vec![
            CatalogProduct::new("full_game", PurchaseKind::OneTime)
                .stripe_price("price_full_game")
                .store_id("com.g3tech.swiftcircuits.full_game"),
            CatalogProduct::new("theme_bundle", PurchaseKind::OneTime)
                .stripe_price("price_theme_bundle")
                .store_id("com.g3tech.swiftcircuits.theme_bundle"),
            CatalogProduct::new("theme.space", PurchaseKind::OneTime)
                .store_id("com.g3tech.swiftcircuits.theme_space"),
        ])
        .unwrap()
    }

    #[test]
    fn products_are_found_by_every_id_they_are_sold_under() {
        let catalog = swift_circuits();
        let full_game = ProductKey::from("full_game");
        assert_eq!(catalog.get(&full_game).unwrap().kind, PurchaseKind::OneTime);
        assert_eq!(
            catalog.by_stripe_price("price_full_game").unwrap().key,
            full_game
        );
        assert_eq!(
            catalog
                .by_app_store_id("com.g3tech.swiftcircuits.full_game")
                .unwrap()
                .key,
            full_game
        );
        assert_eq!(
            catalog
                .by_play_id("com.g3tech.swiftcircuits.theme_space")
                .unwrap()
                .key,
            ProductKey::from("theme.space")
        );
    }

    #[test]
    fn ids_the_app_does_not_list_map_to_nothing() {
        let catalog = swift_circuits();
        assert!(
            catalog
                .by_app_store_id("com.g3tech.swiftcircuits.theme_unknown")
                .is_none()
        );
        assert!(catalog.by_stripe_price("price_other_app").is_none());
        // A store-only product has no web price.
        let space = catalog.get(&ProductKey::from("theme.space")).unwrap();
        assert!(space.stripe_price.is_none());
    }

    #[test]
    fn a_key_or_provider_id_naming_two_products_is_refused() {
        let twice = Catalog::new(vec![
            CatalogProduct::new("full_game", PurchaseKind::OneTime),
            CatalogProduct::new("full_game", PurchaseKind::Subscription),
        ]);
        assert_eq!(
            twice.unwrap_err(),
            CatalogError::DuplicateKey(ProductKey::from("full_game"))
        );
        let shared_price = Catalog::new(vec![
            CatalogProduct::new("a", PurchaseKind::OneTime).stripe_price("price_1"),
            CatalogProduct::new("b", PurchaseKind::OneTime).stripe_price("price_1"),
        ]);
        assert_eq!(
            shared_price.unwrap_err(),
            CatalogError::DuplicateProviderId("price_1".into())
        );
        let empty = Catalog::new(vec![
            CatalogProduct::new("a", PurchaseKind::OneTime).play_id(""),
        ]);
        assert_eq!(empty.unwrap_err(), CatalogError::Empty);
    }

    #[test]
    fn a_config_file_is_checked_like_code() {
        let catalog: Catalog = serde_json::from_value(serde_json::json!([
            { "key": "license", "kind": "one_time", "stripe_price": "price_skicut" },
        ]))
        .unwrap();
        assert!(catalog.by_stripe_price("price_skicut").is_some());
        let round_trip: Catalog =
            serde_json::from_str(&serde_json::to_string(&catalog).unwrap()).unwrap();
        assert_eq!(round_trip, catalog);
        let duplicate = serde_json::from_value::<Catalog>(serde_json::json!([
            { "key": "license", "kind": "one_time" },
            { "key": "license", "kind": "one_time" },
        ]));
        assert!(duplicate.is_err());
    }
}
