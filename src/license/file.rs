//! The signed license file.
//!
//! A license file is `<payload>.<signature>`, both unpadded base64url: the
//! payload is the JSON of [`LicenseClaims`], the signature its Ed25519
//! signature by the app's license signing key. The app ships the matching
//! public key and checks the file offline, so a license works with no
//! network, and a file copied to another machine does not (its `machine`
//! differs).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::entitlements::ProductKey;

/// The current version of [`LicenseClaims`].
pub const CLAIMS_VERSION: u32 = 1;

/// What a license file grants: one product of one app, on one machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub v: u32,
    /// The app's id, such as `tally`.
    pub app: String,
    pub product: ProductKey,
    /// [`key_id`] of the license key, never the key itself.
    pub key_id: String,
    /// The machine id the license was activated for.
    pub machine: String,
    /// When the server signed it.
    pub issued_at: i64,
}

/// Why a license file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenseFileError {
    /// Not a license file at all.
    Malformed,
    /// The signature does not match the app's public key.
    BadSignature,
    /// A valid license, but for another app, product or machine.
    WrongLicense,
    /// The public key the app ships is not an Ed25519 key.
    BadPublicKey,
}

impl std::fmt::Display for LicenseFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "license_malformed",
            Self::BadSignature => "license_signature_invalid",
            Self::WrongLicense => "license_for_another_app_or_machine",
            Self::BadPublicKey => "license_public_key_invalid",
        })
    }
}

impl std::error::Error for LicenseFileError {}

impl LicenseClaims {
    /// The signed bytes of these claims.
    pub fn payload(&self) -> String {
        let json = serde_json::to_vec(self).expect("claims serialize");
        URL_SAFE_NO_PAD.encode(json)
    }

    /// Checks `file` against `public_key` (the 32-byte key, base64), and that
    /// it is this `app`'s license for this `machine`.
    pub fn verify(
        file: &str,
        public_key: &str,
        app: &str,
        machine: &str,
    ) -> Result<Self, LicenseFileError> {
        let claims = Self::verify_signature(file, public_key)?;
        if claims.app != app || claims.machine != machine {
            return Err(LicenseFileError::WrongLicense);
        }
        Ok(claims)
    }

    /// Checks only the signature, and reads the claims.
    pub fn verify_signature(file: &str, public_key: &str) -> Result<Self, LicenseFileError> {
        let key = decode_public_key(public_key)?;
        let (payload, signature) = file
            .trim()
            .split_once('.')
            .ok_or(LicenseFileError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| LicenseFileError::Malformed)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| LicenseFileError::BadSignature)?;
        let json = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| LicenseFileError::Malformed)?;
        let claims: Self =
            serde_json::from_slice(&json).map_err(|_| LicenseFileError::Malformed)?;
        if claims.v != CLAIMS_VERSION {
            return Err(LicenseFileError::Malformed);
        }
        Ok(claims)
    }
}

fn decode_public_key(public_key: &str) -> Result<Vec<u8>, LicenseFileError> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(public_key.trim()))
        .map_err(|_| LicenseFileError::BadPublicKey)?;
    if key.len() != 32 {
        return Err(LicenseFileError::BadPublicKey);
    }
    Ok(key)
}

/// A license key as people type it: upper case, with spaces and any
/// characters that are not letters, digits or dashes dropped.
pub fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// A short, stable id for a license key (the first 16 hex digits of its
/// SHA-256), safe to keep where the key itself should not be.
pub fn key_id(key: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, normalize_key(key).as_bytes());
    digest.as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// A fixed test key pair and its public key in base64.
    pub(crate) fn test_keys() -> (Ed25519KeyPair, String) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public = base64::engine::general_purpose::STANDARD.encode(pair.public_key().as_ref());
        (pair, public)
    }

    pub(crate) fn signed(pair: &Ed25519KeyPair, claims: &LicenseClaims) -> String {
        let payload = claims.payload();
        let signature = pair.sign(payload.as_bytes());
        format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    pub(crate) fn claims() -> LicenseClaims {
        LicenseClaims {
            v: CLAIMS_VERSION,
            app: "tally".into(),
            product: ProductKey::new("tally_full"),
            key_id: key_id("TALLY-AAAA"),
            machine: "m1".into(),
            issued_at: 1_800_000_000,
        }
    }

    #[test]
    fn a_signed_license_verifies_for_its_app_and_machine_only() {
        let (pair, public) = test_keys();
        let file = signed(&pair, &claims());
        assert_eq!(
            LicenseClaims::verify(&file, &public, "tally", "m1").unwrap(),
            claims()
        );
        assert_eq!(
            LicenseClaims::verify(&file, &public, "tally", "m2"),
            Err(LicenseFileError::WrongLicense)
        );
        assert_eq!(
            LicenseClaims::verify(&file, &public, "skicut", "m1"),
            Err(LicenseFileError::WrongLicense)
        );
    }

    #[test]
    fn a_changed_license_or_another_key_is_refused() {
        let (pair, public) = test_keys();
        let file = signed(&pair, &claims());
        let mut other = claims();
        other.machine = "m2".into();
        let (_, signature) = file.split_once('.').unwrap();
        let forged = format!("{}.{signature}", other.payload());
        assert_eq!(
            LicenseClaims::verify(&forged, &public, "tally", "m2"),
            Err(LicenseFileError::BadSignature)
        );

        let stranger = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        assert_eq!(
            LicenseClaims::verify(&signed(&stranger, &claims()), &public, "tally", "m1"),
            Err(LicenseFileError::BadSignature)
        );
        assert_eq!(
            LicenseClaims::verify("nonsense", &public, "tally", "m1"),
            Err(LicenseFileError::Malformed)
        );
        assert_eq!(
            LicenseClaims::verify(&file, "short", "tally", "m1"),
            Err(LicenseFileError::BadPublicKey)
        );
    }

    #[test]
    fn keys_are_compared_as_typed_loosely() {
        assert_eq!(normalize_key(" tally-ab12 cd34\n"), "TALLY-AB12CD34");
        assert_eq!(key_id("tally-ab12"), key_id("TALLY-AB12"));
        assert_eq!(key_id("TALLY-AB12").len(), 16);
        assert_ne!(key_id("TALLY-AB12"), key_id("TALLY-AB13"));
    }
}
