//! Signed tokens for providers' APIs: ES256 for the App Store Server API,
//! RS256 for Google's OAuth token exchange. Both keys arrive as PKCS#8 PEM,
//! which is what App Store Connect and Google Cloud hand out.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::rand::SystemRandom;
use serde::Serialize;

use super::VerifyError;

/// The DER inside a PEM block, whatever its label.
pub(crate) fn pem_to_der(pem: &str) -> Result<Vec<u8>, VerifyError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body)
        .map_err(|_| VerifyError::Configuration("private key is not PEM".into()))
}

fn signing_input(header: &serde_json::Value, claims: &impl Serialize) -> String {
    let encode = |value: Vec<u8>| URL_SAFE_NO_PAD.encode(value);
    let header = serde_json::to_vec(header).unwrap_or_default();
    let claims = serde_json::to_vec(claims).unwrap_or_default();
    format!("{}.{}", encode(header), encode(claims))
}

/// An ES256 JWT, with `kid` in its header when given.
#[cfg(feature = "app-store")]
pub(crate) fn es256(
    claims: &impl Serialize,
    key_pem: &str,
    kid: Option<&str>,
) -> Result<String, VerifyError> {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let random = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &pem_to_der(key_pem)?,
        &random,
    )
    .map_err(|_| VerifyError::Configuration("private key is not a P-256 PKCS#8 key".into()))?;
    let mut header = serde_json::json!({ "alg": "ES256", "typ": "JWT" });
    if let Some(kid) = kid {
        header["kid"] = kid.into();
    }
    let input = signing_input(&header, claims);
    let signature = key
        .sign(&random, input.as_bytes())
        .map_err(|_| VerifyError::Configuration("could not sign with the private key".into()))?;
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    ))
}

/// An RS256 JWT.
#[cfg(feature = "play")]
pub(crate) fn rs256(claims: &impl Serialize, key_pem: &str) -> Result<String, VerifyError> {
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    let key = RsaKeyPair::from_pkcs8(&pem_to_der(key_pem)?)
        .map_err(|_| VerifyError::Configuration("private key is not an RSA PKCS#8 key".into()))?;
    let input = signing_input(&serde_json::json!({ "alg": "RS256", "typ": "JWT" }), claims);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| VerifyError::Configuration("could not sign with the private key".into()))?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

#[cfg(test)]
pub(crate) mod testing {
    //! Throwaway keys for signing tests (`testdata/keys`, see its `generate.sh`).

    #[cfg(feature = "app-store")]
    pub const EC_KEY_PEM: &str = include_str!("../../testdata/keys/ec.key.pem");
    #[cfg(feature = "play")]
    pub const RSA_KEY_PEM: &str = include_str!("../../testdata/keys/rsa.key.pem");
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use ring::signature::UnparsedPublicKey;

    fn parts(token: &str) -> (serde_json::Value, serde_json::Value, String, Vec<u8>) {
        let pieces: Vec<&str> = token.split('.').collect();
        assert_eq!(pieces.len(), 3);
        let decode = |piece: &str| URL_SAFE_NO_PAD.decode(piece).unwrap();
        (
            serde_json::from_slice(&decode(pieces[0])).unwrap(),
            serde_json::from_slice(&decode(pieces[1])).unwrap(),
            format!("{}.{}", pieces[0], pieces[1]),
            decode(pieces[2]),
        )
    }

    #[cfg(feature = "app-store")]
    #[test]
    fn es256_tokens_verify_with_the_keys_public_half() {
        use ring::signature::{
            ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
        };

        let claims = serde_json::json!({ "iss": "issuer", "aud": "appstoreconnect-v1" });
        let token = es256(&claims, EC_KEY_PEM, Some("KEY123")).unwrap();
        let (header, decoded, input, signature) = parts(&token);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY123");
        assert_eq!(decoded, claims);
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pem_to_der(EC_KEY_PEM).unwrap(),
            &SystemRandom::new(),
        )
        .unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[cfg(feature = "play")]
    #[test]
    fn rs256_tokens_verify_with_the_keys_public_half() {
        use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair};

        let claims = serde_json::json!({ "iss": "service@example.iam.gserviceaccount.com" });
        let token = rs256(&claims, RSA_KEY_PEM).unwrap();
        let (header, decoded, input, signature) = parts(&token);
        assert_eq!(header["alg"], "RS256");
        assert!(header.get("kid").is_none());
        assert_eq!(decoded, claims);
        let key = RsaKeyPair::from_pkcs8(&pem_to_der(RSA_KEY_PEM).unwrap()).unwrap();
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref())
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    #[cfg(all(feature = "app-store", feature = "play"))]
    #[test]
    fn a_key_of_the_wrong_kind_is_a_configuration_error() {
        let claims = serde_json::json!({});
        assert!(matches!(
            es256(&claims, RSA_KEY_PEM, None),
            Err(VerifyError::Configuration(_))
        ));
        assert!(matches!(
            rs256(&claims, EC_KEY_PEM),
            Err(VerifyError::Configuration(_))
        ));
        assert!(matches!(
            rs256(&claims, "not a key"),
            Err(VerifyError::Configuration(_))
        ));
    }
}
