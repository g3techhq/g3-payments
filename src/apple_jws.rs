//! Apple's signed data: the JWS the App Store signs transactions, renewal
//! info and server notifications with.
//!
//! Every payload is trusted only after its `x5c` chain verifies to Apple Root
//! CA - G3 and the leaf's key verifies the signature, the checks Apple's own
//! App Store Server Library makes: exactly three certificates, ES256, the leaf
//! and intermediate carrying Apple's marker extensions, and every certificate
//! valid now. Nothing here reads a payload before that, and the errors name
//! only the check that failed, never the payload.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, de::DeserializeOwned};
use webpki::{EndEntityCert, KeyPurposeIdIter};

/// Apple Root CA - G3, from <https://www.apple.com/certificateauthority/>.
/// SHA-256 fingerprint
/// `63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179`;
/// a test pins it.
const APPLE_ROOT_CA_G3: &[u8] = include_bytes!("apple_jws/AppleRootCA-G3.cer");

/// 1.2.840.113635.100.6.11.1: the App Store receipt-signing leaf.
const LEAF_MARKER_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x0B, 0x01];

/// 1.2.840.113635.100.6.2.1: Apple's WWDR intermediate.
const INTERMEDIATE_MARKER_OID: &[u8] =
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x02, 0x01];

/// Why a JWS was refused. Deliberately payload-free, so it can be logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwsError {
    Malformed,
    UnsupportedAlgorithm,
    CertificateCount,
    Certificate,
    Chain,
    MissingAppleMarker,
    Signature,
    Payload,
}

impl JwsError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "jws_malformed",
            Self::UnsupportedAlgorithm => "jws_unsupported_algorithm",
            Self::CertificateCount => "jws_certificate_count",
            Self::Certificate => "jws_certificate_invalid",
            Self::Chain => "jws_chain_untrusted",
            Self::MissingAppleMarker => "jws_apple_marker_missing",
            Self::Signature => "jws_signature_invalid",
            Self::Payload => "jws_payload_invalid",
        }
    }
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for JwsError {}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    x5c: Vec<String>,
}

/// Apple puts no EKU on these certificates, and its libraries check none.
struct AnyExtendedKeyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyExtendedKeyUsage {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

/// Verifies Apple-signed JWS against a fixed set of trusted roots.
pub struct SignedDataVerifier {
    roots: Vec<CertificateDer<'static>>,
}

impl SignedDataVerifier {
    /// Trusts only Apple Root CA - G3.
    pub fn apple() -> Self {
        Self {
            roots: vec![CertificateDer::from(APPLE_ROOT_CA_G3)],
        }
    }

    #[cfg(test)]
    pub fn with_roots(roots: Vec<Vec<u8>>) -> Self {
        Self {
            roots: roots.into_iter().map(CertificateDer::from).collect(),
        }
    }

    /// The payload of `jws`, once its chain and signature check out at `now`.
    pub fn verify<T: DeserializeOwned>(&self, jws: &str, now: UnixTime) -> Result<T, JwsError> {
        let mut parts = jws.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwsError::Malformed);
        };

        let header: Header = URL_SAFE_NO_PAD
            .decode(header_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(JwsError::Malformed)?;
        if header.alg != "ES256" {
            return Err(JwsError::UnsupportedAlgorithm);
        }
        // Leaf, intermediate, root. The root in the header is not trusted; the
        // chain has to end at one of ours.
        if header.x5c.len() != 3 {
            return Err(JwsError::CertificateCount);
        }
        let leaf_der = STANDARD
            .decode(&header.x5c[0])
            .map_err(|_| JwsError::Certificate)?;
        let intermediate_der = STANDARD
            .decode(&header.x5c[1])
            .map_err(|_| JwsError::Certificate)?;

        let leaf_cert = CertificateDer::from(leaf_der.as_slice());
        let leaf = EndEntityCert::try_from(&leaf_cert).map_err(|_| JwsError::Certificate)?;
        let intermediates = [CertificateDer::from(intermediate_der.as_slice())];
        let anchors = self
            .roots
            .iter()
            .map(|root| webpki::anchor_from_trusted_cert(root).map_err(|_| JwsError::Chain))
            .collect::<Result<Vec<_>, _>>()?;

        // The path must run leaf -> the header's intermediate -> a trusted
        // root, so the intermediate whose marker is checked below is the one
        // that actually issued the leaf.
        let through_header_intermediate = |path: &webpki::VerifiedPath<'_>| {
            let mut issued_by = path.intermediate_certificates();
            match (issued_by.next(), issued_by.next()) {
                (Some(intermediate), None) if intermediate.der().as_ref() == intermediate_der => {
                    Ok(())
                }
                _ => Err(webpki::Error::UnknownIssuer),
            }
        };
        leaf.verify_for_usage(
            &[
                webpki::ring::ECDSA_P256_SHA256,
                webpki::ring::ECDSA_P256_SHA384,
                webpki::ring::ECDSA_P384_SHA256,
                webpki::ring::ECDSA_P384_SHA384,
            ],
            &anchors,
            &intermediates,
            now,
            AnyExtendedKeyUsage,
            None,
            Some(&through_header_intermediate),
        )
        .map_err(|_| JwsError::Chain)?;

        if !has_extension(&leaf_der, LEAF_MARKER_OID)
            || !has_extension(&intermediate_der, INTERMEDIATE_MARKER_OID)
        {
            return Err(JwsError::MissingAppleMarker);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| JwsError::Signature)?;
        let signature = der_ecdsa_signature(&signature).ok_or(JwsError::Signature)?;
        let signing_input = &jws[..header_b64.len() + 1 + payload_b64.len()];
        leaf.verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            signing_input.as_bytes(),
            &signature,
        )
        .map_err(|_| JwsError::Signature)?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| JwsError::Payload)?;
        serde_json::from_slice(&payload).map_err(|_| JwsError::Payload)
    }
}

/// JWS carries ES256 signatures as the raw 64-byte `r || s`; webpki takes the
/// ASN.1 `SEQUENCE { INTEGER r, INTEGER s }` that X.509 uses.
fn der_ecdsa_signature(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let first = bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len() - 1);
        let bytes = &bytes[first..];
        let mut out = vec![0x02];
        if bytes[0] & 0x80 != 0 {
            out.push(bytes.len() as u8 + 1);
            out.push(0);
        } else {
            out.push(bytes.len() as u8);
        }
        out.extend_from_slice(bytes);
        out
    }
    let mut body = integer(&raw[..32]);
    body.extend(integer(&raw[32..]));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    Some(out)
}

/// One DER TLV: its tag, its contents and what follows it.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// Whether the certificate's extensions include `oid`. Run only on
/// certificates webpki has already parsed and verified.
fn has_extension(certificate: &[u8], oid: &[u8]) -> bool {
    fn find(certificate: &[u8], oid: &[u8]) -> Option<bool> {
        let (_, certificate, _) = tlv(certificate)?;
        let (_, mut tbs, _) = tlv(certificate)?;
        while !tbs.is_empty() {
            let (tag, contents, rest) = tlv(tbs)?;
            tbs = rest;
            // [3] EXPLICIT Extensions
            if tag == 0xA3 {
                let (_, mut extensions, _) = tlv(contents)?;
                while !extensions.is_empty() {
                    let (_, extension, rest) = tlv(extensions)?;
                    extensions = rest;
                    let (tag, extension_oid, _) = tlv(extension)?;
                    if tag == 0x06 && extension_oid == oid {
                        return Some(true);
                    }
                }
                return Some(false);
            }
        }
        Some(false)
    }
    find(certificate, oid).unwrap_or(false)
}

#[cfg(test)]
pub(crate) mod testing {
    //! Signs payloads the way Apple does, with the synthetic chain in
    //! `testdata/app_store` at the repository root (see its `generate.sh`).

    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    };
    use serde::Serialize;

    pub const ROOT: &[u8] = include_bytes!("../testdata/app_store/root.der");
    pub const INTERMEDIATE: &[u8] = include_bytes!("../testdata/app_store/intermediate.der");
    pub const INTERMEDIATE_UNMARKED: &[u8] =
        include_bytes!("../testdata/app_store/intermediate_unmarked.der");
    pub const LEAF: &[u8] = include_bytes!("../testdata/app_store/leaf.der");
    pub const LEAF_KEY: &[u8] = include_bytes!("../testdata/app_store/leaf.key.der");
    pub const LEAF_UNMARKED: &[u8] = include_bytes!("../testdata/app_store/leaf_unmarked.der");
    pub const LEAF_UNMARKED_KEY: &[u8] =
        include_bytes!("../testdata/app_store/leaf_unmarked.key.der");
    pub const LEAF_UNDER_UNMARKED: &[u8] =
        include_bytes!("../testdata/app_store/leaf_under_unmarked.der");
    pub const LEAF_UNDER_UNMARKED_KEY: &[u8] =
        include_bytes!("../testdata/app_store/leaf_under_unmarked.key.der");
    pub const OTHER_LEAF_KEY: &[u8] = include_bytes!("../testdata/app_store/other_leaf.key.der");
    pub const APPLE_WWDR_G6: &[u8] = include_bytes!("../testdata/app_store/apple_wwdr_g6.der");

    /// Within the synthetic chain's validity (2026-11-04 to 2126).
    pub fn now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000))
    }

    pub fn verifier() -> SignedDataVerifier {
        SignedDataVerifier::with_roots(vec![ROOT.to_vec()])
    }

    /// An ES256 JWS over `claims`, signed with the PKCS#8 `key`, carrying
    /// `chain` (leaf, intermediate, root) in its `x5c` header.
    pub fn sign_with(claims: &impl Serialize, key: &[u8], chain: [&[u8]; 3]) -> String {
        let header = serde_json::json!({
            "alg": "ES256",
            "x5c": chain.iter().map(|cert| STANDARD.encode(cert)).collect::<Vec<_>>(),
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header encodes"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims encode"));
        let signing_input = format!("{header}.{payload}");
        let random = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key, &random)
            .expect("test key is a P-256 PKCS#8 key");
        // FIXED signing is the raw 64-byte `r || s` that JWS carries.
        let signature = key
            .sign(&random, signing_input.as_bytes())
            .expect("test JWS signs");
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    /// Signed by the synthetic chain's well-formed leaf.
    pub fn sign(claims: &impl Serialize) -> String {
        sign_with(claims, LEAF_KEY, [LEAF, INTERMEDIATE, ROOT])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    fn claims() -> Value {
        json!({ "transactionId": "2000000000001", "bundleId": "com.g3tech.greensidepartee" })
    }

    #[test]
    fn the_embedded_root_is_apple_root_ca_g3() {
        let fingerprint = Sha256::digest(APPLE_ROOT_CA_G3)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        assert_eq!(
            fingerprint,
            "63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179"
        );
        assert!(webpki::anchor_from_trusted_cert(&CertificateDer::from(APPLE_ROOT_CA_G3)).is_ok());
    }

    #[test]
    fn apples_real_intermediate_carries_the_marker_the_verifier_checks() {
        assert!(has_extension(APPLE_WWDR_G6, INTERMEDIATE_MARKER_OID));
        assert!(!has_extension(APPLE_WWDR_G6, LEAF_MARKER_OID));
    }

    #[test]
    fn a_payload_signed_by_a_trusted_chain_verifies() {
        let payload: Value = verifier().verify(&sign(&claims()), now()).unwrap();
        assert_eq!(payload, claims());
    }

    #[test]
    fn the_production_verifier_trusts_only_apple() {
        assert_eq!(
            SignedDataVerifier::apple()
                .verify::<Value>(&sign(&claims()), now())
                .unwrap_err(),
            JwsError::Chain
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let jws = sign(&claims());
        let mut parts: Vec<&str> = jws.split('.').collect();
        let forged = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({ "transactionId": "2000000000999" })).unwrap());
        parts[1] = &forged;
        assert_eq!(
            verifier()
                .verify::<Value>(&parts.join("."), now())
                .unwrap_err(),
            JwsError::Signature
        );
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let jws = sign_with(&claims(), OTHER_LEAF_KEY, [LEAF, INTERMEDIATE, ROOT]);
        assert_eq!(
            verifier().verify::<Value>(&jws, now()).unwrap_err(),
            JwsError::Signature
        );
    }

    #[test]
    fn certificates_outside_their_validity_are_refused() {
        let before = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));
        assert_eq!(
            verifier()
                .verify::<Value>(&sign(&claims()), before)
                .unwrap_err(),
            JwsError::Chain
        );
    }

    #[test]
    fn a_leaf_without_apples_marker_is_refused() {
        let jws = sign_with(
            &claims(),
            LEAF_UNMARKED_KEY,
            [LEAF_UNMARKED, INTERMEDIATE, ROOT],
        );
        assert_eq!(
            verifier().verify::<Value>(&jws, now()).unwrap_err(),
            JwsError::MissingAppleMarker
        );
    }

    #[test]
    fn an_intermediate_without_apples_marker_is_refused() {
        let jws = sign_with(
            &claims(),
            LEAF_UNDER_UNMARKED_KEY,
            [LEAF_UNDER_UNMARKED, INTERMEDIATE_UNMARKED, ROOT],
        );
        assert_eq!(
            verifier().verify::<Value>(&jws, now()).unwrap_err(),
            JwsError::MissingAppleMarker
        );
    }

    #[test]
    fn the_marked_intermediate_cannot_vouch_for_a_leaf_it_did_not_issue() {
        let jws = sign_with(
            &claims(),
            LEAF_UNDER_UNMARKED_KEY,
            [LEAF_UNDER_UNMARKED, INTERMEDIATE, ROOT],
        );
        assert_eq!(
            verifier().verify::<Value>(&jws, now()).unwrap_err(),
            JwsError::Chain
        );
    }

    #[test]
    fn anything_but_three_certificates_is_refused() {
        let jws = sign_with(&claims(), LEAF_KEY, [LEAF, INTERMEDIATE, ROOT]);
        let header = json!({
            "alg": "ES256",
            "x5c": [STANDARD.encode(LEAF), STANDARD.encode(INTERMEDIATE)],
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let rest = jws.split_once('.').unwrap().1;
        assert_eq!(
            verifier()
                .verify::<Value>(&format!("{header}.{rest}"), now())
                .unwrap_err(),
            JwsError::CertificateCount
        );
    }

    #[test]
    fn only_es256_is_accepted() {
        let jws = sign_with(&claims(), LEAF_KEY, [LEAF, INTERMEDIATE, ROOT]);
        for alg in ["none", "HS256", "ES384"] {
            let header = json!({
                "alg": alg,
                "x5c": [STANDARD.encode(LEAF), STANDARD.encode(INTERMEDIATE), STANDARD.encode(ROOT)],
            });
            let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let rest = jws.split_once('.').unwrap().1;
            assert_eq!(
                verifier()
                    .verify::<Value>(&format!("{header}.{rest}"), now())
                    .unwrap_err(),
                JwsError::UnsupportedAlgorithm,
                "{alg}"
            );
        }
    }

    #[test]
    fn malformed_input_is_refused_without_panicking() {
        for jws in ["", "a.b", "a.b.c.d", "!!.!!.!!", "e30.e30.e30"] {
            assert!(verifier().verify::<Value>(jws, now()).is_err(), "{jws}");
        }
    }

    #[test]
    fn signatures_convert_to_der() {
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        assert_eq!(
            der_ecdsa_signature(&raw).unwrap(),
            [
                vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0x80],
                vec![0; 31]
            ]
            .concat()
        );
        assert!(der_ecdsa_signature(&raw[..63]).is_none());
    }
}
