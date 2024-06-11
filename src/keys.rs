use jsonwebtoken::jwk;
use std::collections::HashMap;

fn parse_alg(alg: &str) -> Option<jwk::KeyAlgorithm> {
    match alg.to_uppercase().as_str() {
        "RS256" => Some(jwk::KeyAlgorithm::RS256),
        "RS384" => Some(jwk::KeyAlgorithm::RS384),
        "RS512" => Some(jwk::KeyAlgorithm::RS512),
        _ => None,
    }
}

fn parse_usage(usage: &str) -> jwk::PublicKeyUse {
    match usage.to_lowercase().as_str() {
        "sig" => jwk::PublicKeyUse::Signature,
        "enc" => jwk::PublicKeyUse::Encryption,
        other => jwk::PublicKeyUse::Other(other.to_string()),
    }
}

pub type AccessKeyMap = HashMap<String, Box<dyn AccessKey>>;


/// A trait that allows conversion to a jsonwebtoken::jwk::JWK.
pub trait AccessKey {
    fn get_key_id(&self) -> String;
    fn get_jwk(&self) -> jwk::Jwk;
}

/// A struct representing a RSA public key used to sign CFZT JWTs.
pub struct RsaAccessKey {
    key_id: String,
    key_algorithm: String,
    key_usage: String,
    exponent: String,
    modulus: String,
}

impl RsaAccessKey {
    /// Constructs a new RsaAccessKey struct.
    pub fn new(
        key_id: &str,
        key_algorithm: &str,
        key_usage: &str,
        exponent: &str,
        modulus: &str,
    ) -> Self {
        RsaAccessKey {
            key_id: key_id.to_string(),
            key_algorithm: key_algorithm.to_string(),
            key_usage: key_usage.to_string(),
            exponent: exponent.to_string(),
            modulus: modulus.to_string(),
        }
    }
}

impl AccessKey for RsaAccessKey {
    /// Returns the key ID for the CFZT key.
    fn get_key_id(&self) -> String {
        self.key_id.clone()
    }

    /// Mints a valid jsonwebtoken::jwk::JWK struct for the
    /// RsaAccessKey.
    fn get_jwk(&self) -> jwk::Jwk {
        jwk::Jwk {
            common: jwk::CommonParameters {
                public_key_use: Some(parse_usage(&self.key_usage)),
                key_operations: None,
                key_algorithm: parse_alg(&self.key_algorithm),
                key_id: Some(self.key_id.clone()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: jwk::AlgorithmParameters::RSA(jwk::RSAKeyParameters {
                key_type: jwk::RSAKeyType::RSA,
                n: self.modulus.clone(),
                e: self.exponent.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ID: &str = "foo";
    const RSA_KEY_ALGORITHM: &str = "RS256";
    const RSA_KEY_USAGE: &str = "sig";
    const RSA_EXPONENT: &str = "AQAB";
    const RSA_MODULUS: &str = "xbd6OnCJ3D7mb3bjV0LXP9KeZ1Kuiuk0f_OIOi3S4KHunA1KYuUcmKfB5rAYKZakPvZ0YnmL7_GPZNd263fg55U6-QZsNKWW1sldHHCws-eEnyO6nc6KTk6rNwGUY0c2lfAOmyHmXPomy3ly6TBgXFfVs6N-O-LIIQDimaC8C6QHcYk7KBg_heDJG_Izzicb0YeYSOYYAcZ194fA3eU9WIpT3P4K4pMtoTDF4zE5GPDgm-ngnP2RViS0uBJcYXVHeAmAdA1gS5cbvw1tvxe73LZ461W37z2tJZwqapMnlbggnw8gIqy6--rBsKiSDfyfA86YSyUyC43UPWk50jupVw";

    #[test]
    fn test_rsa_access_key() {
        let key = RsaAccessKey::new(
            KEY_ID,
            RSA_KEY_ALGORITHM,
            RSA_KEY_USAGE,
            RSA_EXPONENT,
            RSA_MODULUS,
        );

        assert_eq!(key.get_key_id(), KEY_ID);

        let jwk = key.get_jwk();

        assert_eq!(jwk.common.key_id.unwrap(), KEY_ID);
        assert_eq!(jwk.common.key_algorithm.unwrap(), jwk::KeyAlgorithm::RS256);
        assert_eq!(
            jwk.common.public_key_use.unwrap(),
            jwk::PublicKeyUse::Signature
        );

        match jwk.algorithm {
            jwk::AlgorithmParameters::RSA(params) => {
                assert_eq!(params.key_type, jwk::RSAKeyType::RSA);
                assert_eq!(params.n, RSA_MODULUS);
                assert_eq!(params.e, RSA_EXPONENT);
            }
            _ => panic!("unexpected AlgorithmParameters value"),
        }
    }
}
