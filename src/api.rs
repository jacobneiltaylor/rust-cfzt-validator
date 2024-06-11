use crate::{
    errors::{UnpackError, UnpackResult},
    keys::{self, AccessKey},
    unpack, StdResult,
};

use std::collections::HashMap;

use serde_json::Value;
use ureq;

pub(crate) fn extract_latest_key_id(payload: &Value) -> UnpackResult<String> {
    // get string value at payload["public_cert"]["kid"]
    unpack::as_string(unpack::as_object_get_key(
        unpack::as_object_get_key(payload, "public_cert")?,
        "kid",
    )?)
    .cloned()
}

pub(crate) fn extract_current_keys(payload: &Value) -> UnpackResult<keys::AccessKeyMap> {
    // get array value at payload["keys"]
    let cert_objs = unpack::as_array(unpack::as_object_get_key(payload, "keys")?)?;

    if cert_objs.len() == 0 {
        return Err(UnpackError::empty_container("array"));
    }

    let mut map: keys::AccessKeyMap = HashMap::new();

    for val in cert_objs {
        let obj = unpack::as_object(val)?;

        // will need refactoring if/when cf aupports new key types
        let access_key = keys::RsaAccessKey::new(
            unpack::as_string(unpack::get_key(obj, "kid")?)?,
            unpack::as_string(unpack::get_key(obj, "alg")?)?,
            unpack::as_string(unpack::get_key(obj, "use")?)?,
            unpack::as_string(unpack::get_key(obj, "e")?)?,
            unpack::as_string(unpack::get_key(obj, "n")?)?,
        );

        map.insert(access_key.get_key_id(), Box::new(access_key));
    }

    Ok(map)
}

fn get_team_key_uri(team_name: &str) -> String {
    format!("https://{team_name}.cloudflareaccess.com/cdn-cgi/access/certs")
}

fn get_json_payload(uri: &str) -> Result<Value, ureq::Error> {
    let payload = ureq::get(uri).call()?.into_json::<Value>()?;

    Ok(payload)
}

fn get_team_keys(team_name: &str) -> StdResult<(String, keys::AccessKeyMap)> {
    let uri = get_team_key_uri(team_name);
    let payload = get_json_payload(&uri)?;
    Ok((
        extract_latest_key_id(&payload)?,
        extract_current_keys(&payload)?,
    ))
}

/// Represents a set of trusted signing keys for a specific CFZT Team
pub struct TeamKeys {
    pub team_name: String,
    pub latest_key_id: String,
    pub keys: keys::AccessKeyMap,
}

impl TeamKeys {
    fn new(team_name: &str, latest_key_id: &str, keys: keys::AccessKeyMap) -> Self {
        TeamKeys {
            team_name: team_name.to_string(),
            latest_key_id: latest_key_id.to_string(),
            keys,
        }
    }

    /// Attempts to load signing keys for a given team using a HTTP request.
    pub fn from_team_name(team_name: &str) -> StdResult<Self> {
        let (latest_key_id, keys) = get_team_keys(team_name)?;
        Ok(TeamKeys::new(team_name, &latest_key_id, keys))
    }

    // Attempts to load signing keys from a given serde_json::Value struct.
    pub fn from_json(team_name: &str, json_val: Value) -> StdResult<Self> {
        let latest_key_id = extract_latest_key_id(&json_val)?;
        let keys = extract_current_keys(&json_val)?;
        Ok(TeamKeys::new(team_name, &latest_key_id, keys))
    }

    // Attempts to load signing keys from a given JSON string slice.
    pub fn from_str(team_name: &str, json_str: &str) -> StdResult<Self> {
        let json_val = serde_json::from_str(json_str)?;
        TeamKeys::from_json(team_name, json_val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk;
    use serde_json;

    const DUMMY_PAYLOAD: &str = include_str!("../test_data/dummy_signing_keys.json");

    const EXPECTED_LATEST_KEY_ID: &str = "foo";
    const EXPECTED_LATEST_KEY_CONTENT: &str = "bar";
    const EXPECTED_ADDITIONAL_KEY_ID: &str = "baz";
    const EXPECTED_ADDITIONAL_KEY_CONTENT: &str = "bin";

    const TEST_TEAM: &str = "example";

    fn get_payload_value() -> Value {
        serde_json::from_str(DUMMY_PAYLOAD).unwrap()
    }

    fn assert_access_key_content(key: &Box<dyn AccessKey>, expect: &str) {
        match key.get_jwk().algorithm {
            jwk::AlgorithmParameters::RSA(params) => {
                assert_eq!(params.e, expect);
                assert_eq!(params.n, expect);
            }
            _ => panic!(
                "incorrect AlgorithmParameters for kid '{}'",
                key.get_key_id()
            ),
        }
    }

    #[test]
    fn test_unpack_latest_key_id() {
        let payload = get_payload_value();
        let actual_key_id = extract_latest_key_id(&payload);

        assert!(actual_key_id.is_ok());
        assert_eq!(actual_key_id.unwrap(), EXPECTED_LATEST_KEY_ID);
    }

    #[test]
    fn test_unpack_current_keys() {
        let payload = get_payload_value();
        let actual_keys = extract_current_keys(&payload).unwrap();

        assert!(actual_keys.contains_key(EXPECTED_LATEST_KEY_ID));
        assert!(actual_keys.contains_key(EXPECTED_ADDITIONAL_KEY_ID));

        let latest_key = actual_keys.get(EXPECTED_LATEST_KEY_ID).unwrap();
        let additional_key = actual_keys.get(EXPECTED_ADDITIONAL_KEY_ID).unwrap();

        assert_eq!(latest_key.get_key_id(), EXPECTED_LATEST_KEY_ID);
        assert_eq!(additional_key.get_key_id(), EXPECTED_ADDITIONAL_KEY_ID);

        assert_access_key_content(latest_key, EXPECTED_LATEST_KEY_CONTENT);
        assert_access_key_content(additional_key, EXPECTED_ADDITIONAL_KEY_CONTENT);
    }

    #[test]
    fn test_get_team_keys() {
        let result = get_team_keys(TEST_TEAM);
        assert!(result.is_ok());
    }
}
