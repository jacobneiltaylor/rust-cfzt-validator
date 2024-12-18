use crate::keys;
use jsonwebtoken::{
    jwk::{self, JwkSet},
    DecodingKey,
};
use std::{collections::{HashMap, HashSet}, mem::replace, sync::RwLock};

fn assert_key(key_id: &str, keymap: &keys::AccessKeyMap) {
    if !keymap.contains_key(key_id) {
        panic!("kid '{key_id}' is not in key set");
    }
}

fn build_kid_set(keymap: &keys::AccessKeyMap) -> HashSet<String> {
    let mut kids: HashSet<String> = HashSet::new();

    for kid in keymap.keys() {
        kids.insert(kid.to_string());
    }

    return kids;
}

fn build_jwk_set(keymap: &keys::AccessKeyMap) -> jwk::JwkSet {
    let mut jwks: Vec<jwk::Jwk> = Vec::new();

    for key in keymap.values() {
        jwks.push(key.get_jwk());
    }

    JwkSet { keys: jwks }
}

struct KeySet {
    kid_set: HashSet<String>,
    key_set: jwk::JwkSet,
}

impl KeySet {
    pub fn new(keymap: keys::AccessKeyMap) -> Self {
        Self {
            kid_set: build_kid_set(&keymap),
            key_set: build_jwk_set(&keymap),
        }
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.kid_set.contains(key_id)
    }

    pub fn find(&self, key_id: &str) -> Option<&jwk::Jwk> {
        self.key_set.find(key_id)
    }

    pub fn get_key_ids(&self) -> HashSet<String> {
        self.kid_set.clone()
    }
}


/// Maintains the autoritative list of currently trusted JWKs for a single team
/// and caches the DecodingKey structs derived from them.
/// Needs to be periodically seeded with latest keys by some external trigger
/// invoking the rotate_keys() method.
pub struct Cache {
    latest_key_id: RwLock<String>,
    key_set: RwLock<KeySet>,
    decoding_keys: RwLock<HashMap<String, DecodingKey>>,
}

impl Cache {
    fn contains_key(&self, key_id: &str) -> bool {
        self.key_set.read().unwrap().contains(&key_id)
    }

    fn is_decoding_key_cached(&self, key_id: &str) -> bool {
        self.decoding_keys.read().unwrap().contains_key(key_id)
    }

    fn get_key(&self, key_id: &str) -> Option<jwk::Jwk> {
        Some(self.key_set.read().unwrap().find(key_id)?.clone())
    }

    fn flush_stale_decoding_keys(&self) {
        // Acquire write lock
        let mut decoding_keys = self.decoding_keys.write().unwrap();

        // Take a snapshot of current keys
        let cached_key_ids: Vec<String> = decoding_keys
            .keys()
            .map(|key_id| key_id.to_owned())
            .collect();

        // Identify stale entries in decoding key cache and purge them
        for key_id in cached_key_ids {
            if !self.contains_key(&key_id) {
                decoding_keys.remove(&key_id);
            }
        }
    }

    fn build_decoding_key(&self, key_id: &str) {
        if !self.is_decoding_key_cached(key_id) {
            let mut decoding_keys = self.decoding_keys.write().unwrap();
            let jwk = self.get_key(key_id).unwrap();
            let decoding_key = DecodingKey::from_jwk(&jwk).unwrap();
            decoding_keys.insert(key_id.to_string(), decoding_key);
        }
    }

    /// Constructs a new Cache from a key ID denoting the latest JWK
    /// and a HashMap of key IDs to AccessKey structs.
    pub fn new(latest_key_id: &str, keymap: keys::AccessKeyMap) -> Self {
        assert_key(latest_key_id, &keymap);

        let this = Cache {
            latest_key_id: RwLock::new(latest_key_id.to_string()),
            key_set: RwLock::new(KeySet::new(keymap)),
            decoding_keys: RwLock::new(HashMap::new()),
        };

        // Prewarm the cache with the latest key
        this.build_decoding_key(latest_key_id);

        this
    }

    /// Given a specific map of new keys, check if an update is required.
    pub fn is_rotation_needed(&self, candidate_key_ids: HashSet<String>) -> bool {
        let current = self.get_key_ids();
        let diff: Vec<&String> = current.difference(&candidate_key_ids).collect();
        diff.len() > 0
    }

    /// Retrieve the latest key id
    pub fn get_latest_key_id(&self) -> String {
        self.latest_key_id.read().unwrap().clone()
    }

    /// Updates the Cache with a new latest key ID and map of AccessKey structs.
    pub fn rotate_keys(&self, latest_key_id: &str, latest_keymap: keys::AccessKeyMap) {
        assert_key(latest_key_id, &latest_keymap);

        let _ = replace(&mut *self.latest_key_id.write().unwrap(), latest_key_id.to_string());
        let _ = replace(&mut *self.key_set.write().unwrap(), KeySet::new(latest_keymap));

        self.flush_stale_decoding_keys();
        self.build_decoding_key(latest_key_id);
    }

    /// Get the current list of trusted key IDs.
    pub fn get_key_ids(&self) -> HashSet<String> {
        self.key_set.read().unwrap().get_key_ids()
    }

    /// Attempt to retrieve a specific key as a DecodingKey struct.
    pub fn get_decoding_key(&self, key_id: &str) -> Option<DecodingKey> {
        if self.contains_key(&key_id) {
                self.build_decoding_key(key_id);
                return Some(self.decoding_keys.read().unwrap().get(key_id)?.to_owned());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{api, keys};

    use super::*;
    use jsonwebtoken;
    use serde::{Deserialize, Serialize};
    use serde_json;

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        foo: String,
        bin: String,
    }

    const SAMPLE_NEW_PAYLOAD: &str = include_str!("../test_data/mock_signing_key_1.json");
    const SAMPLE_ROTATION_PAYLOAD: &str = include_str!("../test_data/mock_signing_key_2.json");

    const KEY_ID_NEW: &str = "o3KvfajHFSE6XLTo0oP98efQvVmfpS0CkPKlNSTzNjA";
    const KEY_ID_ROTATE: &str = "X33sNdmTvRC0O6irH8lKcncS9klV37WVzKlV7v2zY_s";

    const TOKEN_NEW: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im8zS3ZmYWpIRlNFNlhMVG8wb1A5OGVmUXZWbWZwUzBDa1BLbE5TVHpOakEifQ.eyJiaW4iOiJiYXoiLCJmb28iOiJiYXIifQ.jRRcOsa4Wayx5dbYC-Rk5qF5SKUq9OnYqRlilK8tuugXFrYkxGXpmX-2_TzRGH8--lnS-OWXVacnbTwKVyS1w3uswAph40ySIGUnOg9oKkL2Gu5aIq8AejmseqQkwWGep9a5dcklAiBMgiwTw2B2rQTay2ZCKKjY0TJm8Lh0Msngsb1aXlMWcLWZxUtEh5bVr7y3m23CT4NuL0hGMxFW9okzuRHW8pyWAgXln8ii2U8-ypVyJ0YLYjpvXPRGg12rPp3NgWh6uGe_HuRqVuHSSWVTUT-bwP4vcTndvq9943gc_O_VRd-OTnN2CRen8KXWdJLwW63mKvxUa4M9RFW-Iw";
    const TOKEN_ROTATE: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlgzM3NOZG1UdlJDME82aXJIOGxLY25jUzlrbFYzN1dWektsVjd2MnpZX3MifQ.eyJiaW4iOiJiYXoiLCJmb28iOiJiYXIifQ.GCfxwZLaDpECHKRYbAg28ZE745ktgCnOlWnlPdT6JNnW3NQIDEHK1hTIjKU8I8yi88JAW77BWiJl7bUW-b_Ykmi3bltDuI4RfGdArQXgWsX5kNCyChMyT63JEh70USmZ7QsBuE3loMHM-gcmP_DD6iKvbCk2vY9TaxIsYfxJtSxZ8i9mYCR93W0qtY9uuSV6Tls6fYHj5shexrbbVmIDMYynxrsbhgbsm6q915k1OnTyxa8fc5Az3-c2zJc3yvOFcwo6z1c9SaRScmeV_U24PqBfWKCknJafv-atv4zkn-ClSZtxdW_JE3mRumib3a7F7gSfany2EhXsp7fOTNgeBg";

    fn load_mock_data(text: &str) -> (String, keys::AccessKeyMap) {
        let payload: serde_json::Value = serde_json::from_str(text).unwrap();
        let key_id = api::extract_latest_key_id(&payload).unwrap();
        let keymap = api::extract_current_keys(&payload).unwrap();

        (key_id, keymap)
    }

    fn get_cache() -> Cache {
        let (latest_key_id, keymap) = load_mock_data(SAMPLE_NEW_PAYLOAD);
        Cache::new(&latest_key_id, keymap)
    }

    fn test_cache(cache: Cache, key_id: &str, token: &str) {
        assert_eq!(cache.get_latest_key_id(), key_id);
        assert!(cache.get_key_ids().contains(key_id));

        let header = jsonwebtoken::decode_header(token).unwrap();
        let header_kid = header.kid.unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.required_spec_claims = HashSet::new();

        assert_eq!(header_kid, key_id);

        let decoding_key = cache.get_decoding_key(&header_kid).unwrap();
        let result =
            jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation);

        assert!(result.is_ok());

        let token = result.unwrap();

        assert_eq!(token.claims.foo.as_str(), "bar");
        assert_eq!(token.claims.bin.as_str(), "baz");
        assert_eq!(token.header.kid.unwrap(), key_id);
    }

    #[test]
    fn test_fresh_cache() {
        let cache = get_cache();
        test_cache(cache, KEY_ID_NEW, TOKEN_NEW);
    }

    #[test]
    fn test_cache_rotation() {
        let cache = get_cache();
        let key_ids = cache.get_key_ids();
        assert!(!cache.is_rotation_needed(key_ids));
        let (latest_key_id, latest_keymap) = load_mock_data(SAMPLE_ROTATION_PAYLOAD);
        let latest_key_ids: HashSet<String> = latest_keymap.keys().cloned().collect();
        assert!(cache.is_rotation_needed(latest_key_ids));
        cache.rotate_keys(&latest_key_id, latest_keymap);
        assert!(!cache.get_key_ids().contains(TOKEN_NEW));
        test_cache(cache, KEY_ID_ROTATE, TOKEN_ROTATE);
    }
}
