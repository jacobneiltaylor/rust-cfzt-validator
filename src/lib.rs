use std::error::Error;

pub mod api;
pub mod app_token;
pub mod cache;
pub(crate) mod errors;
pub mod keys;
pub(crate) mod unpack;

pub type StdResult<T> = Result<T, Box<dyn Error>>;

use std::collections::{HashMap, HashSet};

use crate::{
    cache::Cache,
    errors::{ValidationError, ValidationResult},
};

use jsonwebtoken::{self, TokenData};

pub type DecodedToken = TokenData<serde_json::Value>;

type TeamCache = HashMap<String, TeamValidator>;
type Constraints = jsonwebtoken::Validation;

fn decode_token_header(token: &str) -> ValidationResult<jsonwebtoken::Header> {
    match jsonwebtoken::decode_header(token) {
        Ok(hdr) => Ok(hdr),
        Err(_) => Err(ValidationError::header_decode_failure()),
    }
}

fn decode_token(
    token: &str,
    key: &jsonwebtoken::DecodingKey,
    constraints: &Constraints,
) -> ValidationResult<DecodedToken> {
    match jsonwebtoken::decode::<serde_json::Value>(token, key, constraints) {
        Ok(token_data) => Ok(token_data),
        Err(_) => Err(ValidationError::invalid_jwt()),
    }
}

fn get_kid(header: jsonwebtoken::Header) -> ValidationResult<String> {
    Ok(header.kid.ok_or(ValidationError::header_missing_kid())?)
}

/// The interface for a component capable of validating a CFZT JWT.
pub trait Validator: Sync + Send {
    /// Takes a JWT, team name, and a mutable set of constraints 
    /// and validates a JWT accordingly.
    fn validate_token(
        &self,
        token: &str,
        team_name: &str,
        constraints: &mut Constraints,
    ) -> ValidationResult<DecodedToken>;

    // A hook to trigger the validator to perform syncronisation
    // with the Cloudflare Access API
    fn sync(&self) -> StdResult<bool>;
}

/// Represents a Validator implementation capable of 
/// validating tokens associated with a single CFZT team.
pub struct TeamValidator {
    pub(crate) team_name: String,
    cache: cache::Cache,
}


impl TeamValidator {
    /// Initialises a TeamValidator from a team name, Cache struct and an audience.
    pub fn new(team_name: &str, cache: Cache) -> Self {
        TeamValidator {
            team_name: team_name.to_string(),
            cache,
        }
    }

    /// Initialises a TeamValidator from an existing TeamKeys struct.
    pub fn from_team_keys(team_keys: api::TeamKeys) -> Self {
        let cache = cache::Cache::new(&team_keys.latest_key_id, team_keys.keys);
        Self::new(&team_keys.team_name, cache)
    }

    /// Atttempts to initialise a TeamValidator using a team name.
    /// Keys are retrieved from the CF API.
    pub fn from_team_name(team_name: &str) -> StdResult<Self> {
        let team_keys = api::TeamKeys::from_team_name(&team_name)?;
        let cache = cache::Cache::new(&team_keys.latest_key_id, team_keys.keys);
        Ok(Self::new(team_name, cache))
    }

    /// Attempts to syncronise the TeamValidator's cached keys with
    /// a provided TeamKeys struct. Returns a bool signalling
    /// if an update was necessary.
    pub fn update_keys(&self, team_keys: api::TeamKeys) -> bool {
        let key_ids: HashSet<String> = team_keys.keys.keys().cloned().collect();
        let rotate = self.cache.is_rotation_needed(key_ids);

        if rotate {
            self.cache
                .rotate_keys(&team_keys.latest_key_id, team_keys.keys);
        }

        rotate
    }
}

impl Validator for TeamValidator {
    /// Attempts to validate a token against the CFZT Team associated with the TeamValidator.
    fn validate_token(
        &self,
        token: &str,
        team_name: &str,
        constraints: &mut Constraints,
    ) -> ValidationResult<DecodedToken> {
        if team_name != self.team_name {
            return Err(ValidationError::team_name_mismatch(
                team_name,
                self.team_name.as_str(),
            ))?;
        }

        let header = decode_token_header(token)?;
        let key_id = get_kid(header)?;

        match self.cache.get_decoding_key(&key_id) {
            Some(key) => {
                Ok(decode_token(token, &key, &constraints)?)
            }
            None => Err(ValidationError::no_kid_in_cache(&key_id)),
        }
    }

    /// Attempts to syncronise the TeamValidator's cached keys with
    /// those available via the Cloudflare API. Returns a wrapped bool signalling
    /// if an update was necessary.
    fn sync(&self) -> StdResult<bool> {
        let team_keys = api::TeamKeys::from_team_name(&self.team_name)?;
        Ok(self.update_keys(team_keys))
    }
}

/// Represents a Validator implementation capable of 
/// validating tokens associated with many CFZT teams.
pub struct MultiTeamValidator {
    teams: TeamCache,
}

impl Default for MultiTeamValidator {
    fn default() -> Self {
        MultiTeamValidator {
            teams: HashMap::new(),
        }
    }
}

impl MultiTeamValidator {
    /// Adds a single TeamValidator into the MultiTeamValidator TeamCache.
    pub fn add_team(&mut self, team_validator: TeamValidator) -> StdResult<()> {
        self.teams
            .insert(team_validator.team_name.clone(), team_validator);
        Ok(())
    }

    fn get_team_validator(&self, team_name: &str) -> ValidationResult<&TeamValidator> {
        self.teams
            .get(team_name)
            .ok_or(ValidationError::unknown_team_name(team_name))
    }

    /// Attempts to syncronise a team added to the MultiTeamValidator with
    /// those available via the CF API. Returns a wrapped bool signalling
    /// if an update was necessary.
    pub fn sync_team(&self, team_name: &str) -> StdResult<bool> {
        let team = self.get_team_validator(team_name)?;
        team.sync()
    }

    pub fn get_team_names(&self) -> Vec<String> {
        self.teams.keys().into_iter().map(|x| x.to_string()).collect()
    }
}

impl Validator for MultiTeamValidator {
    /// Attempts to validate a token against a CFZT Team associated with the MultiTeamValidator.
    fn validate_token(
        &self,
        token: &str,
        team_name: &str,
        constraints: &mut Constraints,
    ) -> ValidationResult<DecodedToken> {
        let team = self.get_team_validator(team_name)?;
        team.validate_token(token, team_name, constraints)
    }

    fn sync(&self) -> StdResult<bool> {
        let mut retval = false;

        for team_name in self.teams.keys().into_iter() {
            retval = self.sync_team(team_name)? || retval
        }

        Ok(retval)
    }
}

#[cfg(test)]
mod tests {
    use api::TeamKeys;

    use super::*;

    const TEAM_NAME: &str = "molten";
    const AUDIENCE: &str = "41f1d879c797d912d9bd80710db3dce92d30602a2dcbdf7bab33913071c44bd4";
    const STATIC_KEYS: &str = include_str!("../test_data/sample_signing_keys.json");
    const JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE1ZWE4YmQxYjk0Y2FkZjJhNWYwZjQ3ZGFkMTg4ZTZhYWZiY2QyOGVlYWIyZTcxYjExZGRkOTZkOWNjMjhjNjkifQ.eyJhdWQiOlsiNDFmMWQ4NzljNzk3ZDkxMmQ5YmQ4MDcxMGRiM2RjZTkyZDMwNjAyYTJkY2JkZjdiYWIzMzkxMzA3MWM0NGJkNCJdLCJlbWFpbCI6Im1lQGphY29idGF5bG9yLmlkLmF1IiwiZXhwIjoxNzE3OTgxNDM5LCJpYXQiOjE3MTc5Nzk2MzksIm5iZiI6MTcxNzk3OTYzOSwiaXNzIjoiaHR0cHM6Ly9tb2x0ZW4uY2xvdWRmbGFyZWFjY2Vzcy5jb20iLCJ0eXBlIjoiYXBwIiwiaWRlbnRpdHlfbm9uY2UiOiJBUFhHRnFsT2k5OVNsVVF3Iiwic3ViIjoiNzIwOGVlYTQtNDA5OC01YTMxLTkwNTMtZjA5YjgxYzI4MWZkIiwiY3VzdG9tIjp7ImVtYWlsIjoiIn0sImNvdW50cnkiOiJBVSJ9.nwTTyb2ioh5Fw39zKyBMZJuj0wzxOuP2KxsbzDLQCmOBNekTvhmquAui3bmuwpzhTTfjxP9yAJG1_N0Hmc-h613E8jOQclqAVgr9_JEYPZ2v58exPRgjeokEIQweRYKgLgoqHAqaYTKQ4v8-pHeRL66L-2Ui3uVUi8V8PkeJogKfPHvFjnkCqZPFFpuxkW735x0Vxq5CzQesoHH37hLAJe7ckc4Jav1AholNsLOvlBIxZtC9ET8-3YqO5rOUCqSX_6oKmf0VyOmqzbSw4gaXvnaTBAPiGruU63gg_LsV0NVGeVvddy84Tl3WvQvbPwdCJ9W9KsbkyOryfgbL0lrZPA";

    fn get_team_validator() -> TeamValidator {
        let team_keys = TeamKeys::from_str(TEAM_NAME, STATIC_KEYS).unwrap();
        TeamValidator::from_team_keys(team_keys)
    }

    fn get_multi_team_validator() -> MultiTeamValidator {
        let mut validator = MultiTeamValidator::default();
        validator.add_team(get_team_validator()).unwrap();
        validator
    }

    fn get_constraints() -> Constraints {
        let mut constraints = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        constraints.validate_nbf = false;
        constraints.validate_exp = false;
        constraints.set_audience(&[AUDIENCE]);
        constraints
    }

    #[test]
    fn test_team_validator_sync() {
        let validator = get_team_validator();
        let result = validator.sync();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_multi_team_validator_team_sync() {
        let validator = get_multi_team_validator();
        let result = validator.sync_team(TEAM_NAME);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_team_validator_validate_token() {
        let validator = get_team_validator();
        let mut constraints = get_constraints();
        let result = validator.validate_token(JWT, TEAM_NAME, &mut constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multi_team_validator_validate_token() {
        let validator = get_multi_team_validator();
        let mut constraints = get_constraints();
        let result = validator.validate_token(JWT, TEAM_NAME, &mut constraints);
        assert!(result.is_ok());
    }
}
