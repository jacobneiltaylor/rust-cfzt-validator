use std::{error::Error, fmt};

pub type UnpackResult<T> = Result<T, UnpackError>;
pub type ValidationResult<T> = Result<T, ValidationError>;

#[derive(Debug)]
pub struct UnpackError {
    message: String,
}

impl UnpackError {
    pub fn unmarshal(expect: &str) -> Self {
        UnpackError {
            message: format!("error when attempting to unmarshal json value as {expect}"),
        }
    }

    pub fn missing_key(key: &str) -> Self {
        UnpackError {
            message: format!("key '{key}' not found when attempting to extract value from object"),
        }
    }

    pub fn empty_container(expect: &str) -> Self {
        UnpackError {
            message: format!("attempted to unpack empty {expect}"),
        }
    }

    pub fn number_parse_failure(expect: &str) -> Self {
        UnpackError {
            message: format!("failed parsing json number as {expect}"),
        }
    }
}

impl Error for UnpackError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UnpackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unpack fail: {}", self.message)
    }
}

#[derive(Debug)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    pub fn team_name_mismatch(expect: &str, actual: &str) -> Self {
        ValidationError {
            message: format!(
                "provided team name '{actual}' does not match validator team name '{expect}'"
            ),
        }
    }

    pub fn unknown_team_name(expect: &str) -> Self {
        ValidationError {
            message: format!("team name '{expect}' not found"),
        }
    }

    pub fn header_missing_kid() -> Self {
        ValidationError {
            message: "no kid in jwt header".to_string(),
        }
    }

    pub fn no_kid_in_cache(expect: &str) -> Self {
        ValidationError {
            message: format!("kid '{expect}' not found in cache"),
        }
    }

    pub fn header_decode_failure() -> Self {
        ValidationError {
            message: "failed to decode jwt header".to_string(),
        }
    }

    pub fn invalid_jwt() -> Self {
        ValidationError {
            message: "jwt is not valid".to_string(),
        }
    }
}

impl Error for ValidationError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "validation fail: {}", self.message)
    }
}
