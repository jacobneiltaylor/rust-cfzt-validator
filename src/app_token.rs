use crate::{
    errors::{UnpackError, UnpackResult},
    unpack, DecodedToken,
};

/// Represents the common claims included in the CFZT JWT
pub struct ApplicationToken {
    pub email: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    pub iss: String,
    pub sub: String,
    pub country: String,
    pub custom: unpack::JsonObject,
    pub headers: jsonwebtoken::Header,
}

impl ApplicationToken {
    // Consumes a `TokenData<Value>` emitted by a successful `Validator.validate_token()`
    // and returns an ApplicationToken struct.
    pub fn from_token_data(token_data: DecodedToken) -> UnpackResult<Self> {
        let claims = unpack::as_object(&token_data.claims)?;

        let get_str_claim = |key: &str| -> UnpackResult<String> {
            Ok(unpack::as_string(unpack::get_key(claims, key)?)?.clone())
        };

        let get_uint_claim = |key: &str| -> UnpackResult<u64> {
            let num = unpack::as_number(unpack::get_key(claims, key)?)?;
            num.as_u64().ok_or(UnpackError::number_parse_failure("u64"))
        };

        let get_obj_claim = |key: &str| -> UnpackResult<unpack::JsonObject> {
            Ok(unpack::as_object(unpack::get_key(claims, key)?)?.to_owned())
        };

        Ok(ApplicationToken {
            email: get_str_claim("email")?,
            exp: get_uint_claim("exp")?,
            iat: get_uint_claim("iat")?,
            nbf: get_uint_claim("nbf")?,
            iss: get_str_claim("iss")?,
            sub: get_str_claim("sub")?,
            country: get_str_claim("country")?,
            custom: get_obj_claim("custom")?,
            headers: token_data.header,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::TeamKeys,
        {TeamValidator, Validator},
    };

    const TEAM_NAME: &str = "molten";
    const AUDIENCE: &str = "41f1d879c797d912d9bd80710db3dce92d30602a2dcbdf7bab33913071c44bd4";
    const APPLICATION_TOKEN_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE1ZWE4YmQxYjk0Y2FkZjJhNWYwZjQ3ZGFkMTg4ZTZhYWZiY2QyOGVlYWIyZTcxYjExZGRkOTZkOWNjMjhjNjkifQ.eyJhdWQiOlsiNDFmMWQ4NzljNzk3ZDkxMmQ5YmQ4MDcxMGRiM2RjZTkyZDMwNjAyYTJkY2JkZjdiYWIzMzkxMzA3MWM0NGJkNCJdLCJlbWFpbCI6Im1lQGphY29idGF5bG9yLmlkLmF1IiwiZXhwIjoxNzE3OTgxNDM5LCJpYXQiOjE3MTc5Nzk2MzksIm5iZiI6MTcxNzk3OTYzOSwiaXNzIjoiaHR0cHM6Ly9tb2x0ZW4uY2xvdWRmbGFyZWFjY2Vzcy5jb20iLCJ0eXBlIjoiYXBwIiwiaWRlbnRpdHlfbm9uY2UiOiJBUFhHRnFsT2k5OVNsVVF3Iiwic3ViIjoiNzIwOGVlYTQtNDA5OC01YTMxLTkwNTMtZjA5YjgxYzI4MWZkIiwiY3VzdG9tIjp7ImVtYWlsIjoiIn0sImNvdW50cnkiOiJBVSJ9.nwTTyb2ioh5Fw39zKyBMZJuj0wzxOuP2KxsbzDLQCmOBNekTvhmquAui3bmuwpzhTTfjxP9yAJG1_N0Hmc-h613E8jOQclqAVgr9_JEYPZ2v58exPRgjeokEIQweRYKgLgoqHAqaYTKQ4v8-pHeRL66L-2Ui3uVUi8V8PkeJogKfPHvFjnkCqZPFFpuxkW735x0Vxq5CzQesoHH37hLAJe7ckc4Jav1AholNsLOvlBIxZtC9ET8-3YqO5rOUCqSX_6oKmf0VyOmqzbSw4gaXvnaTBAPiGruU63gg_LsV0NVGeVvddy84Tl3WvQvbPwdCJ9W9KsbkyOryfgbL0lrZPA";
    const SIGNING_KEYS_JSON: &str = include_str!("../test_data/sample_signing_keys.json");

    fn get_validator() -> Box<dyn Validator> {
        let keys = TeamKeys::from_str(TEAM_NAME, SIGNING_KEYS_JSON).unwrap();
        let validator = TeamValidator::from_team_keys(keys, AUDIENCE);
        Box::new(validator)
    }

    #[test]
    fn test_application_token() {
        let mut validator = get_validator();

        let mut constraints = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        constraints.validate_nbf = false;
        constraints.validate_exp = false;

        let result = validator.validate_token(APPLICATION_TOKEN_JWT, TEAM_NAME, &mut constraints);
        assert!(result.is_ok());

        let app_token = ApplicationToken::from_token_data(result.unwrap()).unwrap();

        assert_eq!(app_token.exp, 1717981439);
        assert_eq!(app_token.iat, 1717979639);
        assert_eq!(app_token.nbf, 1717979639);
        assert_eq!(app_token.iss, "https://molten.cloudflareaccess.com");
        assert_eq!(app_token.sub, "7208eea4-4098-5a31-9053-f09b81c281fd");
        assert_eq!(app_token.country, "AU")
    }
}
