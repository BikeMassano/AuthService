use jsonwebtoken::{encode, EncodingKey, Header, errors::Error as JwtError, DecodingKey, Validation};
use sea_orm::ActiveEnum;


use crate::{
    application::jwt_provider::JwtProvider,
    domain::{claims::Claims, enums::roles::Role},
};

pub struct HmacJwtProvider {
    secret_key: String,
}

impl HmacJwtProvider {
    pub fn new(secret_key: String) -> Self { Self { secret_key } }
}

impl JwtProvider for HmacJwtProvider {
    fn generate_token(&self, username: &str, role: &Role) -> Result<String, JwtError> {
        let claims = Claims {
            sub: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };
        
        let token = encode(
            &Header::default(),
            &claims, 
            &EncodingKey::from_secret(self.secret_key.as_bytes(),
        ))?;
        
        Ok(token)
    }

    fn decode_token(&self, token: &str) -> Result<Claims, JwtError> {
        jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret_key.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| e.into())
    }
}