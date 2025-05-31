use jsonwebtoken::{encode, EncodingKey, Header, errors::Error as JwtError};
use sea_orm::ActiveEnum;


use crate::{
    application::jwt_provider::JwtProvider,
    domain::{claims::Claims, enums::roles::Role},
};

pub struct HmacJwtProvider;

impl JwtProvider for HmacJwtProvider {
    fn generate_token(&self, username: &str, role: &Role) -> Result<String, JwtError> {
        let claims = Claims {
            sub: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };

        // вынести секретный ключ!
        let token = encode(
            &Header::default(), 
            &claims, 
            &EncodingKey::from_secret("secret".as_ref()))?;
        
        Ok(token)
    }
}