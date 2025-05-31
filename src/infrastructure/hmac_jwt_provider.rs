use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::ActiveEnum;
use crate::application::jwt_provider::JwtProvider;
use crate::domain::claims::Claims;
use crate::domain::enums::roles::Role;
use jsonwebtoken::errors::Error as JwtError;

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