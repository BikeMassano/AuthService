use jsonwebtoken::{encode, EncodingKey, Header, errors::Error as JwtError, DecodingKey, Validation, Algorithm};
use sea_orm::ActiveEnum;


use crate::{
    application::jwt_provider::JwtProvider,
    domain::{claims::Claims, enums::roles::Role},
};

pub struct RsaJwtProvider {
    private_secret_key: String,
    public_secret_key: String,
}

impl RsaJwtProvider {
    pub fn new(private_secret_key: String, public_secret_key: String) -> Self {
        Self { private_secret_key, public_secret_key }
    }
}

impl JwtProvider for RsaJwtProvider {
    fn generate_token(&self, username: &str, role: &Role) -> Result<String, JwtError> {
        let claims = Claims {
            sub: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.private_secret_key.as_bytes())?;
        
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims, 
            &encoding_key,)?;
        
        Ok(token)
    }

    fn decode_token(&self, token: &str) -> Result<Claims, JwtError> {
        jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_rsa_pem(self.public_secret_key.as_bytes())?,
            &Validation::new(Algorithm::RS256),
        )
        .map(|data| data.claims)
        .map_err(|e| e.into())
    }
}