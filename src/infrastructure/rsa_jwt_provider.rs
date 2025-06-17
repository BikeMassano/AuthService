use jsonwebtoken::{encode, EncodingKey, Header, errors::Error as JwtError, DecodingKey, Validation, Algorithm};
use jsonwebtoken::errors::ErrorKind;
use sea_orm::{ActiveEnum, Iden};
use uuid::Uuid;
use crate::{
    application::jwt_provider::JwtProvider,
    domain::{claims::Claims, enums::roles::Role},
};
use crate::domain::enums::token_type::TokenType;

pub struct RsaJwtProvider {
    private_secret_key: String,
    public_secret_key: String,
    issuer: String,
    access_token_exp: i64,
    refresh_token_exp: i64
}

impl RsaJwtProvider {
    pub fn new(private_secret_key: String, public_secret_key: String, issuer: String, access_token_exp: i64, refresh_token_exp: i64) -> Self {
        Self { private_secret_key, public_secret_key, issuer, access_token_exp, refresh_token_exp }
    }
}

impl JwtProvider for RsaJwtProvider {
    fn generate_access_token(&self, username: &str, id: &Uuid, role: &Role) -> Result<String, JwtError> {
        let claims = Claims {
            sub: id.to_owned(),
            name: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(self.access_token_exp)).timestamp(),
            token_type: TokenType::Access,
            iss: self.issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            jti: None,
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.private_secret_key.as_bytes())
            .map_err(JwtError::from)?;
        
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims, 
            &encoding_key,)?;
        
        Ok(token)
    }

    fn verify_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 3;
        validation.set_required_spec_claims(&["exp", "iss", "sub", "token_type"]);
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_rsa_pem(self.public_secret_key.as_bytes())
                .map_err(JwtError::from)?,
            &validation,
        )?;

        if token_data.claims.token_type != TokenType::Access {
            return Err(JwtError::from(ErrorKind::InvalidToken));
        }

        Ok(token_data.claims)
    }

    fn generate_refresh_token(&self, username: &str, id: &Uuid, role: &Role) -> Result<String, JwtError> {
        let claims = Claims {
            sub: id.to_owned(),
            name: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::days(self.refresh_token_exp)).timestamp(),
            token_type: TokenType::Refresh,
            iss: self.issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            jti: Some(Uuid::new_v4().to_string())
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.private_secret_key.as_bytes())
            .map_err(JwtError::from)?;

        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &encoding_key,
        )?;

        Ok(token)
    }

    fn verify_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 3;
        validation.set_required_spec_claims(&["exp", "iss", "sub", "token_type"]);
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<Claims>(
            token,
            &DecodingKey::from_rsa_pem(self.public_secret_key.as_bytes())
                .map_err(JwtError::from)?,
            &validation,
        )?;

        // Проверяем, что это именно refresh-токен
        if token_data.claims.token_type != TokenType::Refresh {
            return Err(JwtError::from(ErrorKind::InvalidToken));
        }

        Ok(token_data.claims)
    }
}