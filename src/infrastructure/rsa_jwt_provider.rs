use crate::domain::enums::token_type::TokenType;
use crate::domain::models::token_data::TokenData;
use crate::{
    application::jwt_provider::JwtProvider,
    domain::{claims::Claims, enums::roles::Role},
};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, encode, errors::Error as JwtError,
};
use sea_orm::ActiveEnum;
use uuid::Uuid;

pub struct RsaJwtProvider {
    decoding_key: DecodingKey,
    encoding_key: EncodingKey,
    issuer: String,
    access_token_exp: i64,
    refresh_token_exp: i64,
}

impl RsaJwtProvider {
    pub fn new(
        private_key_pem: &str,
        public_key_pem: &str,
        issuer: String,
        access_token_exp: i64,
        refresh_token_exp: i64,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        Ok(Self {
            decoding_key: DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?,
            encoding_key: EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?,
            issuer,
            access_token_exp,
            refresh_token_exp,
        })
    }
}

impl JwtProvider for RsaJwtProvider {
    fn generate_access_token(
        &self,
        username: &str,
        id: &Uuid,
        role: &Role,
    ) -> Result<TokenData, JwtError> {
        // Заполняем данные для токена
        let claims = Claims {
            sub: id.to_owned(),
            name: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(self.access_token_exp))
                .timestamp(),
            token_type: TokenType::Access,
            iss: self.issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::new_v4(),
        };
        // Создаём токен
        let token = encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)?;
        // Возвращаем токен
        let token_data = TokenData { token, claims };
        Ok(token_data)
    }

    fn verify_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        // Настройки валидации токена
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 3;
        validation.set_required_spec_claims(&["exp", "iss", "sub", "token_type"]);
        validation.validate_exp = true;
        // Декодируем токен, получаем Claims
        let token_data = jsonwebtoken::decode::<Claims>(token, &self.decoding_key, &validation)?;
        // Проверяем, что это access-токен
        if token_data.claims.token_type != TokenType::Access {
            return Err(JwtError::from(ErrorKind::InvalidToken));
        }
        // Возвращаем Claims из токена
        Ok(token_data.claims)
    }

    fn generate_refresh_token(
        &self,
        username: &str,
        id: &Uuid,
        role: &Role,
    ) -> Result<TokenData, JwtError> {
        // Заполняем данные для токена
        let claims = Claims {
            sub: id.to_owned(),
            name: username.to_owned(),
            role: role.to_value(),
            exp: (chrono::Utc::now() + chrono::Duration::days(self.refresh_token_exp)).timestamp(),
            token_type: TokenType::Refresh,
            iss: self.issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::new_v4(),
        };
        // Создаём токен
        let token = encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)?;
        // Возвращаем токен
        let token_data = TokenData { token, claims };
        Ok(token_data)
    }

    fn verify_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        // Настройки валидации токена
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 3;
        validation.set_required_spec_claims(&["exp", "iss", "sub", "token_type"]);
        validation.validate_exp = true;
        // Декодируем токен, получаем Claims
        let token_data = jsonwebtoken::decode::<Claims>(token, &self.decoding_key, &validation)?;
        // Проверяем, что это refresh-токен
        if token_data.claims.token_type != TokenType::Refresh {
            return Err(JwtError::from(ErrorKind::InvalidToken));
        }
        // Возвращаем Claims из токена
        Ok(token_data.claims)
    }
}
