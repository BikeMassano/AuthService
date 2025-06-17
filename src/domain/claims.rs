use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::domain::enums::token_type::TokenType;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub name: String,
    pub role: String,
    pub exp: i64,
    pub token_type: TokenType,
    pub iat: i64,
    pub iss: String,
    pub jti: Option<String>
}