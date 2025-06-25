use crate::domain::claims::Claims;

#[derive(Debug)]
pub struct TokenData {
    pub token: String,
    pub claims: Claims,
}