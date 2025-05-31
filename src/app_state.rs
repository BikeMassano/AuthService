use std::sync::Arc;
use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;

#[derive(Clone)]
pub struct AppState {
    pub jwt_provider: Arc<dyn JwtProvider>,
    pub password_hasher: Arc<dyn PasswordHasher>,
}