use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;
use crate::application::repositories::token_repository::TokenRepository;
use crate::application::repositories::user_repository::UserRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub jwt_provider: Arc<dyn JwtProvider>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub user_repository: Arc<dyn UserRepository>,
    pub token_repository: Arc<dyn TokenRepository>,
}
