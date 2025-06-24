use crate::application::services::auth_service::AuthService;
use crate::application::services::user_service::UserService;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
}
