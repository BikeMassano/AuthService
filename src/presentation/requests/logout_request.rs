use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub user_id: Uuid,
    pub token_id: Uuid
}