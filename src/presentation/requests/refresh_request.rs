use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub user_id: Uuid,
    pub token_id: Uuid,
}
