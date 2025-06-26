use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LogoutAllRequest {
    pub user_id: Uuid,
}
