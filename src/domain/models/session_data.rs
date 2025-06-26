use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub token: String,
    pub token_id: Uuid,
    pub expires_at: i64,
    pub issued_at: i64,
    pub user_agent: String,
    pub ip_address: String,
}
