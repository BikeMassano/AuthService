use serde::Serialize;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Serialize)]
pub struct SessionResponse {
    pub token_id: Uuid,
    pub user_agent: String,
    pub ip_address: String,
    pub created_at: DateTime<Utc>,
}