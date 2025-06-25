use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub token: String,
    pub expires_at: i64,
    pub issued_at: i64,
}
