use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token_id: Option<Uuid>,
}
