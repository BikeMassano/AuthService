use crate::domain::enums::roles::Role;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct UserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub profile_pic_url: Option<String>,
}
