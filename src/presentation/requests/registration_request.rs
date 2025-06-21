use serde::Deserialize;

#[derive(Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub profile_pic_url: Option<String>,
}