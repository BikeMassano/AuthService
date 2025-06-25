use serde::Deserialize;

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub profile_pic_url: Option<String>,
}
