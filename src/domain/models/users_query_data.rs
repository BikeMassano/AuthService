use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UserQueryParams {
    pub(crate) page: u32,
    pub(crate) page_size: u32,
    pub(crate) search: Option<String>,
}
