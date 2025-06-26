use uuid::Uuid;

pub struct RefreshData {
    pub user_id: Uuid,
    pub token_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
}
