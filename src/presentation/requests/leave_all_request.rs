use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LeaveAllRequest {
    pub user_id: Uuid,
}
