use sea_orm::entity::prelude::*;
use serde::{Serialize, Deserialize};

use crate::domain::enums::roles::Role;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    #[sea_orm(unique)]
    pub username: String,
    #[serde(skip_deserializing)]
    pub password_hash: String,
    #[sea_orm(unique)]
    pub email: String,
    pub role_id: Role,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
