use sea_orm::{DeriveActiveEnum, EnumIter, prelude::StringLen};

#[derive(Clone, Debug, PartialEq, EnumIter, DeriveActiveEnum, Eq)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(50))")]
pub enum Role {
    #[sea_orm(string_value = "Admin")]
    ADMIN,
    #[sea_orm(string_value = "User")]
    USER,
    #[sea_orm(string_value = "Guest")]
    GUEST
}