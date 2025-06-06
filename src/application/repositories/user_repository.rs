use sea_orm::DbErr;
use sea_orm::prelude::async_trait::async_trait;
use sqlx::types::Uuid;

use crate::domain::entities::users::Model as UserModel;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_name(&self, name: &str) -> Result<UserModel, DbErr>;
    async fn find_by_id(&self, id: Uuid) -> Result<UserModel, DbErr>;
    async fn find_by_email(&self, email: &str) -> Result<UserModel, DbErr>;
    async fn list_users(&self, page: u32, page_size: u32) -> Result<Vec<UserModel>, DbErr>;
    async fn create (&self, username: String, email: String, password_hash: String) -> Result<(), DbErr>; // передать DTO вместо логина
    async fn delete_by_id(&self, id: i32) -> Result<(), DbErr>;
    async fn update_by_id(&self, id: i32, user: UserModel) -> Result<(), DbErr>; // передать DTO вместо логина
}