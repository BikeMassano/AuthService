use sea_orm::prelude::async_trait::async_trait;

use crate::domain::entities::users;

#[async_trait]
pub trait UserRepository {
    async fn find_by_name(&self, name: &str) -> Result<users::Model, sqlx::Error>;
    async fn find_by_id(&self, id: i32) -> Result<users::Model, sqlx::Error>;
    async fn find_by_email(&self, email: &str) -> Result<users::Model, sqlx::Error>;
    async fn list_users(&self, page: u32, page_size: u32) -> Result<Vec<users::Model>, sqlx::Error>;
    async fn create (&self, username: &str) -> Result<(), sqlx::Error>; // передать DTO вместо логина
    async fn delete_by_id(&self, id: i32) -> Result<(), sqlx::Error>;
    async fn update_by_id(&self, id: i32, username: &str) -> Result<(), sqlx::Error>; // передать DTO вместо логина
}