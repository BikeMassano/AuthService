use sea_orm::DatabaseConnection;
use sea_orm::prelude::async_trait::async_trait;
use sqlx::Error;
use crate::application::repositories::user_repository::UserRepository;
use crate::domain::entities::users::Model;

pub struct PostgresUserRepository {
    db: DatabaseConnection
}

impl PostgresUserRepository {
    pub fn new(db: DatabaseConnection) -> Self { Self { db } }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_name(&self, name: &str) -> Result<Model, Error> {
        todo!()
    }

    async fn find_by_id(&self, id: i32) -> Result<Model, Error> {
        todo!()
    }

    async fn find_by_email(&self, email: &str) -> Result<Model, Error> {
        todo!()
    }

    async fn list_users(&self, page: u32, page_size: u32) -> Result<Vec<Model>, Error> {
        todo!()
    }

    async fn create(&self, username: &str) -> Result<(), Error> {
        todo!()
    }

    async fn delete_by_id(&self, id: i32) -> Result<(), Error> {
        todo!()
    }

    async fn update_by_id(&self, id: i32, username: &str) -> Result<(), Error> {
        todo!()
    }
}