use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, QueryFilter, QueryOrder, QuerySelect, Set};
use sea_orm::prelude::async_trait::async_trait;
use uuid::Uuid;

use crate::application::repositories::user_repository::UserRepository;
use crate::domain::entities::users::{Model as UserModel, Entity as UserEntity, Column as UserColumn, ActiveModel as UserActiveModel};
use crate::domain::enums::roles::Role;

pub struct PostgresUserRepository {
    db: DatabaseConnection
}

impl PostgresUserRepository {
    pub fn new(db: DatabaseConnection) -> Self { Self { db } }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_name(&self, name: &str) -> Result<UserModel, DbErr> {
        let user = UserEntity::find()
            .filter(UserColumn::Username.eq(name))
            .one(&self.db)
            .await?;

        user.ok_or(DbErr::RecordNotFound(String::from("User not found")))
    }
    async fn find_by_id(&self, id: Uuid) -> Result<UserModel, DbErr> {
        let user = UserEntity::find_by_id(id)
            .one(&self.db)
            .await?;

        user.ok_or(DbErr::RecordNotFound(format!("User {} not found", id)))
    }

    async fn find_by_email(&self, email: &str) -> Result<UserModel, DbErr> {
        let user = UserEntity::find()
            .filter(UserColumn::Email.eq(email))
            .one(&self.db)
            .await?;

        user.ok_or(DbErr::RecordNotFound(String::from("User not found")))
    }

    async fn list_users(&self, page: u32, page_size: u32) -> Result<Vec<UserModel>, DbErr> {
        let users = UserEntity::find()
            .order_by_asc(UserColumn::UserId)
            .limit(page_size as u64)
            .offset((page.saturating_sub(1) * page_size) as u64)
            .all(&self.db)
            .await?;

        Ok(users)
    }

    async fn create(&self, username: String, email: String, password_hash: String) -> Result<(), DbErr> {
        let user = UserActiveModel {
            user_id: Set(Uuid::new_v4()),
            username: Set(username),
            password_hash: Set(password_hash),
            email: Set(email),
            role: Set(Role::USER),
        };

        match user.insert(&self.db).await {
            Ok(_) => Ok(()),
            Err(err) => {
                eprintln!("Insert failed {err}");
                Err(err)
            }
        }
    }

    async fn delete_by_id(&self, id: Uuid) -> Result<(), DbErr> {
        UserEntity::delete_by_id(id)
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn update_by_id(&self, id: Uuid, user: UserModel) -> Result<(), DbErr> {
        // Ищем пользователя
        let existing_user = UserEntity::find_by_id(id)
            .one(&self.db)
            .await?
            .ok_or(DbErr::RecordNotFound(format!("User {} not found", id)))?;

        // Преобразовываем в отслеживаемую модель
        let mut active_user: UserActiveModel = existing_user.into();

        // Изменяем поля изменяемой модели
        if active_user.username.as_ref() != &user.username {
            active_user.username = Set(user.username);
        }
        if active_user.email.as_ref() != &user.email {
            active_user.email = Set(user.email);
        }
        if active_user.password_hash.as_ref() != &user.password_hash {
            active_user.password_hash = Set(user.password_hash);
        }
        if active_user.role.as_ref() != &user.role {
            active_user.role = Set(user.role);
        }

        active_user.update(&self.db).await?;
        
        Ok(())
    }
}