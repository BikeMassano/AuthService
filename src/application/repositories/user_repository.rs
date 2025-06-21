use sea_orm::prelude::async_trait::async_trait;
use sea_orm::{Condition, DbErr};
use sqlx::types::Uuid;

use crate::domain::entities::users::{Column, Entity, Model as UserModel, Model};

#[async_trait]
/// Интерфейс для работы с базой данных пользователей.
///
/// Определяет стандартный асинхронный интерфейс для поиска, создания, обновления и удаления записей пользователей.
/// Все операции выполняются асинхронно и возвращают `Result` с ошибкой базы данных (`DbErr`) при неудаче.
pub trait UserRepository: Send + Sync {
    /// Находит пользователя по имени.
    ///
    /// # Параметры
    /// * `name` - имя пользователя для поиска.
    ///
    /// # Возвращаемое значение
    /// * `Result<UserModel, DbErr>` - модель пользователя при успешном поиске,
    /// либо ошибка базы данных.
    async fn find_by_name(&self, name: &str) -> Result<UserModel, DbErr>;

    /// Находит пользователя по уникальному идентификатору.
    ///
    /// # Параметры
    /// * `id` - UUID пользователя.
    ///
    /// # Возвращаемое значение
    /// * `Result<UserModel, DbErr>` - модель пользователя при успешном поиске,
    async fn find_by_id(&self, id: Uuid) -> Result<UserModel, DbErr>;

    /// Находит пользователя по email.
    ///
    /// # Параметры
    /// * `email` - email пользователя для поиска.
    ///
    /// # Возвращаемое значение
    /// * `Result<UserModel, DbErr>` - модель пользователя при успешном поиске,
    async fn find_by_email(&self, email: &str) -> Result<UserModel, DbErr>;

    /// Возвращает список пользователей с пагинацией.
    ///
    /// # Параметры
    /// * `page` - номер страницы (начиная с 1).
    /// * `page_size` - количество записей на странице.
    ///
    /// # Возвращаемое значение
    /// * `Result<Vec<UserModel>, DbErr>` - вектор моделей пользователей,
    /// либо ошибка базы данных.
    async fn list_users(&self, page: u32, page_size: u32) -> Result<Vec<UserModel>, DbErr>;

    /// Создает нового пользователя.
    ///
    /// # Параметры
    /// * `username` - имя пользователя.
    /// * `email` - email пользователя.
    /// * `password_hash` - хеш пароля пользователя.
    /// * `profile_pic_url` - URL аватара пользователя.
    ///
    /// # Возвращаемое значение
    /// * `Result<(), DbErr>` - Ok(()) при успешном создании,
    /// либо ошибка базы данных.
    async fn create(
        &self,
        username: String,
        email: String,
        password_hash: String,
        profile_pic_url: String,
    ) -> Result<(), DbErr>;

    /// Удаляет пользователя по идентификатору.
    ///
    /// # Параметры
    /// * `id` - UUID пользователя для удаления.
    ///
    /// # Возвращаемое значение
    /// * `Result<(), DbErr>` - Ok(()) при успешном удалении,
    /// либо ошибка базы данных.
    async fn delete_by_id(&self, id: Uuid) -> Result<(), DbErr>;

    /// Обновляет данные пользователя по идентификатору.
    ///
    /// # Параметры
    /// * `id` - UUID пользователя для обновления.
    /// * `user` - модель с новыми данными пользователя.
    ///
    /// # Возвращаемое значение
    /// * `Result<(), DbErr>` - Ok(()) при успешном обновлении,
    /// либо ошибка базы данных.
    async fn update_by_id(&self, id: Uuid, user: UserModel) -> Result<(), DbErr>;

    /// Находит пользователя по email или имени пользователя.
    ///
    /// # Параметры
    /// * `email_or_username` - строка, содержащая email или имя пользователя.
    ///
    /// # Возвращаемое значение
    /// * `Result<UserModel, DbErr>` - модель пользователя при успешном поиске,
    /// либо ошибка базы данных.
    async fn find_by_email_or_username(&self, email_or_username: &str) -> Result<UserModel, DbErr>;
}
