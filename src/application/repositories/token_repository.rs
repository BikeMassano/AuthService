use crate::domain::models::session_data::SessionData;
use chrono::Duration;
use sea_orm::prelude::async_trait::async_trait;
use std::error::Error;
use uuid::Uuid;

#[async_trait]
/// Трейт для работы с базой данных refresh токенов.
///
/// Определяет стандартный асинхронный интерфейс для управления refresh токенами,
/// включая сохранение, поиск и удаление токенов.
pub trait TokenRepository: Send + Sync {
    /// Сохраняет refresh токен для указанного пользователя.
    ///
    /// # Параметры
    ///
    /// * `user_id` - уникальный идентификатор пользователя (UUID).
    /// * `token` - идентификатор refresh токена (UUID).
    /// * `expires_in` - продолжительность жизни токена.
    ///
    /// # Возвращаемое значение
    /// * `Result<(), Box<dyn Error>>` - Ok(()) в случае успешного сохранения,
    /// либо ошибка в случае неудачи.
    async fn save_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
        token: &str,
        expires_in: Duration,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<(), Box<dyn Error>>;
    /// Проверяет существование refresh токена для пользователя с указанным id.
    ///
    /// # Параметры
    ///
    /// * `user_id` - уникальный идентификатор пользователя (UUID).
    /// * `token_id` - идентификатор refresh токена (строка).
    ///
    /// # Возвращаемое значение
    /// * `Result<bool, Box<dyn Error>>` - true если токен существует,
    /// false если не существует, либо ошибка в случае неудачи.
    async fn find_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
    ) -> Result<SessionData, Box<dyn Error>>;
    /// Удаляет refresh токен по id для пользователя с указанным id.
    ///
    /// # Параметры
    ///
    /// * `user_id` - уникальный идентификатор пользователя (UUID).
    /// * `token_id` - идентификатор refresh токена (строка).
    ///
    /// # Возвращаемое значение
    /// * `Result<(), Box<dyn Error>>` - Ok() если токен удалён,
    /// либо ошибка в случае неудачи.
    async fn delete_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
    ) -> Result<(), Box<dyn Error>>;
    /// Удаляет все refresh токены для пользователя с указанным id.
    ///
    /// # Параметры
    ///
    /// * `user_id` - уникальный идентификатор пользователя (UUID).
    ///
    /// # Возвращаемое значение
    /// * `Result<(), Box<dyn Error>>` - Ok() если токены удалён,
    /// либо ошибка в случае неудачи.
    async fn delete_all_refresh_tokens(&self, user_id: &Uuid) -> Result<(), Box<dyn Error>>;

    async fn find_user_refresh_tokens(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<SessionData>, Box<dyn Error>>;
}
