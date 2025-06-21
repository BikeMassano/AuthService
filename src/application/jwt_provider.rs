use crate::domain::claims::Claims;
use crate::domain::enums::roles::Role;
use jsonwebtoken::errors::Error as JwtError;
use uuid::Uuid;

/// Трейт для работы с Json Web Tokens (JWT)
///
/// Определяет стандартный интерфейс для генерации и верификации Json Web Tokens,
/// включая access и refresh токены
pub trait JwtProvider: Send + Sync {
    /// Генерирует JWT access токен на основе данных пользователя
    ///
    /// # Параметры
    ///
    /// * `username` — имя пользователя, для которого создаётся токен.
    /// * `role` — роль пользователя, которая будет зашита в токен.
    /// * `id` — уникальный идентификатор пользователя (UUID).
    /// # Возвращаемое значение
    /// * `Result` сгенерированный JWT access токен в виде строки в случае успеха,
    /// либо ошибка типа `JwtError` при неудаче.
    fn generate_access_token(
        &self,
        username: &str,
        id: &Uuid,
        role: &Role,
    ) -> Result<String, JwtError>;
    /// Проверяет и декодирует JWT access токен.
    ///
    /// # Параметры
    ///
    /// * `token` — JWT access токен в виде строки.
    ///
    /// # Возвращаемое значение
    /// * `Result` с Claims токена в случае успеха,
    /// либо ошибка типа `JwtError` при неудаче.
    fn verify_access_token(&self, token: &str) -> Result<Claims, JwtError>;
    /// Генерирует JWT refresh токен на основе данных пользователя
    ///
    /// # Параметры
    ///
    /// * `username` — имя пользователя, для которого создаётся токен.
    /// * `role` — роль пользователя, которая будет зашита в токен.
    /// * `id` — уникальный идентификатор пользователя (UUID).
    /// # Возвращаемое значение
    /// * `Result` сгенерированный JWT refresh токен в виде строки в случае успеха,
    /// либо ошибка типа `JwtError` при неудаче.
    fn generate_refresh_token(
        &self,
        username: &str,
        id: &Uuid,
        role: &Role,
    ) -> Result<String, JwtError>;
    /// Проверяет и декодирует JWT refresh токен.
    ///
    /// # Параметры
    ///
    /// * `token` — JWT refresh токен в виде строки.
    ///
    /// # Возвращаемое значение
    /// * `Result` с Claims токена в случае успеха,
    /// либо ошибка типа `JwtError` при неудаче.
    fn verify_refresh_token(&self, token: &str) -> Result<Claims, JwtError>;
}
