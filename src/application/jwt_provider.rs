use jsonwebtoken::errors::Error as JwtError;
use uuid::Uuid;
use crate::domain::claims::Claims;
use crate::domain::enums::roles::Role;
/// Интерфейс для создания Json Web Tokens
///
/// Этот трейт предоставляет методы генерации Json Web Tokens.
pub trait JwtProvider: Send + Sync {
    /// Генерирует JWT на основе имени пользователя и роли.
    ///
    /// # Параметры
    ///
    /// * `username` — имя пользователя, для которого создаётся токен.
    /// * `role` — роль пользователя, которая будет зашита в токен.
    /// # Возвращаемое значение
    /// * `Result` со строкой, содержащей сгенерированный JWT в случае успеха,
    /// либо ошибку типа `JwtError` при неудаче.
    fn generate_access_token(&self, username: &str, id: &Uuid, role: &Role) -> Result<String, JwtError>;
    fn verify_access_token(&self, token: &str) -> Result<Claims, JwtError>;
    fn generate_refresh_token(&self, username: &str, id: &Uuid, role: &Role) -> Result<String, JwtError>;
    fn verify_refresh_token(&self, token: &str) -> Result<Claims, JwtError>;
}