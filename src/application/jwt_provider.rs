use jsonwebtoken::errors::Error as JwtError;

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
    fn generate_token(&self, username: &str, role: &Role) -> Result<String, JwtError>;
}