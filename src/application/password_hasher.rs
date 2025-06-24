use argon2::password_hash::Error;
use sea_orm::prelude::async_trait::async_trait;

/// Трейт для безопасного хеширования и верификации паролей.
///
/// Определяет стандартный интерфейс для преобразования паролей в хеши
/// и проверки их соответствия.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Генерирует хеш для заданного пароля.
    ///
    /// # Параметры
    /// * `password`: Пароль в открытом виде, который требуется захешировать.
    ///
    /// # Возвращаемое значение
    /// * `String`, содержащий хеш пароля.
    async fn hash_password(&self, password: &str) -> Result<String, Error>;
    /// Проверяет соответствие переданного пароля его хешу.
    ///
    /// # Параметры
    /// * `password`: Пароль в открытом виде для проверки.
    /// * `password_hash`: Ожидаемый хеш пароля для сравнения.
    ///
    /// # Возвращаемое значение
    /// * `true`, если пароль соответствует хешу, `false` в противном случае.
    async fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, Error>;
}
