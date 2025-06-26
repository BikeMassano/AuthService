use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;
use crate::application::repositories::token_repository::TokenRepository;
use crate::application::repositories::user_repository::UserRepository;
use crate::application::services::auth_service::AuthError::{
    InvalidCredentials, TokenError, UserAlreadyExists
};
use crate::domain::entities::users::Model as UserModel;
use crate::domain::models::login_data::LoginData;
use crate::domain::models::refresh_data::RefreshData;
use crate::domain::models::registration_data::RegistrationData;
use argon2::password_hash::Error;
use chrono::Duration;
use sea_orm::DbErr;
use std::sync::Arc;
use uuid::Uuid;
use crate::domain::models::session_data::SessionData;

pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    token_repo: Arc<dyn TokenRepository>,
    jwt_provider: Arc<dyn JwtProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl AuthService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        token_repo: Arc<dyn TokenRepository>,
        jwt_provider: Arc<dyn JwtProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            user_repo,
            token_repo,
            jwt_provider,
            password_hasher,
        }
    }

    pub async fn register(&self, registration_data: RegistrationData) -> Result<String, AuthError> {
        // Данные для регистрации
        let username = registration_data.username;
        let email = registration_data.email;
        let profile_pic_url = registration_data.profile_pic_url;

        // Таски для проверки существования пользователей в бд
        let username_check = self.user_repo.find_by_name(&username);
        let email_check = self.user_repo.find_by_email(&email);
        // Запуск тасок
        let (username_result, email_result) = tokio::join!(username_check, email_check);
        // Если нашли пользователя, то выбрасываем ошибку
        if username_result.is_ok() || email_result.is_ok() {
            return Err(UserAlreadyExists);
        }
        
        // Хешируем пароль пользователя
        let password = registration_data.password;
        let password_hasher = &self.password_hasher;

        let password_hash = password_hasher.hash_password(&password).await?;

        // Заносим пользователя в БД
        self.user_repo
            .create(username, email, password_hash, profile_pic_url)
            .await?;

        Ok("You are registered".to_string())
    }

    pub async fn login(&self, login_data: LoginData) -> Result<(String, Uuid), AuthError> {
        let email = login_data.email;
        let password = login_data.password;

        // Поиск пользователя по почте
        let user = match self.user_repo.find_by_email(&email).await {
            Ok(user) => user,
            Err(_) => return Err(InvalidCredentials), // скрываем, есть ли пользователь
        };

        // Проверка пароля на валидность
        let password_hasher = &self.password_hasher;
        let is_valid = password_hasher
            .verify_password(&password, &user.password_hash)
            .await?;

        // Генерация пары access + refresh токенов
        if is_valid {
            let tokens = self.generate_tokens(
                user,
                &login_data.user_agent,
                &login_data.ip_address
            ).await?;
            Ok(tokens)
        } else {
            Err(InvalidCredentials)
        }
    }

    pub async fn refresh(&self, refresh_data: RefreshData) -> Result<(String, Uuid), AuthError> {
        let user_id = refresh_data.user_id;
        let token_id = refresh_data.token_id;

        // данные о сессии
        let session_data = self
            .token_repo
            .find_refresh_token(&user_id, &token_id)
            .await
            .map_err(|_| TokenError)?;

        // верифицировать токен
        self.jwt_provider
            .verify_refresh_token(&session_data.token)
            .map_err(|_| TokenError)?;

        // найти пользователя
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await
            .map_err(|_| InvalidCredentials)?;

        // сгенерировать новую пару токенов и занести refresh токен в бд
        let tokens = self.generate_tokens(
            user,
            &refresh_data.user_agent,
            &refresh_data.ip_address
        ).await?;

        // инвалидировать старый refresh токен
        self.token_repo
            .delete_refresh_token(&user_id, &token_id)
            .await
            .map_err(|_| TokenError)?;
        // возвращаем пару токенов

        Ok(tokens)
    }

    pub async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        // Удаляем все refresh-токены пользователя
        self.token_repo
            .delete_all_refresh_tokens(&user_id)
            .await
            .map_err(|_| TokenError)?;

        Ok(())
    }

    pub async fn delete_user_session(&self, user_id: Uuid, token_id: Uuid) -> Result<(), AuthError> {
        // Удаляем refresh-сессию
        self.token_repo
            .delete_refresh_token(&user_id, &token_id)
            .await
            .map_err(|_| TokenError)?;
        Ok(())
    }
    
    pub async fn get_user_sessions(&self, user_name: &str) -> Result<Vec<SessionData>, AuthError> {
        let user = self.user_repo.find_by_name(user_name).await?;
        
        let sessions = self.token_repo
            .find_user_refresh_tokens(&user.user_id)
            .await
            .map_err(|_| TokenError)?;
        Ok(sessions)
    }

    async fn generate_tokens(
        &self,
        user: UserModel,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<(String, Uuid), AuthError> {
        // Генерация access токена
        let access_token_data = self
            .jwt_provider
            .generate_access_token(&user.username, &user.user_id, &user.role)
            .map_err(|_| TokenError)?;

        // Генерация refresh токена
        let refresh_token_data = self
            .jwt_provider
            .generate_refresh_token(&user.username, &user.user_id, &user.role)
            .map_err(|_| TokenError)?;

        // Сохранение refresh токена
        self.token_repo
            .save_refresh_token(
                &user.user_id,
                &refresh_token_data.claims.jti,
                &refresh_token_data.token,
                Duration::days(15),
                user_agent,
                ip_address,
            )
            .await
            .map_err(|_| TokenError)?;

        // возврат access токена и id refresh токена
        Ok((access_token_data.token, refresh_token_data.claims.jti))
    }
}

#[derive(Debug)]
pub enum AuthError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    DatabaseError(DbErr),
    HashingError(Error),
    TokenError,
}

impl From<DbErr> for AuthError {
    fn from(err: DbErr) -> Self {
        AuthError::DatabaseError(err)
    }
}

impl From<Error> for AuthError {
    fn from(err: Error) -> Self {
        AuthError::HashingError(err)
    }
}
