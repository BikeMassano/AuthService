use crate::application::repositories::token_repository::TokenRepository;
use crate::domain::models::session_data::SessionData;
use chrono::{Duration, Utc};
use deadpool_redis::Pool;
use deadpool_redis::redis::AsyncCommands;
use sea_orm::prelude::async_trait::async_trait;
use std::error::Error;
use uuid::Uuid;

pub struct RedisTokenRepository {
    pool: Pool,
}

impl RedisTokenRepository {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn Error>> {
        let pool = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl TokenRepository for RedisTokenRepository {
    async fn save_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
        token: &str,
        expires_in: Duration,
        access_jti: &Uuid,
    ) -> Result<(), Box<dyn Error>> {
        // Создаём соединение с Redis
        let mut conn = self.pool.get().await?;

        // Формируем ключи для хранения сессий пользователя
        let key = format!("USER_REFRESH_TOKEN:{}:{}", user_id, token_id);

        // Вычисляем expires_at и issued_at
        let issued_at = Utc::now();
        let expires_at = issued_at + expires_in;

        let session_data = SessionData {
            token: token.to_string(),
            expires_at: expires_at.timestamp(),
            issued_at: issued_at.timestamp(),
        };

        let session_json = serde_json::to_string(&session_data)?;
        let ttl_seconds = expires_in.num_seconds().max(1) as u64;

        // Сохраняем в БД
        let _ : () = conn.set_ex(&key, session_json, ttl_seconds)
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        Ok(())
    }

    async fn find_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
    ) -> Result<SessionData, Box<dyn Error>> {
        // Создаём соединение с Redis
        let mut conn = self.pool.get().await?;
        // Формируем ключ для хранения сессий пользователя
        let key = format!("USER_REFRESH_TOKEN:{}:{}", user_id, token_id);

        // Получаем данные сессии из Redis
        let session_json: String = conn.get(&key).await?;

        // Десериализуем JSON в структуру SessionData
        let session_data: SessionData = serde_json::from_str(&session_json)?;

        Ok(session_data)
    }

    async fn delete_refresh_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
    ) -> Result<(), Box<dyn Error>> {
        // Создаём соединение с Redis
        let mut conn = self.pool.get().await?;

        // Формируем ключ для хранения refresh-токенов пользователя
        let key = format!("USER_REFRESH_TOKEN:{}:{}", user_id, token_id);

        // Удаляем запись о токене из хеша
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    async fn delete_all_refresh_tokens(&self, user_id: &Uuid) -> Result<(), Box<dyn Error>> {
        // Создаём соединение с Redis
        let mut conn = self.pool.get().await?;

        let pattern = format!("USER_REFRESH_TOKEN:{}:*", user_id);
        // Получаем все ключи, соответствующие шаблону
        let keys: Vec<String> = conn.keys(&pattern).await?;
        // Удаляем все найденные ключи
        if !keys.is_empty() {
            let _ : () = conn.del(keys).await?;
        }

        Ok(())
    }

    async fn find_user_refresh_tokens(
        &self,
        user_id: &Uuid
    ) -> Result<Vec<SessionData>, Box<dyn Error>> {
        let mut conn = self.pool.get().await?;
        let pattern = format!("USER_REFRESH_TOKEN:{}:*", user_id);

        let keys: Vec<String> = conn.keys(&pattern).await?;

        let mut sessions = Vec::new();
        for key in keys {
            if let Ok(json) = conn.get::<_, String>(&key).await {
                if let Ok(session) = serde_json::from_str::<SessionData>(&json) {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }
}
