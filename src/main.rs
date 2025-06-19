use std::{env, sync::Arc};
use axum::{Router, routing::{get, post}};
use axum::routing::patch;
use dotenv::dotenv;
use sea_orm::Database;

use crate::{
    application::{
        jwt_provider::JwtProvider,
        password_hasher::PasswordHasher,
        repositories::user_repository::UserRepository,
    },
    infrastructure::{
        app_state::AppState,
        argon2_password_hasher::Argon2PasswordHasher,
        data::pg_user_repository::PostgresUserRepository,
        rsa_jwt_provider::RsaJwtProvider,
    },
    presentation::controller::{login_handler, registration_handler},
};
use crate::application::repositories::token_repository::TokenRepository;
use crate::infrastructure::data::redis_token_repository::RedisTokenRepository;
use crate::presentation::controller::{get_current_user_handler, get_user_handler, get_users_handler, update_current_user_handler};

mod presentation;
mod domain;
mod application;
mod infrastructure;

#[tokio::main]
async fn main() {
    // Загружаем переменные окружения
    dotenv().ok();

    // Получаем секретные ключи для JWT
    let private_key = env::var("JWT_PRIVATE_KEY")
        .expect("JWT_PRIVATE_KEY must be set");
    let public_key = env::var("JWT_PUBLIC_KEY")
        .expect("JWT_PUBLIC_KEY must be set");
    // Получаем время истечения access токена в минутах
    let access_token_exp = env::var("JWT_ACCESS_EXP")
        .expect("JWT_ACCESS_EXP must be set")
        .parse::<i64>()
        .expect("JWT_ACCESS_EXP must be a number");
    // Получаем время истечения refresh токена в днях
    let refresh_token_exp = env::var("JWT_REFRESH_EXP")
        .expect("JWT_REFRESH_EXP must be set")
        .parse::<i64>()
        .expect("JWT_REFRESH_EXP must be a number");
    // Получаем издателя токена
    let issuer = env::var("ISSUER")
        .expect("ISSUER must be set");

    // Получаем строку подключения к базе данных учётных записей
    let user_db_url = env::var("USER_DATABASE_URL")
        .expect("USER_DATABASE_URL must be set");

    // Устанавливаем соединение с базой данных учётных записей
    let user_db_connection = Database::connect(&user_db_url).await
        .expect("Failed to connect to database");

    // Получаем строку подключения к базе данных refresh токенов
    let token_db_url = env::var("TOKEN_DATABASE_URL")
        .expect("TOKEN_DATABASE_URL must be set");

    // Инстанцируем сервисы
    let jwt_provider: Arc<dyn JwtProvider> = Arc::new(RsaJwtProvider::new(&private_key, &public_key, issuer, access_token_exp, refresh_token_exp)
        .expect("Failed to create jwt provider"));
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2PasswordHasher::new());
    let user_repository: Arc<dyn UserRepository> = Arc::new(PostgresUserRepository::new(user_db_connection));
    let token_repository: Arc<dyn TokenRepository> = Arc::new(
        RedisTokenRepository::new(&token_db_url)
            .expect("Failed to create Redis token repository")
    );

    // Внедряем сервисы в контейнер зависимостей
    let app_state = Arc::new(AppState {
        jwt_provider,
        password_hasher,
        user_repository,
        token_repository
    });

    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/registration", post(registration_handler))
        .route("/me", get(get_current_user_handler))
        .route("/admin/users", get(get_users_handler))
        .route("/admin/users/{username}", get(get_user_handler))
        .route("/me", patch(update_current_user_handler))

        .with_state(app_state);

    let listener =
        tokio::net::TcpListener::bind(("127.0.0.1", 8080))
            .await
            .unwrap();

    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .unwrap();
}