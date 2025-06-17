use std::env;
use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use dotenv::dotenv;
use sea_orm::Database;
use infrastructure::app_state::AppState;
use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;
use crate::application::repositories::user_repository::UserRepository;
use crate::infrastructure::argon2_password_hasher::Argon2PasswordHasher;
use crate::infrastructure::data::pg_user_repository::PostgresUserRepository;
use crate::infrastructure::rsa_jwt_provider::{RsaJwtProvider};
use crate::presentation::controller::{get_info_handler, login_handler, registration_handler};

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
    
    // Получаем строку подключения к базе данных
    let db_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    // Устанавливаем соединение с базой данных
    let db_connection = Database::connect(&db_url).await
        .expect("Failed to connect to database");

    // Инстанцируем сервисы
    let jwt_provider: Arc<dyn JwtProvider> = Arc::new(RsaJwtProvider::new(private_key, public_key, issuer, access_token_exp, refresh_token_exp));
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2PasswordHasher::new());
    let user_repository: Arc<dyn UserRepository> = Arc::new(PostgresUserRepository::new(db_connection));

    // Внедряем сервисы в контейнер зависимостей
    let app_state = Arc::new(AppState {
        jwt_provider,
        password_hasher,
        user_repository,
    });

    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/registration", post(registration_handler))
        .route("/info", get(get_info_handler))

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
