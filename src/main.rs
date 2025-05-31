use std::env;
use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use dotenv::dotenv;
use sea_orm::Database;
use crate::app_state::AppState;
use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;
use crate::application::repositories::user_repository::UserRepository;
use crate::infrastructure::argon2_password_hasher::Argon2PasswordHasher;
use crate::infrastructure::data::pg_user_repository::PostgresUserRepository;
use crate::infrastructure::hmac_jwt_provider::HmacJwtProvider;
use crate::presentation::controller::{get_info_handler, login_handler};

mod presentation;
mod domain;
mod application;
mod infrastructure;
mod app_state;

#[tokio::main]
async fn main() {
    // Загружаем переменные окружения
    dotenv().ok();
    // Получаем секретный ключ для JWT
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    // Получаем строку подключения к базе данных
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    // Установить соединение с базой данных
    let db_connection = Database::connect(&db_url).await
        .expect("Failed to connect to database");

    // Инстанцируем сервисы
    let jwt_provider: Arc<dyn JwtProvider> = Arc::new(HmacJwtProvider::new(secret));
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2PasswordHasher);
    let user_repository: Arc<dyn UserRepository> = Arc::new(PostgresUserRepository::new(db_connection));

    // Внедряем сервисы в контейнер зависимостей
    let app_state = AppState {
        jwt_provider,
        password_hasher,
        user_repository,
    };

    let app = Router::new()
        .route("/login", post(login_handler))
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
