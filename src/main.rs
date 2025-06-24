use crate::application::repositories::token_repository::TokenRepository;
use crate::infrastructure::data::redis_token_repository::RedisTokenRepository;
use crate::{
    application::{
        jwt_provider::JwtProvider, password_hasher::PasswordHasher,
        repositories::user_repository::UserRepository,
    },
    infrastructure::{
        app_state::AppState, argon2_password_hasher::Argon2PasswordHasher,
        data::pg_user_repository::PostgresUserRepository, rsa_jwt_provider::RsaJwtProvider,
    },
};
use presentation::controllers::controller::{
    get_current_user_handler,
    get_user_handler,
    get_users_handler,
    refresh_handler,
    //update_current_user_handler,
};

use crate::application::services::auth_service::AuthService;
use crate::application::services::user_service::UserService;
use crate::presentation::controllers::controller::{
    delete_all_sessions_handler, delete_session_handler,
};
use axum::{
    Router,
    routing::{get, patch, post},
};
use dotenv::dotenv;
use presentation::controllers::controller::{login_handler, registration_handler};
use sea_orm::Database;
use std::{env, sync::Arc};

mod application;
mod domain;
mod infrastructure;
mod presentation;

#[tokio::main]
async fn main() {
    // Загружаем переменные окружения
    dotenv().ok();

    // Получаем фиктивный хеш пароля argon2id
    let dummy_hash = env::var("DUMMY_HASH").expect("DUMMY_HASH must be set");

    // Получаем секретные ключи для JWT
    let private_key = env::var("JWT_PRIVATE_KEY").expect("JWT_PRIVATE_KEY must be set");
    let public_key = env::var("JWT_PUBLIC_KEY").expect("JWT_PUBLIC_KEY must be set");
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
    let issuer = env::var("ISSUER").expect("ISSUER must be set");

    // Получаем строку подключения к базе данных учётных записей
    let user_db_url = env::var("USER_DATABASE_URL").expect("USER_DATABASE_URL must be set");

    // Устанавливаем соединение с базой данных учётных записей
    let user_db_connection = Database::connect(&user_db_url)
        .await
        .expect("Failed to connect to database");

    // Получаем строку подключения к базе данных refresh токенов
    let token_db_url = env::var("TOKEN_DATABASE_URL").expect("TOKEN_DATABASE_URL must be set");

    {
        // Проверяем подключение к Redis
        let redis_client =
            redis::Client::open(token_db_url.clone()).expect("Failed to create Redis client");

        // Проверяем соединение с Redis
        let mut redis_conn = redis_client
            .get_multiplexed_async_connection()
            .await
            .expect("Failed to connect to Redis database");
    }

    // Инстанцируем сервисы
    // Сервис работы JWT токенами
    let jwt_provider: Arc<dyn JwtProvider> = Arc::new(
        RsaJwtProvider::new(
            &private_key,
            &public_key,
            issuer,
            access_token_exp,
            refresh_token_exp,
        )
        .expect("Failed to create jwt provider"),
    );
    // Сервис для хеширования паролей
    let password_hasher: Arc<dyn PasswordHasher> =
        Arc::new(Argon2PasswordHasher::new(dummy_hash).expect("Failed to create password hasher"));
    // Репозиторий для работы с БД пользователей
    let user_repository: Arc<dyn UserRepository> =
        Arc::new(PostgresUserRepository::new(user_db_connection));
    // Репозиторий для работы с БД refresh токенов в redis
    let token_repository: Arc<dyn TokenRepository> = Arc::new(
        RedisTokenRepository::new(&token_db_url).expect("Failed to create Redis token repository"),
    );

    // Создаем AuthService
    let auth_service = Arc::new(AuthService::new(
        user_repository.clone(),
        token_repository.clone(),
        jwt_provider.clone(),
        password_hasher.clone(),
    ));

    // Создаем UserService
    let user_service = Arc::new(UserService::new(
        user_repository,
        token_repository,
        jwt_provider,
        password_hasher,
    ));

    // Внедряем сервисы в контейнер зависимостей
    let app_state = Arc::new(AppState {
        auth_service,
        user_service,
    });

    let app = Router::new()
        .route("/logout", post(delete_session_handler))
        .route("/login", post(login_handler))
        .route("/registration", post(registration_handler))
        .route("/me", get(get_current_user_handler))
        .route("/admin/users", get(get_users_handler))
        .route("/admin/users/{username}", get(get_user_handler))
        //.route("/me", patch(update_current_user_handler))
        .route("/refresh", post(refresh_handler))
        .route("/sessions/leave", post(delete_session_handler))
        .route("/sessions/leave-all", post(delete_all_sessions_handler))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 8080))
        .await
        .unwrap();

    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
