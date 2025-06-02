use std::sync::Arc;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sea_orm::DbErr;

use crate::{
    application::{password_hasher::PasswordHasher},
    presentation::{requests::login_request::LoginRequest, responses::login_response::LoginResponse},
};

use crate::domain::entities::users::Model;
use crate::infrastructure::app_state::AppState;
use crate::presentation::requests::registration_request::RegistrationRequest;

pub async fn registration_handler(
    State(state): State<Arc<AppState>>,
    Json(registration_request): Json<RegistrationRequest>,
) -> Result<Json<String>, StatusCode> {
    let username = registration_request.username;
    let password = registration_request.password;
    let email = registration_request.email;
    
    let password_hasher = state.password_hasher.clone();

    
    let password_hash = match tokio::task::spawn_blocking(move || {
        password_hasher.hash_password(&password)
    })
    .await{
        Ok(hash) => hash,
        Err(_) => return Err(StatusCode::UNPROCESSABLE_ENTITY),
    };

    match state.user_repository.create(username, email, password_hash).await {
        Ok(_) => {
            let info = "You are registered".to_string();
            Ok(Json(info))
        }
        Err(_) => {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(login_request) : Json<LoginRequest>
) -> Result<Json<LoginResponse>, StatusCode> {
    // Поиск пользователя по имени
    let user_repository = &state.user_repository;

    let user = match user_repository.find_by_name(&login_request.username).await {
        Ok(user) => user,
        // Если не найден по имени, ищем по email
        Err(DbErr::RecordNotFound(_)) => match user_repository.find_by_email(&login_request.username).await {
            Ok(user) => user,
            // Не найден ни по имени, ни по email
            Err(DbErr::RecordNotFound(_)) => {
                eprintln!("User {} not found", &login_request.username);
                return Err(StatusCode::NOT_FOUND);
            },
            Err(err) => {
                eprintln!("Failed to find user {}: {}", &login_request.username, err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            },
        },
        Err(err) => {
            eprintln!("Failed to find user {}: {}", &login_request.username, err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };


    let username = &user.username;
    let password = &login_request.password;
    let user_role = &user.role;

    let is_valid = is_valid_user(&user, password, &state.password_hasher);

    if is_valid.await {

        let token = match state.jwt_provider.generate_token(username, user_role) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("Failed to encode token: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };

        Ok(Json(LoginResponse { token }))
    }
    else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn is_valid_user(
    user: &Model, 
    password: &str,
    password_hasher: &Arc<dyn PasswordHasher>,
) -> bool {
    // получаем захэшированный пароль
    let password_hash = user.password_hash.clone();
    let password = password.to_owned();
    let password_hasher = password_hasher.clone();
    // Сравнение
    tokio::task::spawn_blocking(move || {
        password_hasher.verify_password(&password, password_hash.as_ref())
    })
    .await
    .unwrap_or(false)
}
pub async fn get_info_handler(
    State(state): State<Arc<AppState>>,
    header_map: HeaderMap
) -> Result<Json<String>, StatusCode> {
    if let Some(auth_header) = header_map.get("Authorization") {
        if let Ok(auth_header_str) = auth_header.to_str() {
            if auth_header_str.starts_with("Bearer ") {
                let token = auth_header_str.trim_start_matches("Bearer ").to_string();

                return match state.jwt_provider.decode_token(&token) {
                    Ok(_) => {
                        let info = "You are logged in".to_string();
                        Ok(Json(info))
                    }
                    Err(e) => {
                        eprintln!("Failed to encode token: {}", e);
                        Err(StatusCode::UNAUTHORIZED)
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}