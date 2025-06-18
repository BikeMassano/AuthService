use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Duration;
use sea_orm::{DbErr, Set};
use serde::Deserialize;

use crate::{
    application::{password_hasher::PasswordHasher},
    presentation::{requests::login_request::LoginRequest, responses::login_response::LoginResponse},
};
use crate::application::jwt_provider::JwtProvider;
use crate::domain::claims::Claims;
use crate::domain::entities::users::{Model as UserModel, ActiveModel as UserActiveModel};
use crate::infrastructure::app_state::AppState;
use crate::presentation::requests::registration_request::RegistrationRequest;
use crate::presentation::requests::update_request::UpdateRequest;
use crate::presentation::responses::user_response::UserResponse;

#[derive(Debug, Deserialize)]
pub struct Pagination {
    page: u32,
    page_size: u32,
}

pub async fn registration_handler(
    State(state): State<Arc<AppState>>,
    Json(registration_request): Json<RegistrationRequest>,
) -> Result<Json<String>, StatusCode> {
    let username = registration_request.username;
    let email = registration_request.email;

    let username_check = state.user_repository.find_by_name(&username);
    let email_check = state.user_repository.find_by_email(&email);

    let (username_result, email_result) = tokio::join!(username_check, email_check);

    if username_result.is_ok() || email_result.is_ok() {
        return Err(StatusCode::CONFLICT);
    }

    let password = registration_request.password;
    let password_hasher = state.password_hasher.clone();

    
    let password_hash = match tokio::task::spawn_blocking(move || {
        password_hasher.hash_password(&password)
    })
    .await{
        Ok(Ok(hash)) => hash,
        Ok(Err(_)) => return Err(StatusCode::UNPROCESSABLE_ENTITY),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
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
    // Реализовать аутентификацию после регистрации
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(login_request) : Json<LoginRequest>
) -> Result<Json<LoginResponse>, StatusCode> {
    // Поиск пользователя по имени
    let user = match state.user_repository.find_by_name(&login_request.username).await {
        Ok(user) => user,
        // Если не найден по имени, ищем по email
        Err(DbErr::RecordNotFound(_)) => match state.user_repository.find_by_email(&login_request.username).await {
            Ok(user) => user,
            // Не найден ни по имени, ни по email
            Err(DbErr::RecordNotFound(_)) => {
                return Err(StatusCode::UNAUTHORIZED);
            },
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            },
        },
        Err(_) => {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };


    let username = &user.username;
    let password = &login_request.password;
    let user_role = &user.role;
    let user_id = &user.user_id;

    let is_valid = is_valid_user(&user, password, &state.password_hasher);

    if is_valid.await {

        let access_token = match state.jwt_provider.generate_access_token(username, user_id ,user_role) {
            Ok(token) => token,
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };

        let refresh_token = match state.jwt_provider.generate_refresh_token(&user.username, &user.user_id, &user.role) {
            Ok(token) => token,
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // реализовать сохранение refresh-токена в базу Redis
        
        Ok(Json(LoginResponse { 
            access_token,
            refresh_token
        }))
    }
    else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn logout_handler() -> Result<Json<String>, StatusCode> {
    todo!()
}

pub async fn refresh_handler() -> Result<Json<String>, StatusCode> {
    // верифицировать токен
    // проверить отзыв токена
    // найти пользователя
    // сгенерировать новую пару токенов
    // занести новый refresh токен в бд redis

    todo!()
}

pub async fn delete_token_handler() -> Result<Json<String>, StatusCode> {
    todo!()
}

pub async fn get_current_user_handler(
    State(state): State<Arc<AppState>>,
    header_map: HeaderMap,
) -> Result<Json<UserResponse>, StatusCode> {
    let claims = extract_and_validate_token(&state.jwt_provider, &header_map)?;

    // Находим пользователя
    let user = state
        .user_repository
        .find_by_id(claims.sub)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Формируем ответ
    Ok(Json(UserResponse {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
    }))
}

pub async fn update_current_user_handler(
    State(state): State<Arc<AppState>>,
    header_map: HeaderMap,
    Json(update_request): Json<UpdateRequest>
) -> Result<Json<LoginResponse>, StatusCode> {
    // 1. Аутентификация
    let claims = match extract_and_validate_token(&state.jwt_provider, &header_map) {
        Ok(claims) => claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    // 2. Получаем текущего пользователя
    let user = state
        .user_repository
        .find_by_id(claims.sub)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 3. Применяем изменения из запроса
    let updated_user = UserModel {
        user_id: user.user_id,
        username: update_request.username.unwrap_or(user.username),
        email: update_request.email.unwrap_or(user.email),
        password_hash: user.password_hash,
        role: user.role
    };

    // 4. Обновляем пользователя в БД
    state
        .user_repository
        .update_by_id(claims.sub, updated_user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 5. Получаем обновлённые данные
    let updated_user = state
        .user_repository
        .find_by_id(claims.sub)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // 6. Инвалидируем старые токены
    state.token_repository.delete_all_refresh_tokens(&updated_user.user_id).await?;
    
    // 7. Генерируем новые токены
    let access_token = match state.jwt_provider.generate_access_token(&updated_user.username, &updated_user.user_id ,&updated_user.role) {
        Ok(token) => token,
        Err(_) => {
            return Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    };

    let refresh_token = match state.jwt_provider.generate_refresh_token(&updated_user.username, &updated_user.user_id ,&updated_user.role) {
        Ok(token) => token,
        Err(_) => {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    state.token_repository.save_refresh_token(&updated_user.user_id, &refresh_token, Duration::days(15)).await?;

    // 8. Конвертируем в UserResponse и возвращаем
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn get_users_handler(
    State(state): State<Arc<AppState>>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let users = state.user_repository.list_users(pagination.page, pagination.page_size)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user_response = users.into_iter().
        map(|user| UserResponse {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            role: user.role
        }).collect::<Vec<UserResponse>>();

    Ok(Json(user_response))
}

pub async fn get_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<UserResponse>, StatusCode> {
    let user = state.user_repository.find_by_name(&username)
        .await
        .map_err(|e| {
            match e {
                DbErr::RecordNotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    let user_response = UserResponse {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role
    };

    Ok(Json(user_response))
}

fn extract_and_validate_token(
    jwt_provider: &Arc<dyn JwtProvider>,
    header_map: &HeaderMap,
) -> Result<Claims, StatusCode> {
    let token = header_map
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    jwt_provider
        .verify_access_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}


async fn is_valid_user(
    user: &UserModel,
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