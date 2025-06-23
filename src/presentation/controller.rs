use crate::application::jwt_provider::JwtProvider;
use crate::application::repositories::token_repository::TokenRepository;
use crate::domain::claims::Claims;
use crate::domain::entities::users::Model as UserModel;
use crate::infrastructure::app_state::AppState;
use crate::presentation::requests::refresh_request::RefreshRequest;
use crate::presentation::requests::registration_request::RegistrationRequest;
use crate::presentation::requests::update_request::UpdateRequest;
use crate::presentation::responses::user_response::UserResponse;
use crate::{
    application::password_hasher::PasswordHasher,
    presentation::{
        requests::login_request::LoginRequest, responses::login_response::LoginResponse,
    },
};
use argon2::password_hash::Error;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Duration;
use jsonwebtoken::errors::ErrorKind;
use sea_orm::DbErr;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct Pagination {
    page: u32,
    page_size: u32,
}

pub async fn registration_handler(
    State(state): State<Arc<AppState>>,
    Json(registration_request): Json<RegistrationRequest>,
) -> Result<Json<String>, StatusCode> {
    // Данные для регистрации
    let username = registration_request.username;
    let email = registration_request.email;
    let profile_pic_url = registration_request.profile_pic_url;

    // Таски для проверки существования пользователей в бд
    let username_check = state.user_repository.find_by_name(&username);
    let email_check = state.user_repository.find_by_email(&email);
    // Запуск тасок
    let (username_result, email_result) = tokio::join!(username_check, email_check);
    // Если нашли пользователя, то выбрасываем ошибку
    if username_result.is_ok() || email_result.is_ok() {
        return Err(StatusCode::CONFLICT);
    }
    // Хешируем пароль пользователя
    let password = registration_request.password;
    let password_hasher = state.password_hasher.clone();

    let password_hash =
        match tokio::task::spawn_blocking(move || password_hasher.hash_password(&password)).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(_)) => return Err(StatusCode::UNPROCESSABLE_ENTITY),
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
    // Заносим пользователя в БД
    match state
        .user_repository
        .create(username, email, password_hash, profile_pic_url)
        .await
    {
        Ok(_) => {
            let info = "You are registered".to_string();
            Ok(Json(info))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Поиск пользователя по почте
    let user = match state
        .user_repository
        .find_by_email(&login_request.email)
        .await
    {
        Ok(user) => user,
        Err(DbErr::RecordNotFound(_)) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    // Пароль из запроса на аутентификацию
    let password = &login_request.password;
    // Проверка пароля на валидность
    let is_valid = match is_valid_user(&user, password, &state.password_hasher).await {
        Ok(is_valid) => is_valid,
        Err(Error::Crypto) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    // Если пароль валиден - возвращаем пару токенов
    if is_valid {
        let tokens = generate_tokens(&state.jwt_provider, &state.token_repository, &user)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(tokens))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn logout_handler() -> Result<Json<String>, StatusCode> {
    todo!()
}

pub async fn refresh_handler(
    State(state): State<Arc<AppState>>,
    Json(refresh_request): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let user_id = &refresh_request.user_id;
    let token_id = &refresh_request.token_id;
    // данные о сессии
    let session_data = match state
        .token_repository
        .find_refresh_token(user_id, token_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED), // Токен не найден
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    // верифицировать токен
    let _ = &state
        .jwt_provider
        .verify_refresh_token(&session_data.token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // найти пользователя
    let user = match state.user_repository.find_by_id(user_id.clone()).await {
        Ok(user) => user,
        Err(DbErr::RecordNotFound(_)) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    // сгенерировать новую пару токенов и занести refresh токен в бд
    let tokens = generate_tokens(&state.jwt_provider, &state.token_repository, &user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // инвалидировать старый refresh токен
    let _ = &state
        .token_repository
        .delete_refresh_token(user_id, token_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // возвращаем пару токенов
    Ok(Json(tokens))
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
    Json(update_request): Json<UpdateRequest>,
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
        role: user.role,
        profile_pic_url: user.profile_pic_url,
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
    state
        .token_repository
        .delete_all_refresh_tokens(&updated_user.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 7. Генерируем новые токены
    let tokens =
        generate_tokens(&state.jwt_provider, &state.token_repository, &updated_user).await?;

    // 8. Конвертируем в UserResponse и возвращаем
    Ok(Json(tokens))
}

pub async fn get_users_handler(
    State(state): State<Arc<AppState>>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let users = state
        .user_repository
        .list_users(pagination.page, pagination.page_size)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user_response = users
        .into_iter()
        .map(|user| UserResponse {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            role: user.role,
        })
        .collect::<Vec<UserResponse>>();

    Ok(Json(user_response))
}

pub async fn get_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<UserResponse>, StatusCode> {
    let user = state
        .user_repository
        .find_by_name(&username)
        .await
        .map_err(|e| match e {
            DbErr::RecordNotFound(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    let user_response = UserResponse {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
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

async fn generate_tokens(
    jwt_provider: &Arc<dyn JwtProvider>,
    token_repository: &Arc<dyn TokenRepository>,
    user: &UserModel,
) -> Result<LoginResponse, StatusCode> {
    // Генерация access токена
    let access_token = jwt_provider
        .generate_access_token(&user.username, &user.user_id, &user.role)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Генерация refresh токена
    let refresh_token = jwt_provider
        .generate_refresh_token(&user.username, &user.user_id, &user.role)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_token_id = match jwt_provider.verify_refresh_token(&refresh_token) {
        Ok(claims) => claims.jti,
        Err(e) => {
            return match e.kind() {
                ErrorKind::InvalidToken => Err(StatusCode::UNAUTHORIZED),
                ErrorKind::ExpiredSignature => Err(StatusCode::UNAUTHORIZED),
                _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
    };

    // Сохранение refresh токена
    token_repository
        .save_refresh_token(
            &user.user_id,
            &refresh_token_id,
            &refresh_token,
            Duration::days(15),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // возврат access токена и id refresh токена
    Ok(LoginResponse {
        access_token,
        refresh_token_id,
    })
}

async fn is_valid_user(
    user: &UserModel,
    password: &str,
    password_hasher: &Arc<dyn PasswordHasher>,
) -> Result<bool, Error> {
    // получаем захешированный пароль
    let password_hash = user.password_hash.clone();
    let password = password.to_owned();
    let password_hasher = password_hasher.clone();
    // Сравнение
    tokio::task::spawn_blocking(move || {
        password_hasher.verify_password(&password, password_hash.as_ref())
    })
    .await
    .map_err(|_| Error::Crypto)?
}
