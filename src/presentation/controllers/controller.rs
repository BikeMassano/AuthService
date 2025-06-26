use crate::application::repositories::token_repository::TokenRepository;
use crate::application::services::auth_service::AuthError;
use crate::domain::models::login_data::LoginData;
use crate::domain::models::refresh_data::RefreshData;
use crate::domain::models::registration_data::RegistrationData;
use crate::domain::models::users_query_data::UserQueryParams;
use crate::infrastructure::app_state::AppState;
use crate::presentation::requests::logout_all_request::LogoutAllRequest;
use crate::presentation::requests::login_request::LoginRequest;
use crate::presentation::requests::refresh_request::RefreshRequest;
use crate::presentation::requests::registration_request::RegistrationRequest;
use crate::presentation::requests::update_request::UpdateRequest;
use crate::presentation::responses::login_response::LoginResponse;
use crate::presentation::responses::user_response::UserResponse;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use std::sync::Arc;
use chrono::DateTime;
use uuid::Uuid;
use crate::presentation::requests::logout_request::LogoutRequest;
use crate::presentation::responses::session_response::SessionResponse;

pub async fn registration_handler(
    State(state): State<Arc<AppState>>,
    Json(registration_request): Json<RegistrationRequest>,
) -> Result<Json<String>, StatusCode> {
    let registration_data = RegistrationData {
        username: registration_request.username,
        email: registration_request.email,
        password: registration_request.password,
        profile_pic_url: registration_request.profile_pic_url,
    };

    match state.auth_service.register(registration_data).await {
        Ok(message) => Ok(Json(message)),
        Err(AuthError::UserAlreadyExists) => Err(StatusCode::CONFLICT),
        Err(AuthError::DatabaseError(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(AuthError::HashingError(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let login_data = LoginData {
        email: login_request.email,
        password: login_request.password,
        user_agent: login_request.user_agent,
        ip_address: login_request.ip_address,
    };

    match state.auth_service.login(login_data).await {
        Ok((access_token, refresh_token_id)) => Ok(Json(LoginResponse {
            access_token,
            refresh_token_id,
        })),
        Err(AuthError::InvalidCredentials) => Err(StatusCode::UNAUTHORIZED),
        Err(AuthError::DatabaseError(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(AuthError::TokenError) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_sessions_handler(
    State(state): State<Arc<AppState>>, 
    Path(username): Path<String>
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    let sessions = match state.auth_service.get_user_sessions(&username).await {
        Ok(sessions) => sessions,
        Err(AuthError::UserNotFound) => return Err(StatusCode::NOT_FOUND),
        Err(AuthError::DatabaseError(_)) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(AuthError::TokenError) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    
    let session_responses = sessions
        .into_iter()
        .map(|session| {
            let created_at = DateTime::from_timestamp(session.issued_at, 0)
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(SessionResponse {
                token_id: session.token_id,
                user_agent: session.user_agent,
                ip_address: session.ip_address,
                created_at,
            })
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;

    Ok(Json(session_responses))
}

pub async fn logout_all_handler(
    State(state): State<Arc<AppState>>,
    Json(logout_all_request): Json<LogoutAllRequest>,
) -> Result<(), StatusCode> {
    match state.auth_service.delete_user_sessions(logout_all_request.user_id).await {
        Ok(()) => Ok(()),
        Err(AuthError::TokenError) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<(), StatusCode> {
    state
        .user_service
        .delete_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

pub async fn refresh_handler(
    State(state): State<Arc<AppState>>,
    Json(refresh_request): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let refresh_data = RefreshData {
        user_id: refresh_request.user_id,
        token_id: refresh_request.token_id,
        user_agent: refresh_request.user_agent,
        ip_address: refresh_request.ip_address,
    };

    match state.auth_service.refresh(refresh_data).await {
        Ok((access_token, refresh_token_id)) => Ok(Json(LoginResponse {
            access_token,
            refresh_token_id,
        })),
        Err(AuthError::TokenError) => Err(StatusCode::UNAUTHORIZED),
        Err(AuthError::InvalidCredentials) => Err(StatusCode::UNAUTHORIZED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    Json(logout_request): Json<LogoutRequest>,
) -> Result<(), StatusCode> {
    let user_id = logout_request.user_id;
    let token_id = logout_request.token_id;

    state
        .auth_service
        .delete_user_session(user_id, token_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

pub async fn get_current_user_handler(
    State(state): State<Arc<AppState>>,
    header_map: HeaderMap,
) -> Result<Json<UserResponse>, StatusCode> {
    todo!()
}

pub async fn update_current_user_handler(
    State(state): State<Arc<AppState>>,
    header_map: HeaderMap,
    Json(update_request): Json<UpdateRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    todo!()
}

pub async fn get_users_handler(
    State(state): State<Arc<AppState>>,
    Query(user_query_params): Query<UserQueryParams>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let users = match state.user_service.list_users(user_query_params).await {
        Ok(users) => users,
        Err(AuthError::UserNotFound) => return Err(StatusCode::NOT_FOUND),
        Err(AuthError::DatabaseError(_)) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let user_responses = users
        .into_iter()
        .map(|user| UserResponse {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            role: user.role,
            profile_pic_url: user.profile_pic_url,
        })
        .collect();

    Ok(Json(user_responses))
}

pub async fn get_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<UserResponse>, StatusCode> {
    match state.user_service.get_user_by_username(&username).await {
        Ok(user) => Ok(Json(UserResponse {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            role: user.role,
            profile_pic_url: user.profile_pic_url,
        })),
        Err(AuthError::UserNotFound) => Err(StatusCode::NOT_FOUND),
        Err(AuthError::DatabaseError(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
