use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use crate::domain::claims::Claims;
use crate::presentation::requests::login_request::LoginRequest;
use crate::presentation::responses::login_response::LoginResponse;

pub async fn login_handler(Json(login_request) : Json<LoginRequest>)
                           -> Result<Json<LoginResponse>, StatusCode> {
    let username = &login_request.username;
    let password = &login_request.password;

    let is_valid = is_valid_user(username, password);

    if is_valid {
        let claims = Claims {
            sub: username.clone(),
            role: "".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };

        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("secret".as_ref())) {
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

fn is_valid_user(username: &str, password: &str) -> bool {
    // Имитируем получение хэша пароля из БД
    let password_hash = bcrypt::hash("secret", bcrypt::DEFAULT_COST).unwrap();
    // Сравнение
    bcrypt::verify(password, password_hash.as_str()).unwrap_or(false)
}
pub async fn get_info_handler(header_map: HeaderMap) -> Result<Json<String>, StatusCode> {
    if let Some(auth_header) = header_map.get("Authorization") {
        if let Ok(auth_header_str) = auth_header.to_str() {
            if auth_header_str.starts_with("Bearer ") {
                let token = auth_header_str.trim_start_matches("Bearer ").to_string();

                return match decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::default()) {
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