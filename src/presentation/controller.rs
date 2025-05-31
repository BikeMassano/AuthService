use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use jsonwebtoken::{decode, DecodingKey, Validation};

use crate::{
    application::{jwt_provider::JwtProvider, password_hasher::PasswordHasher},
    domain::{claims::Claims, enums::roles::Role},
    infrastructure::{argon2_password_hasher::Argon2PasswordHasher, bcrypt_password_hasher::BcryptPasswordHasher, hmac_jwt_provider::HmacJwtProvider},
    presentation::{requests::login_request::LoginRequest, responses::login_response::LoginResponse},
};

pub async fn login_handler(Json(login_request) : Json<LoginRequest>)
                           -> Result<Json<LoginResponse>, StatusCode> {
    let username = &login_request.username;
    let password = &login_request.password;

    let is_valid = is_valid_user(username, password);

    if is_valid {
        
        let jwt_provider = HmacJwtProvider;

        let token = match jwt_provider.generate_token(username, &Role::GUEST) {
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
    
    // let hasher = BcryptPasswordHasher;
    // let password_hash = "$2b$12$.dTGuvJDSh9YPd7iek1s/.ZQdE8aZdfFAQFSYViD.cvge3VRs9eg6";
    
    let hasher = Argon2PasswordHasher;
    let password_hash = "$argon2id$v=19$m=65536,t=3,p=2$iJJTyO0Bk8wfzJMLlmriSA$NW6tlkHWO3k2GHRaac4iWXkXOSiv34A6X1pzc01zLqQ";
    // Сравнение
    hasher.verify_password(password, password_hash.as_ref())
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