use crate::application::jwt_provider::JwtProvider;
use crate::application::password_hasher::PasswordHasher;
use crate::application::repositories::token_repository::TokenRepository;
use crate::application::repositories::user_repository::UserRepository;
use crate::application::services::auth_service::AuthError;
use crate::application::services::auth_service::AuthError::{DatabaseError, UserNotFound};
use crate::domain::entities::users::Model as UserModel;
use crate::domain::models::update_data::UpdateData;
use crate::domain::models::users_query_data::UserQueryParams;
use sea_orm::DbErr;
use std::sync::Arc;
use uuid::Uuid;

pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
    token_repo: Arc<dyn TokenRepository>,
    jwt_provider: Arc<dyn JwtProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl UserService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        token_repo: Arc<dyn TokenRepository>,
        jwt_provider: Arc<dyn JwtProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            user_repo,
            token_repo,
            jwt_provider,
            password_hasher,
        }
    }

    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        todo!()
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<UserModel, AuthError> {
        self.user_repo
            .find_by_id(user_id)
            .await
            .map_err(|e| match e {
                DbErr::RecordNotFound(_) => UserNotFound,
                _ => DatabaseError(e),
            })
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<UserModel, AuthError> {
        self.user_repo
            .find_by_name(&username)
            .await
            .map_err(|e| match e {
                DbErr::RecordNotFound(_) => UserNotFound,
                _ => DatabaseError(e),
            })
    }

    pub async fn list_users(
        &self,
        query_params: UserQueryParams,
    ) -> Result<Vec<UserModel>, AuthError> {
        self.user_repo
            .list_users(
                query_params.page,
                query_params.page_size,
                query_params.search,
            )
            .await
            .map_err(|e| match e {
                DbErr::RecordNotFound(_) => UserNotFound,
                _ => DatabaseError(e),
            })
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        update_request: UpdateData,
        current_user: &UserModel,
    ) -> Result<UserModel, AuthError> {
        todo!()
    }
}
