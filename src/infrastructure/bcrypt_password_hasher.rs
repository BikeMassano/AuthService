use crate::application::password_hasher::PasswordHasher;

pub struct BcryptPasswordHasher;

impl PasswordHasher for BcryptPasswordHasher {
    fn hash_password(&self, password: &str) -> String {
        bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap()
    }

    fn verify_password(&self, password: &str, password_hash: &str) -> bool {
        bcrypt::verify(password, password_hash).unwrap_or(false)
    }
}