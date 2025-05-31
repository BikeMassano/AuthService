use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher as PH, PasswordVerifier, SaltString, rand_core::OsRng
    },
    Argon2
};

use crate::application::password_hasher::PasswordHasher;

pub struct Argon2PasswordHasher;

impl PasswordHasher for Argon2PasswordHasher {
    fn hash_password(&self, password: &str) -> String {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 2, None).unwrap(),
        );

        let salt = SaltString::generate(&mut OsRng);

        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

        password_hash.to_string()
    }


    fn verify_password(&self, password: &str, password_hash: &str) -> bool {
        let parsed_hash = PasswordHash::new(password_hash);
        if parsed_hash.is_err() {
            return false
        }
        
        let parsed_hash = parsed_hash.unwrap();
        
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }
}