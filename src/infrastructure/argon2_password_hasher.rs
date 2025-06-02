use argon2::{password_hash::{
    PasswordHash, PasswordHasher as PH, PasswordVerifier, SaltString, rand_core::OsRng
}, Argon2, Params};
use argon2::password_hash::Error;
use crate::application::password_hasher::PasswordHasher;

pub struct Argon2PasswordHasher {
    argon2: Argon2<'static>,
}

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(32768, 2, 1, None).unwrap(),
        );

        Self { argon2 }
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash_password(&self, password: &str) -> Result<String, Error> {


        let salt = SaltString::generate(&mut OsRng);

        let password_hash = match self.argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => return Err(e),
        };

        Ok(password_hash)
    }


    fn verify_password(&self, password: &str, password_hash: &str) -> bool {
        let parsed_hash = PasswordHash::new(password_hash);
        if parsed_hash.is_err() {
            return false
        }
        
        let parsed_hash = parsed_hash.unwrap();

        self.argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }
}