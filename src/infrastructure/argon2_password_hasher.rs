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
            Params::new(7168, 2, 1, None).unwrap(),
        );

        Self { argon2 }
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash_password(&self, password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = self.argon2.hash_password(password.as_bytes(), &salt)?.to_string();

        Ok(password_hash)
    }


    fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, Error> {
        let parsed_hash = match PasswordHash::new(password_hash) {
            Ok(hash) => hash,
            Err(e) => {
                // фиктивная проверка пароля для защиты от атак по времени
                let fake_hash = PasswordHash::new("$argon2id$v=19$m=7168,t=2,p=1$dummy").unwrap();
                let _ = self.argon2.verify_password(password.as_bytes(), &fake_hash);
                
                return Err(e)
            }
        };
        
    Ok(self.argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
}