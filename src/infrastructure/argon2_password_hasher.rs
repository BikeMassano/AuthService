use crate::application::password_hasher::PasswordHasher;
use argon2::password_hash::Error;
use argon2::{
    Argon2, Params,
    password_hash::{
        PasswordHash, PasswordHasher as PH, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use sea_orm::prelude::async_trait::async_trait;
use std::sync::Arc;

pub struct Argon2PasswordHasher {
    argon2: Argon2<'static>,
    dummy_hash: Arc<str>,
}

impl Argon2PasswordHasher {
    pub fn new(dummy_hash: String) -> Result<Self, Error> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(7168, 2, 1, None)?,
        );

        Ok(Self {
            argon2,
            dummy_hash: dummy_hash.into(),
        })
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash_password(&self, password: &str) -> Result<String, Error> {
        let password = password.as_bytes().to_vec();
        let argon2 = self.argon2.clone();

        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);

            argon2
                .hash_password(&password, &salt)
                .map(|hash| hash.to_string())
        })
        .await
        .map_err(|_| Error::Crypto)?
    }

    async fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, Error> {
        let password = password.as_bytes().to_vec();
        let password_hash = password_hash.to_string();
        let argon2 = self.argon2.clone();
        let dummy_hash = self.dummy_hash.clone();

        tokio::task::spawn_blocking(move || {
            let parsed_hash = match PasswordHash::new(&password_hash) {
                Ok(hash) => hash,
                Err(e) => {
                    // Фиктивная проверка для защиты от timing-атак
                    let fake_hash = PasswordHash::new(&dummy_hash).map_err(|_| Error::Crypto)?;
                    argon2.verify_password(&password, &fake_hash)?;
                    return Err(e);
                }
            };
            Ok(argon2.verify_password(&password, &parsed_hash).is_ok())
        })
        .await
        .map_err(|_| Error::Crypto)?
    }
}
