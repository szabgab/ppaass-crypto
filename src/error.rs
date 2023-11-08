use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Aes crypto error happen: {0}")]
    Aes(String),
    #[error("Rsa crypto error happen: {0}")]
    Rsa(String),
    #[error("Rsa crypto not found with user token: {0}")]
    RsaCryptoNotFound(String),
}
