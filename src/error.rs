use thiserror::Error;

#[derive(Error, Debug)]

pub enum CryptoError {
    #[error("Crypto error happen because of io: {_0:?}")]
    StdIo(#[from] std::io::Error),
    #[error("Crypto error happen because of reason: {_0:?}")]
    Other(String),
}
