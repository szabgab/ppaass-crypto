mod crypto;
mod error;

use bytes::Bytes;

pub use crypto::*;
pub use error::*;
use uuid::Uuid;

/// Generate a 16 length bytes
pub fn random_16_bytes() -> Bytes {
    Uuid::new_v4().as_bytes().to_vec().into()
}

pub trait RsaCryptoFetcher {
    fn fetch(&self, user_token: &str) -> Result<&RsaCrypto, CryptoError>;
}
