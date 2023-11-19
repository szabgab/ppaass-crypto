mod crypto;
mod error;

use bytes::Bytes;

pub use crypto::*;
pub use error::*;
use uuid::Uuid;

/// Generate a 32 length bytes
pub fn random_32_bytes() -> Bytes {
    let mut result = Vec::new();
    result.extend_from_slice(Uuid::new_v4().as_bytes());
    result.extend_from_slice(Uuid::new_v4().as_bytes());
    result.into()
}
