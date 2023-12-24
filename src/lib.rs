use bytes::Bytes;
use rand::random;

pub mod crypto;
pub mod error;

pub fn random_32_bytes() -> Bytes {
    let random_32_bytes = random::<[u8; 32]>();
    Bytes::from(random_32_bytes.to_vec())
}
