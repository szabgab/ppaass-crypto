use bytes::{Bytes, BytesMut};
use uuid::Uuid;
use ppaass_crypto::crypto::{decrypt_with_aes, encrypt_with_aes};
use ppaass_crypto::error::CryptoError;

/// Generate a 32 length bytes
fn random_32_bytes() -> Bytes {
    let mut result = Vec::new();
    result.extend_from_slice(Uuid::new_v4().as_bytes());
    result.extend_from_slice(Uuid::new_v4().as_bytes());
    result.into()
}

#[test]
fn test() -> Result<(), CryptoError> {
    let encryption_token = random_32_bytes();
    let mut target = BytesMut::from_iter(
        "hello world! this is my plaintext888888888888888."
            .as_bytes()
            .to_vec(),
    );
    encrypt_with_aes(&encryption_token, &mut target)?;
    println!("Encrypt result: [{:?}]", String::from_utf8_lossy(&target));
    let mut encrypted_target = BytesMut::from_iter(target.to_vec());
    let descrypted_result = decrypt_with_aes(&encryption_token, &mut encrypted_target)?;
    println!(
        "Decrypted result: [{:?}]",
        String::from_utf8_lossy(&descrypted_result)
    );
    Ok(())
}
