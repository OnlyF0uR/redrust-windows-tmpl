use std::ptr;
use windows::{
    core::{Error, Result, PCWSTR},
    Win32::{
        Foundation::NTSTATUS,
        Security::Cryptography::{
            BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt,
            BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptImportKeyPair,
            BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_PAD_PKCS1, BCRYPT_RSAFULLPRIVATE_BLOB,
            BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM,
        },
    },
};

pub fn import_key(key_bytes: &[u8], is_private: bool) -> Result<BCRYPT_KEY_HANDLE> {
    let mut h_alg: BCRYPT_ALG_HANDLE = BCRYPT_ALG_HANDLE(ptr::null_mut());
    unsafe {
        let _ = BCryptOpenAlgorithmProvider(
            &mut h_alg,
            BCRYPT_RSA_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
    }

    let key_blob_type = if is_private {
        BCRYPT_RSAFULLPRIVATE_BLOB
    } else {
        BCRYPT_RSAPUBLIC_BLOB
    };

    let mut h_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE(ptr::null_mut());
    let status =
        unsafe { BCryptImportKeyPair(h_alg, None, key_blob_type, &mut h_key, key_bytes, 0) };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    Ok(h_key)
}

pub fn encrypt(public_key: BCRYPT_KEY_HANDLE, plaintext: &[u8], bitsize: usize) -> Result<Vec<u8>> {
    let mut encrypted_data = vec![0u8; bitsize / 8];
    let mut encrypted_size = 0u32;

    let status = unsafe {
        BCryptEncrypt(
            public_key,
            Some(plaintext),
            None,
            None,
            Some(encrypted_data.as_mut_slice()),
            &mut encrypted_size,
            BCRYPT_PAD_PKCS1,
        )
    };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    encrypted_data.truncate(encrypted_size as usize);
    Ok(encrypted_data)
}

pub fn decrypt(private_key: BCRYPT_KEY_HANDLE, encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let mut decrypted_data = vec![0u8; encrypted_data.len()];
    let mut decrypted_size = 0u32;

    let status = unsafe {
        BCryptDecrypt(
            private_key,
            Some(encrypted_data),
            None,
            None,
            Some(decrypted_data.as_mut_slice()),
            &mut decrypted_size,
            BCRYPT_PAD_PKCS1,
        )
    };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    decrypted_data.truncate(decrypted_size as usize);
    Ok(decrypted_data)
}

pub fn generate_rsa_keypair(key_size: u32) -> Result<(BCRYPT_KEY_HANDLE, Vec<u8>, Vec<u8>)> {
    let mut h_alg: BCRYPT_ALG_HANDLE = BCRYPT_ALG_HANDLE(ptr::null_mut());
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut h_alg,
            BCRYPT_RSA_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    let mut h_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE(ptr::null_mut());
    let status = unsafe { BCryptGenerateKeyPair(h_alg, &mut h_key, key_size, 0) };
    if status != NTSTATUS(0) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        };
        return Err(Error::from(status));
    }

    let status = unsafe { BCryptFinalizeKeyPair(h_key, 0) };
    if status != NTSTATUS(0) {
        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }
        return Err(Error::from(status));
    }

    let public_key = export_blob(h_key, BCRYPT_RSAPUBLIC_BLOB)?;
    let private_key = export_blob(h_key, BCRYPT_RSAFULLPRIVATE_BLOB)?;

    Ok((h_key, public_key, private_key))
}

fn export_blob(h_key: BCRYPT_KEY_HANDLE, key_type: PCWSTR) -> Result<Vec<u8>> {
    let mut blob_size = 0u32;

    let status = unsafe { BCryptExportKey(h_key, None, key_type, None, &mut blob_size, 0) };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    let mut blob = vec![0u8; blob_size as usize];
    let status = unsafe {
        BCryptExportKey(
            h_key,
            None,
            key_type,
            Some(blob.as_mut_slice()),
            &mut blob_size,
            0,
        )
    };
    if status != NTSTATUS(0) {
        return Err(Error::from(status));
    }

    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let (h_key, _, _) = generate_rsa_keypair(2048).unwrap();
        let pt = b"Hello, world!";
        let ed = encrypt(h_key, pt, 2048).unwrap();
        let dd = decrypt(h_key, &ed).unwrap();

        assert_eq!(pt, dd.as_slice());
    }

    #[test]
    fn test_rsa_import() {
        let (_, pub_key, priv_key) = generate_rsa_keypair(2048).unwrap();
        let pk = import_key(&pub_key, false).unwrap();
        let sk = import_key(&priv_key, true).unwrap();

        let pt = b"Hello, world!";
        let ed = encrypt(pk, pt, 2048).unwrap();
        let dd = decrypt(sk, &ed).unwrap();

        assert_eq!(pt, dd.as_slice());
    }
}
