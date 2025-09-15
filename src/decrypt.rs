use std::fs::File;
use std::io::{Read, Write};
use std::{fs, path::Path};

use aes::Aes128;
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions as FileOptions};

pub fn to_string(key: impl AsRef<[u8]>, path: impl AsRef<Path>) -> crate::Result<String> {
    let bytes = decrypt(key.as_ref(), path)?;
    Ok(String::from_utf8(bytes)?)
}

pub fn binary(
    key: impl AsRef<[u8]>,
    path: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> crate::Result<()> {
    let data = decrypt(key.as_ref(), path)?;
    fs::write(target.as_ref(), &data)?;
    Ok(())
}

pub fn zip(
    key: impl AsRef<[u8]>,
    path: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> crate::Result<()> {
    let original_file = File::open(path.as_ref())?;
    let mut original_zip = ZipArchive::new(original_file)?;
    let target_file = File::create(target.as_ref())?;
    let mut target_zip = ZipWriter::new(target_file);

    for i in 0..original_zip.len() {
        let mut entry = original_zip.by_index(i)?;

        if entry.is_dir() {
            target_zip.add_directory(entry.name().to_string(), FileOptions::default())?;
            continue;
        }

        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;

        let outdata = match decrypt_buf(key.as_ref(), &data) {
            Ok(p) => p,
            Err(_) => data,
        };

        target_zip.start_file(
            entry.name(),
            FileOptions::default().compression_method(entry.compression()),
        )?;
        target_zip.write_all(&outdata)?;
    }
    target_zip.finish()?;
    Ok(())
}

fn decrypt_buf(key: &[u8], data: &[u8]) -> crate::Result<Vec<u8>> {
    if data.len() == 1 && data[0] == 0 {
        return Ok(Vec::new());
    }
    if data.len() < 16 {
        return Ok(data.to_vec());
    }

    let (iv, ciphertext) = data.split_at(16);
    let mut ct = ciphertext.to_vec();
    let dec = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|e| format!("Invalid key/iv length: {e}"))?;
    let raw = dec
        .decrypt_padded_mut::<Pkcs7>(&mut ct)
        .map_err(|e| format!("PKCS7 unpad error: {e}"))?;

    Ok(raw.to_vec())
}

fn decrypt(key: &[u8], path: impl AsRef<Path>) -> crate::Result<Vec<u8>> {
    if key.len() != 16 {
        return Err("key for .dat must be 16 bytes (AES-128)".into());
    }

    let buf = fs::read(path)?;
    if buf.len() <= 16 {
        return Err(".dat file must be larger than 16 bytes".into());
    }

    decrypt_buf(key, &buf)
}
