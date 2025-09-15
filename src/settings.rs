use serde::Deserialize;
use sha1::{Digest, Sha1};

use std::{
    fs,
    io::{Error as IoError, ErrorKind},
    path::Path,
};

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(rename = "__schema_version__")]
    pub schema_version: u32,
    pub data: Data,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Data {
    #[serde(rename = "autoLogin")]
    pub auto_login: AutoLogin,
    pub device: Device,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AutoLogin {
    pub enable: bool,
    pub username: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "deviceNick")]
    pub device_nick: String,
}

pub fn decrypt(key: &str, path: impl AsRef<Path>) -> crate::Result<Settings> {
    let buffer = fs::read(path)?;
    if buffer.len() < 256 {
        return Err(IoError::new(ErrorKind::InvalidData, "buffer shorter than 256").into());
    }
    if &buffer[0..4] != b"data" {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid signature").into());
    }

    let checksum = std::str::from_utf8(&buffer[108..148])
        .map_err(|_| IoError::new(ErrorKind::InvalidData, "checksum not utf-8"))?;
    let body = &buffer[256..];

    // SHA1(body) (hex lowercase)
    let mut hasher = Sha1::new();
    hasher.update(body);
    let got = hex_lower(&hasher.finalize());
    if got != checksum {
        return Err(IoError::new(ErrorKind::InvalidData, "checksum mismatch").into());
    }

    // Key point: determine whether to PKCS7-pad the key to a multiple of 16 based on (JS) UTF-16 length % 16
    let js_len_utf16 = key.encode_utf16().count(); // Equivalent to JS's key.length
    let mut key_bytes = key.as_bytes().to_vec(); // Equivalent to CryptoJS Utf8.parse(key)
    if js_len_utf16 % 16 != 0 {
        pkcs7_pad_in_place(&mut key_bytes, 16);
    }
    // Now key_bytes is a multiple of 16; in CryptoJS: keySize = key.sigBytes / 4
    let ptxt = aes_ecb_decrypt_cryptojs(&key_bytes, body)?;
    let mut ptxt = ptxt; // Decrypted plaintext still containing PKCS7 padding

    // CryptoJS.pad.Pkcs7.unpad: take last byte as pad length and truncate
    cryptojs_pkcs7_unpad_in_place(&mut ptxt)?;

    Ok(serde_json::from_str(str::from_utf8(&ptxt).map_err(
        |_| IoError::new(ErrorKind::InvalidData, "plaintext not utf-8"),
    )?)?)
}

/* ==================== CryptoJS AES (verbatim port) ==================== */

#[allow(dead_code)]
struct Tables {
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    sub_mix_0: [u32; 256],
    sub_mix_1: [u32; 256],
    sub_mix_2: [u32; 256],
    sub_mix_3: [u32; 256],
    inv_sub_mix_0: [u32; 256],
    inv_sub_mix_1: [u32; 256],
    inv_sub_mix_2: [u32; 256],
    inv_sub_mix_3: [u32; 256],
    rcon: [u32; 11],
}

fn build_tables() -> Tables {
    // Same table construction as CryptoJS (see source):
    // - d[i] = xtime
    // - advance x/xi: if (!x) { x = xi = 1 } else { x = x2 ^ d[d[d[x8 ^ x2]]]; xi ^= d[d[xi]]; }
    let mut d = [0u8; 256];
    for i in 0..256 {
        d[i] = if i < 0x80 {
            (i as u8) << 1
        } else {
            ((((i as u8) << 1) as u16) ^ 0x11b) as u8
        };
    }
    let mut sbox = [0u8; 256];
    let mut inv_sbox = [0u8; 256];
    let mut sub_mix_0 = [0u32; 256];
    let mut sub_mix_1 = [0u32; 256];
    let mut sub_mix_2 = [0u32; 256];
    let mut sub_mix_3 = [0u32; 256];
    let mut inv_sub_mix_0 = [0u32; 256];
    let mut inv_sub_mix_1 = [0u32; 256];
    let mut inv_sub_mix_2 = [0u32; 256];
    let mut inv_sub_mix_3 = [0u32; 256];

    let mut x: u8 = 0;
    let mut xi: u8 = 0;
    for _ in 0..256 {
        // sbox / inv_sbox
        let mut sx = (xi as u16)
            ^ ((xi as u16) << 1)
            ^ ((xi as u16) << 2)
            ^ ((xi as u16) << 3)
            ^ ((xi as u16) << 4);
        sx = ((sx >> 8) ^ (sx & 0xff) ^ 0x63) & 0xff;
        let sx_u8 = sx as u8;
        sbox[x as usize] = sx_u8;
        inv_sbox[sx_u8 as usize] = x;

        // Multiplication precomputation
        let x2 = d[x as usize] as u32;
        let x4 = d[x2 as usize] as u32;
        let x8 = d[x4 as usize] as u32;

        // SUB_MIX (forward)
        let t = (u32::from(d[sx_u8 as usize]) * 0x101) ^ (u32::from(sx_u8) * 0x1010100);
        sub_mix_0[x as usize] = (t << 24) | (t >> 8);
        sub_mix_1[x as usize] = (t << 16) | (t >> 16);
        sub_mix_2[x as usize] = (t << 8) | (t >> 24);
        sub_mix_3[x as usize] = t;

        // INV_SUB_MIX (inverse)
        let t_inv = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ ((x as u32) * 0x1010100);
        inv_sub_mix_0[sx_u8 as usize] = (t_inv << 24) | (t_inv >> 8);
        inv_sub_mix_1[sx_u8 as usize] = (t_inv << 16) | (t_inv >> 16);
        inv_sub_mix_2[sx_u8 as usize] = (t_inv << 8) | (t_inv >> 24);
        inv_sub_mix_3[sx_u8 as usize] = t_inv;

        // Advance x/xi (exact match to original source logic)
        if x == 0 {
            x = 1;
            xi = 1;
        } else {
            let idx1 = ((x8 as u8) ^ (x2 as u8)) as usize;
            let idx2 = d[idx1] as usize;
            let idx3 = d[idx2] as usize;
            x = (x2 as u8) ^ d[idx3];
            xi ^= d[d[xi as usize] as usize];
        }
    }

    Tables {
        sbox,
        inv_sbox,
        sub_mix_0,
        sub_mix_1,
        sub_mix_2,
        sub_mix_3,
        inv_sub_mix_0,
        inv_sub_mix_1,
        inv_sub_mix_2,
        inv_sub_mix_3,
        rcon: [
            0x00u32, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        ]
        .map(|v| v << 24),
    }
}

fn aes_ecb_decrypt_cryptojs(key_bytes: &[u8], data: &[u8]) -> crate::Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(
            IoError::new(ErrorKind::InvalidData, "ciphertext len not multiple of 16").into(),
        );
    }
    let t = build_tables();

    // Fill key into u32 words as CryptoJS does (WordArray, big-endian)
    if key_bytes.is_empty() {
        return Err(IoError::new(ErrorKind::InvalidInput, "empty key").into());
    }
    let key_words = bytes_to_words_be(key_bytes);
    let key_size = key_bytes.len() / 4; // CryptoJS: keySize = key.sigBytes / 4 (already ensured multiple of 16)
    debug_assert_eq!(key_size, key_words.len());

    let n_rounds = key_size + 6;
    let ks_rows = (n_rounds + 1) * 4;

    // Round keys
    let mut key_schedule = vec![0u32; ks_rows];
    for ks_row in 0..ks_rows {
        if ks_row < key_size {
            key_schedule[ks_row] = key_words[ks_row];
        } else {
            let mut temp = key_schedule[ks_row - 1];
            if ks_row % key_size == 0 {
                temp = temp.rotate_left(8);
                temp = (u32::from(t.sbox[(temp >> 24) as usize]) << 24)
                    | (u32::from(t.sbox[((temp >> 16) & 0xff) as usize]) << 16)
                    | (u32::from(t.sbox[((temp >> 8) & 0xff) as usize]) << 8)
                    | u32::from(t.sbox[(temp & 0xff) as usize]);
                temp ^= t.rcon[(ks_row / key_size) as usize];
            } else if key_size > 6 && ks_row % key_size == 4 {
                temp = (u32::from(t.sbox[(temp >> 24) as usize]) << 24)
                    | (u32::from(t.sbox[((temp >> 16) & 0xff) as usize]) << 16)
                    | (u32::from(t.sbox[((temp >> 8) & 0xff) as usize]) << 8)
                    | u32::from(t.sbox[(temp & 0xff) as usize]);
            }
            key_schedule[ks_row] = key_schedule[ks_row - key_size] ^ temp;
        }
    }

    // Inverse round keys
    let mut inv_key_schedule = vec![0u32; ks_rows];
    for inv_ks_row in 0..ks_rows {
        let ks_row = ks_rows - inv_ks_row;
        let temp = if inv_ks_row % 4 != 0 {
            key_schedule[ks_row]
        } else {
            key_schedule[ks_row - 4]
        };
        inv_key_schedule[inv_ks_row] = if inv_ks_row < 4 || ks_row <= 4 {
            temp
        } else {
            let b0 = (temp >> 24) as usize;
            let b1 = ((temp >> 16) & 0xff) as usize;
            let b2 = ((temp >> 8) & 0xff) as usize;
            let b3 = (temp & 0xff) as usize;
            t.inv_sub_mix_0[t.sbox[b0] as usize]
                ^ t.inv_sub_mix_1[t.sbox[b1] as usize]
                ^ t.inv_sub_mix_2[t.sbox[b2] as usize]
                ^ t.inv_sub_mix_3[t.sbox[b3] as usize]
        };
    }

    // Block-wise decryption (strictly per CryptoJS: swap(1,3), call _doCryptBlock with INV tables and INV_SBOX, then swap back)
    let mut out = Vec::<u8>::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let mut m = [
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]),
            u32::from_be_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]),
            u32::from_be_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]),
            u32::from_be_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]),
        ];

        m.swap(1, 3);
        do_crypt_block(
            &mut m,
            &inv_key_schedule,
            n_rounds,
            &t.inv_sub_mix_0,
            &t.inv_sub_mix_1,
            &t.inv_sub_mix_2,
            &t.inv_sub_mix_3,
            &t.inv_sbox,
        );
        m.swap(1, 3);

        out.extend_from_slice(&m[0].to_be_bytes());
        out.extend_from_slice(&m[1].to_be_bytes());
        out.extend_from_slice(&m[2].to_be_bytes());
        out.extend_from_slice(&m[3].to_be_bytes());

        i += 16;
    }
    Ok(out)
}

#[inline]
fn do_crypt_block(
    m: &mut [u32; 4],
    key_schedule: &[u32],
    n_rounds: usize,
    sub_mix_0: &[u32; 256],
    sub_mix_1: &[u32; 256],
    sub_mix_2: &[u32; 256],
    sub_mix_3: &[u32; 256],
    sbox: &[u8; 256],
) {
    let mut s0 = m[0] ^ key_schedule[0];
    let mut s1 = m[1] ^ key_schedule[1];
    let mut s2 = m[2] ^ key_schedule[2];
    let mut s3 = m[3] ^ key_schedule[3];
    let mut ks_row = 4;

    for _ in 1..n_rounds {
        let t0 = sub_mix_0[(s0 >> 24) as usize]
            ^ sub_mix_1[((s1 >> 16) & 0xff) as usize]
            ^ sub_mix_2[((s2 >> 8) & 0xff) as usize]
            ^ sub_mix_3[(s3 & 0xff) as usize]
            ^ key_schedule[ks_row];
        ks_row += 1;

        let t1 = sub_mix_0[(s1 >> 24) as usize]
            ^ sub_mix_1[((s2 >> 16) & 0xff) as usize]
            ^ sub_mix_2[((s3 >> 8) & 0xff) as usize]
            ^ sub_mix_3[(s0 & 0xff) as usize]
            ^ key_schedule[ks_row];
        ks_row += 1;

        let t2 = sub_mix_0[(s2 >> 24) as usize]
            ^ sub_mix_1[((s3 >> 16) & 0xff) as usize]
            ^ sub_mix_2[((s0 >> 8) & 0xff) as usize]
            ^ sub_mix_3[(s1 & 0xff) as usize]
            ^ key_schedule[ks_row];
        ks_row += 1;

        let t3 = sub_mix_0[(s3 >> 24) as usize]
            ^ sub_mix_1[((s0 >> 16) & 0xff) as usize]
            ^ sub_mix_2[((s1 >> 8) & 0xff) as usize]
            ^ sub_mix_3[(s2 & 0xff) as usize]
            ^ key_schedule[ks_row];
        ks_row += 1;

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Final round: use provided SBOX (inv_sbox for decryption) then add round key
    m[0] = ((u32::from(sbox[(s0 >> 24) as usize]) << 24)
        | (u32::from(sbox[((s1 >> 16) & 0xff) as usize]) << 16)
        | (u32::from(sbox[((s2 >> 8) & 0xff) as usize]) << 8)
        | u32::from(sbox[(s3 & 0xff) as usize]))
        ^ key_schedule[ks_row];
    ks_row += 1;

    m[1] = ((u32::from(sbox[(s1 >> 24) as usize]) << 24)
        | (u32::from(sbox[((s2 >> 16) & 0xff) as usize]) << 16)
        | (u32::from(sbox[((s3 >> 8) & 0xff) as usize]) << 8)
        | u32::from(sbox[(s0 & 0xff) as usize]))
        ^ key_schedule[ks_row];
    ks_row += 1;

    m[2] = ((u32::from(sbox[(s2 >> 24) as usize]) << 24)
        | (u32::from(sbox[((s3 >> 16) & 0xff) as usize]) << 16)
        | (u32::from(sbox[((s0 >> 8) & 0xff) as usize]) << 8)
        | u32::from(sbox[(s1 & 0xff) as usize]))
        ^ key_schedule[ks_row];
    ks_row += 1;

    m[3] = ((u32::from(sbox[(s3 >> 24) as usize]) << 24)
        | (u32::from(sbox[((s0 >> 16) & 0xff) as usize]) << 16)
        | (u32::from(sbox[((s1 >> 8) & 0xff) as usize]) << 8)
        | u32::from(sbox[(s2 & 0xff) as usize]))
        ^ key_schedule[ks_row];
}

/* ==================== Utilities ==================== */

fn bytes_to_words_be(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() / 4);
    let mut i = 0;
    while i < bytes.len() {
        out.push(u32::from_be_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
        ]));
        i += 4;
    }
    out
}

fn pkcs7_pad_in_place(buf: &mut Vec<u8>, block_size: usize) {
    let pad = (block_size - (buf.len() % block_size)) as u8;
    for _ in 0..pad {
        buf.push(pad);
    }
}

fn cryptojs_pkcs7_unpad_in_place(buf: &mut Vec<u8>) -> crate::Result<()> {
    if buf.is_empty() {
        return Err(IoError::new(ErrorKind::InvalidData, "empty plaintext").into());
    }
    let n = *buf.last().unwrap() as usize;
    if n == 0 || n > buf.len() {
        return Err(IoError::new(ErrorKind::InvalidData, "invalid pkcs7 length").into());
    }
    buf.truncate(buf.len() - n);
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
