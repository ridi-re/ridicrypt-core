use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use keyring::Entry;

pub fn get_global_key() -> crate::Result<String> {
    #[cfg(target_os = "windows")]
    let entry = Entry::new_with_target("com.ridi.books/global", "", "global")?;
    #[cfg(target_os = "macos")]
    let entry = Entry::new_with_target("com.ridi.books", "", "global")?;

    let secret = secret_to_str(entry.get_secret()?)?;
    let decoded = general_purpose::STANDARD.decode(secret.trim_matches(char::is_whitespace))?;
    Ok(String::from_utf8(decoded)?)
}

fn secret_to_str(b: Vec<u8>) -> crate::Result<String> {
    #[cfg(target_os = "windows")]
    {
        let is_utf16le = b.len() % 2 == 0
            && b.iter().skip(1).step_by(2).filter(|&&b| b == 0).count() * 2 >= b.len();

        if is_utf16le {
            let u16s: Vec<u16> = b
                .chunks_exact(2)
                .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                .collect();
            Ok(String::from_utf16(&u16s)?)
        } else {
            Ok(String::from_utf8(b)?)
        }
    }

    #[cfg(target_os = "macos")]
    {
        Ok(String::from_utf8(b)?)
    }
}

pub fn get_ridi_data_path() -> crate::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let app_data = std::env::var("APPDATA")?;
        Ok([&app_data, "Ridibooks"].iter().collect())
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME")?;
        Ok([&home, "Library", "Application Support", "Ridibooks"]
            .iter()
            .collect())
    }
}
