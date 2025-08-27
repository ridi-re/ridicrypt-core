use base64::{Engine as _, engine::general_purpose};
use keyring::Entry;

use crate::utils::secret_to_str;

pub fn get() -> crate::Result<String> {
    #[cfg(target_os = "windows")]
    let entry = Entry::new_with_target("com.ridi.books/global", "", "global")?;
    #[cfg(target_os = "macos")]
    let entry = Entry::new_with_target("com.ridi.books", "", "global")?;

    let secret = secret_to_str(entry.get_secret()?)?;
    let decoded = general_purpose::STANDARD.decode(secret.trim_matches(char::is_whitespace))?;
    Ok(String::from_utf8(decoded)?)
}
