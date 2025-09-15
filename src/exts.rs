use std::path::Path;

use crate::decrypt;
use crate::settings;

pub trait SettingsExt {
    fn decrypt_settings(&self, path: impl AsRef<Path>) -> crate::Result<settings::Settings>;
}

impl SettingsExt for str {
    fn decrypt_settings(&self, path: impl AsRef<Path>) -> crate::Result<settings::Settings> {
        Ok(settings::decrypt(self, path)?)
    }
}

pub trait DecryptExt {
    fn decrypt_key(&self, path: impl AsRef<Path>) -> crate::Result<String>;
    fn decrypt_zip(&self, path: impl AsRef<Path>, target: impl AsRef<Path>) -> crate::Result<()>;
    fn decrypt_binary(&self, path: impl AsRef<Path>, target: impl AsRef<Path>)
    -> crate::Result<()>;
}

impl DecryptExt for str {
    fn decrypt_key(&self, path: impl AsRef<Path>) -> crate::Result<String> {
        decrypt::to_string(self, path)
    }

    fn decrypt_zip(&self, path: impl AsRef<Path>, target: impl AsRef<Path>) -> crate::Result<()> {
        decrypt::zip(self, path, target)
    }

    fn decrypt_binary(
        &self,
        path: impl AsRef<Path>,
        target: impl AsRef<Path>,
    ) -> crate::Result<()> {
        decrypt::binary(self, path, target)
    }
}
