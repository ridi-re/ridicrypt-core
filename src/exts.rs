use std::path::Path;

use crate::settings;

use crate::decrypt;

pub trait SettingsDecryptExt {
    fn decrypt_settings(&self) -> crate::Result<settings::Settings>;
}

impl SettingsDecryptExt for str {
    fn decrypt_settings(&self) -> crate::Result<settings::Settings> {
        Ok(settings::decrypt(self)?)
    }
}

pub trait DecryptExt {
    fn decrypt_to_u8(&self) -> crate::Result<Vec<u8>>;
    fn decrypt_to_string(&self) -> crate::Result<String>;
    fn decrypt_zip(&self, target: impl AsRef<Path>) -> crate::Result<()>;
    fn decrypt_zip_legacy(&self, target: impl AsRef<Path>) -> crate::Result<()>;
}

impl<K, P> DecryptExt for (K, P)
where
    K: AsRef<[u8]>,
    P: AsRef<Path>,
{
    fn decrypt_to_u8(&self) -> crate::Result<Vec<u8>> {
        decrypt::to_u8(self.0.as_ref(), self.1.as_ref())
    }

    fn decrypt_to_string(&self) -> crate::Result<String> {
        decrypt::to_string(self.0.as_ref(), self.1.as_ref())
    }

    fn decrypt_zip_legacy(&self, target: impl AsRef<Path>) -> crate::Result<()> {
        decrypt::zip_legacy(self.0.as_ref(), self.1.as_ref(), target)
    }

    fn decrypt_zip(&self, target: impl AsRef<Path>) -> crate::Result<()> {
        decrypt::zip(self.0.as_ref(), self.1.as_ref(), target)
    }
}
