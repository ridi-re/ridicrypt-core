use std::path::Path;

use crate::datastores;
use crate::decrypt;

pub trait DatastoresExt {
    fn decrypt_datastores(&self, path: impl AsRef<Path>) -> crate::Result<String>;
}

impl DatastoresExt for str {
    fn decrypt_datastores(&self, path: impl AsRef<Path>) -> crate::Result<String> {
        Ok(datastores::decrypt(self, path)?)
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
