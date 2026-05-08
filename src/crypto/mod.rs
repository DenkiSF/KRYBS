// src/crypto/mod.rs

use anyhow::{Context, Result};
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

mod wrapped_kuznechik;
pub use wrapped_kuznechik::WrappedKuznechik;

/// Основной криптографический интерфейс, скрывающий детали реализации (envelope encryption).
#[derive(Debug, Clone)]
pub struct Crypto {
    /// Если Some – шифрование включено и используется обёрнутый контейнер.
    wrapped: Option<WrappedKuznechik>,
}

impl Crypto {
    /// Создаёт экземпляр с заданным мастер‑ключом (KEK).
    pub fn new_with_key(kek: [u8; 32]) -> Self {
        Self {
            wrapped: Some(WrappedKuznechik::new(kek)),
        }
    }

    /// Создаёт экземпляр без шифрования (все операции будут возвращать ошибку).
    pub fn new_without_encryption() -> Self {
        Self { wrapped: None }
    }

    /// Включено ли шифрование.
    pub fn is_enabled(&self) -> bool {
        self.wrapped.is_some()
    }

    // ---------- Операции шифрования/расшифрования файлов ----------

    /// Шифрует открытый файл `src` в обёрнутый контейнер `dest`.
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        match &self.wrapped {
            Some(w) => w.encrypt_file(src, dest),
            None => anyhow::bail!("Шифрование не включено"),
        }
    }

    /// Расшифровывает обёрнутый контейнер `src` в открытый файл `dest`.
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        match &self.wrapped {
            Some(w) => w.decrypt_file(src, dest),
            None => anyhow::bail!("Шифрование не включено"),
        }
    }

    // ---------- Управление ключами ----------

    /// Генерирует случайный 256‑битный ключ.
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Сохраняет ключ в бинарный файл (с правами 0o600 на Unix).
    pub fn save_key(key: &[u8; 32], path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Не удалось создать родительский каталог для ключа")?;
        }

        let mut file = File::create(path).context("Не удалось создать файл ключа")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        file.write_all(key).context("Не удалось записать ключ")?;
        Ok(())
    }

    /// Загружает ключ из файла (ожидается ровно 32 байта).
    pub fn load_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
        let mut key_bytes = [0u8; 32];
        let mut file = File::open(path).context("Не удалось открыть файл ключа")?;

        let n = file
            .read(&mut key_bytes)
            .context("Не удалось прочитать ключ")?;
        if n != 32 {
            anyhow::bail!("Файл ключа содержит {} байт, ожидалось 32", n);
        }

        let mut extra = [0u8; 1];
        if file
            .read(&mut extra)
            .context("Не удалось проверить размер файла ключа")?
            != 0
        {
            anyhow::bail!("Файл ключа длиннее 32 байт — возможно, указан неверный файл");
        }

        Ok(Zeroizing::new(key_bytes))
    }

    // ---------- Перешифрование (rekey) ----------

    /// Меняет мастер‑ключ для существующего контейнера (быстрая замена KEK).
    /// Перезаписывает только заголовок с зашифрованным DEK, не трогая данные.
    pub fn rekey_backup(
        encrypted_path: &Path,
        old_key: &[u8; 32],
        new_key: &[u8; 32],
    ) -> Result<()> {
        WrappedKuznechik::reencrypt_dek(old_key, new_key, encrypted_path)
    }
}
