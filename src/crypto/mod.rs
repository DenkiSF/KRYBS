// src/crypto/mod.rs
mod kuznechik_cipher;
mod wrapped_kuznechik;

use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub use kuznechik_cipher::KuznechikCipher;
pub use wrapped_kuznechik::WrappedKuznechik;

/// Главный криптографический модуль системы.
/// Использует схему envelope encryption (DEK/KEK).
#[derive(Debug, Clone)]
pub struct Crypto {
    wrapped: Option<WrappedKuznechik>,
    enabled: bool,
}

impl Crypto {
    /// Создаёт криптомодуль с шифрованием (новый формат обёртки).
    pub fn new_with_key(kek: [u8; 32]) -> Self {
        Self {
            wrapped: Some(WrappedKuznechik::new(kek)),
            enabled: true,
        }
    }

    /// Создаёт криптомодуль без шифрования.
    pub fn new_without_encryption() -> Self {
        Self {
            wrapped: None,
            enabled: false,
        }
    }

    /// Проверяет, включено ли шифрование.
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.wrapped.is_some()
    }

    /// Шифрует файл в формате обёртки.
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(wrapped) = &self.wrapped {
            wrapped.encrypt_file(src, dest)
        } else {
            fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Дешифрует файл (только обёрнутый формат).
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(wrapped) = &self.wrapped {
            if !WrappedKuznechik::is_wrapped(src)? {
                anyhow::bail!("Файл не является зашифрованным контейнером KRYB");
            }
            wrapped.decrypt_file(src, dest)
        } else {
            fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Генерирует новый случайный KEK (256 бит).
    pub fn generate_key() -> [u8; 32] {
        KuznechikCipher::generate_key()
    }

    /// Сохраняет KEK в файл (бинарный, 32 байта).
    pub fn save_key(key: &[u8; 32], path: &Path) -> Result<()> {
        let mut file = fs::File::create(path)
            .with_context(|| format!("Не удалось создать файл ключа: {}", path.display()))?;
        file.write_all(key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    /// Загружает KEK из файла.
    pub fn load_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
        let mut file = fs::File::open(path)
            .with_context(|| format!("Не удалось открыть файл ключа: {}", path.display()))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        if buffer.len() != 32 {
            anyhow::bail!("Некорректный размер ключа: ожидалось 32 байта, получено {}", buffer.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&buffer);
        Ok(Zeroizing::new(key))
    }

    /// Перешифровывает DEK в указанном зашифрованном файле бэкапа.
    /// Возвращает ошибку, если файл не является обёрнутым.
    pub fn rekey_backup(backup_enc_path: &Path, old_key: &[u8; 32], new_key: &[u8; 32]) -> Result<()> {
        if !WrappedKuznechik::is_wrapped(backup_enc_path)? {
            anyhow::bail!("Резервная копия не в обёрнутом формате, невозможно перешифровать");
        }
        WrappedKuznechik::reencrypt_dek(old_key, new_key, backup_enc_path)?;
        Ok(())
    }
}