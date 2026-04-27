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
/// Использует Envelope Encryption (DEK/KEK). Старый формат (прямое шифрование) также поддерживается.
#[derive(Debug, Clone)]
pub struct Crypto {
    wrapped: Option<WrappedKuznechik>,
    legacy_key: Option<Zeroizing<[u8; 32]>>,
    enabled: bool,
}

impl Crypto {
    /// Создаёт криптомодуль с шифрованием (новый формат обёртки).
    pub fn new_with_key(kek: [u8; 32]) -> Self {
        Self {
            wrapped: Some(WrappedKuznechik::new(kek)),
            legacy_key: Some(Zeroizing::new(kek)),
            enabled: true,
        }
    }

    /// Создаёт криптомодуль без шифрования.
    pub fn new_without_encryption() -> Self {
        Self {
            wrapped: None,
            legacy_key: None,
            enabled: false,
        }
    }

    /// Проверяет, включено ли шифрование.
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.wrapped.is_some()
    }

    /// Шифрует файл (всегда в новом формате обёртки).
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(wrapped) = &self.wrapped {
            wrapped.encrypt_file(src, dest)
        } else {
            fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Дешифрует файл с автоматическим определением формата (обёртка или legacy).
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(wrapped) = &self.wrapped {
            // Проверяем, является ли файл обёрнутым
            if WrappedKuznechik::is_wrapped(src)? {
                return wrapped.decrypt_file(src, dest);
            } else {
                // Пробуем расшифровать как старый формат (IV + ciphertext)
                if let Some(legacy_kek) = &self.legacy_key {
                    let cipher = KuznechikCipher::new(**legacy_kek);
                    return cipher.decrypt_file(src, dest);
                } else {
                    anyhow::bail!("No legacy key available for old format decryption");
                }
            }
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
            .with_context(|| format!("Failed to create key file: {}", path.display()))?;
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
            .with_context(|| format!("Failed to open key file: {}", path.display()))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        if buffer.len() != 32 {
            anyhow::bail!("Invalid key size: expected 32 bytes, got {}", buffer.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&buffer);
        Ok(Zeroizing::new(key))
    }

    /// Перешифровывает DEK в указанном зашифрованном файле бэкапа.
    /// Возвращает `true`, если операция выполнена (файл был обёрнут), иначе `false`.
    pub fn rekey_backup(backup_enc_path: &Path, old_key: &[u8; 32], new_key: &[u8; 32]) -> Result<()> {
        if !WrappedKuznechik::is_wrapped(backup_enc_path)? {
            anyhow::bail!("Backup is not in wrapped format, cannot rekey");
        }
        WrappedKuznechik::reencrypt_dek(old_key, new_key, backup_enc_path)?;
        Ok(())
    }
}