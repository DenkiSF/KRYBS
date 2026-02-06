// src/crypto/mod.rs
mod kuznechik_cipher;

use anyhow::Result;
use std::path::Path;

pub use kuznechik_cipher::KuznechikCipher;

/// Главный криптографический модуль системы
#[derive(Debug, Clone)]
pub struct Crypto {
    cipher: Option<KuznechikCipher>,
    enabled: bool,
}

impl Crypto {
    /// Создает криптомодуль с шифрованием
    pub fn new_with_key(key: [u8; 32]) -> Self {
        Self {
            cipher: Some(KuznechikCipher::new(key)),
            enabled: true,
        }
    }

    /// Создает криптомодуль без шифрования
    pub fn new_without_encryption() -> Self {
        Self {
            cipher: None,
            enabled: false,
        }
    }

    /// Проверяет, включено ли шифрование
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.cipher.is_some()
    }

    /// Шифрует файл
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(cipher) = &self.cipher {
            cipher.encrypt_file(src, dest)
        } else {
            // Без шифрования просто копируем файл
            std::fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Дешифрует файл
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(cipher) = &self.cipher {
            cipher.decrypt_file(src, dest)
        } else {
            // Без шифрования просто копируем файл
            std::fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Генерирует новый ключ шифрования
    pub fn generate_key() -> [u8; 32] {
        KuznechikCipher::generate_key()
    }

    /// Сохраняет ключ в файл
    pub fn save_key(key: &[u8; 32], path: &Path) -> Result<()> {
        // Дополнительно можно зашифровать ключ мастер-паролем
        std::fs::write(path, key)?;
        Ok(())
    }

    /// Загружает ключ из файла
    pub fn load_key(path: &Path) -> Result<[u8; 32]> {
        let data = std::fs::read(path)?;
        if data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key size"));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(key)
    }
}