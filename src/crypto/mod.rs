// src/crypto/mod.rs
mod kuznechik_cipher;

use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write};
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
            fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Дешифрует файл
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        if let Some(cipher) = &self.cipher {
            cipher.decrypt_file(src, dest)
        } else {
            // Без шифрования просто копируем файл
            fs::copy(src, dest)?;
            Ok(())
        }
    }

    /// Генерирует новый ключ шифрования
    pub fn generate_key() -> [u8; 32] {
        KuznechikCipher::generate_key()
    }

    /// Сохраняет ключ в файл
    pub fn save_key(key: &[u8; 32], path: &Path) -> Result<()> {
        let mut file = fs::File::create(path)
            .with_context(|| format!("Failed to create key file: {}", path.display()))?;
        
        file.write_all(key)?;
        
        // Устанавливаем права только для владельца (на Unix системах)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(path, perms)?;
        }
        
        Ok(())
    }

    /// Загружает ключ из файла
    pub fn load_key(path: &Path) -> Result<[u8; 32]> {
        let mut file = fs::File::open(path)
            .with_context(|| format!("Failed to open key file: {}", path.display()))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        
        if buffer.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid key size: expected 32 bytes, got {} bytes",
                buffer.len()
            ));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&buffer);
        Ok(key)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_crypto_without_encryption() -> Result<()> {
        let temp_dir = tempdir()?;
        let crypto = Crypto::new_without_encryption();
        
        let source_file = temp_dir.path().join("source.txt");
        let dest_file = temp_dir.path().join("dest.txt");
        
        fs::write(&source_file, b"test data")?;
        
        crypto.encrypt_file(&source_file, &dest_file)?;
        
        let encrypted = fs::read(&dest_file)?;
        assert_eq!(encrypted, b"test data");
        
        Ok(())
    }

    #[test]
    fn test_key_generation_and_save_load() -> Result<()> {
        let temp_dir = tempdir()?;
        
        let key = Crypto::generate_key();
        let key_file = temp_dir.path().join("test.key");
        
        // Сохраняем ключ
        Crypto::save_key(&key, &key_file)?;
        
        // Загружаем ключ
        let loaded_key = Crypto::load_key(&key_file)?;
        
        assert_eq!(key, loaded_key);
        Ok(())
    }

    #[test]
    fn test_invalid_key_file() {
        let temp_dir = tempdir().unwrap();
        let invalid_key_file = temp_dir.path().join("invalid.key");
        
        fs::write(&invalid_key_file, b"too short").unwrap();
        
        let result = Crypto::load_key(&invalid_key_file);
        assert!(result.is_err());
    }
}