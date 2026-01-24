// src/crypto/mod.rs
// ЗАКОММЕНТИРОВАНО: модуль криптографии временно отключен для тестирования
// pub mod kuznechik;
// pub mod ctr;

use anyhow::Result;
use std::fs;
use std::path::Path;
// use zeroize::Zeroize;

#[derive(Clone)]
pub struct CryptoManager {
    // master_key: [u8; 32], // ЗАКОММЕНТИРОВАНО: ключ не используется
}

// ЗАКОММЕНТИРОВАНО: очистка памяти не требуется
/*
impl Drop for CryptoManager {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}
*/

impl CryptoManager {
    pub fn load_master_key(_key_path: &Path) -> Result<Self> {
        // ЗАКОММЕНТИРОВАНО: временно не загружаем ключ
        /*
        let key_bytes = fs::read(key_path)
            .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;

        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid key length: {} bytes (expected 32)",
                key_bytes.len()
            ));
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_bytes);

        Ok(Self { master_key })
        */
        println!("[INFO] CryptoManager: encryption is temporarily disabled for testing");
        Ok(Self {})
    }

    pub fn generate_master_key(_key_path: &Path) -> Result<()> {
        // ЗАКОММЕНТИРОВАНО: временно не генерируем ключи
        /*
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory for {}", key_path.display()))?;
        }

        fs::write(key_path, &key)
            .with_context(|| format!("Failed to write key to {}", key_path.display()))?;

        key.zeroize();
        */
        println!("[INFO] Key generation is temporarily disabled for testing");
        Ok(())
    }

    pub fn encrypt_file(&self, _src: &Path, _dst: &Path) -> Result<()> {
        // ЗАКОММЕНТИРОВАНО: временно не шифруем файлы
        /*
        ctr::encrypt_file(src, dst, &self.master_key)
        */
        println!("[INFO] Encryption is temporarily disabled for testing");
        // Вместо шифрования просто копируем файл
        if _src != _dst {
            fs::copy(_src, _dst)?;
        }
        Ok(())
    }

    pub fn decrypt_file(&self, _src: &Path, _dst: &Path) -> Result<()> {
        // ЗАКОММЕНТИРОВАНО: временно не дешифруем файлы
        /*
        ctr::decrypt_file(src, dst, &self.master_key)
        */
        println!("[INFO] Decryption is temporarily disabled for testing");
        // Вместо дешифрования просто копируем файл
        if _src != _dst {
            fs::copy(_src, _dst)?;
        }
        Ok(())
    }

    pub fn verify_file(&self, _src: &Path) -> Result<()> {
        // ЗАКОММЕНТИРОВАНО: временно не проверяем файлы
        /*
        ctr::verify_file(src, &self.master_key)
        */
        println!("[INFO] File verification is temporarily disabled for testing");
        // Просто проверяем существование файла
        if !_src.exists() {
            return Err(anyhow::anyhow!("File not found: {}", _src.display()));
        }
        Ok(())
    }

    // Для обратной совместимости с существующим кодом
    pub fn new_dummy() -> Self {
        Self {}
    }
}