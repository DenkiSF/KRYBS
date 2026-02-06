// src/crypto/kuznechik_cipher.rs
use anyhow::Result;
use crate::kuznechik::core::Kuznechik;
use crate::kuznechik::operations::{BLOCK_SIZE, KEY_SIZE};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

const IV_SIZE: usize = BLOCK_SIZE * 2; // 32 байта для CBC

#[derive(Debug, Clone)]
pub struct KuznechikCipher {
    cipher: Kuznechik,
}

impl KuznechikCipher {
    /// Создает новый шифровальщик с ключом
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self {
            cipher: Kuznechik::new(key),
        }
    }

    /// Создает шифровальщик из KDF (с производным ключом)
    pub fn new_from_kdf(kin: &[u8], label: &[u8], seed: &[u8]) -> Self {
        Self {
            cipher: Kuznechik::new_from_kdf(kin, label, seed),
        }
    }

    /// Генерирует случайный ключ
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Генерирует случайный IV
    pub fn generate_iv() -> Vec<u8> {
        let mut iv = vec![0u8; IV_SIZE];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    /// Шифрует файл в режиме CBC
    pub fn encrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let iv = Self::generate_iv();
        let plaintext = fs::read(src_path)?;

        // Шифруем данные
        let ciphertext = self.encrypt_cbc(&plaintext, &iv)?;

        // Записываем IV + зашифрованные данные
        let mut file = fs::File::create(dest_path)?;
        file.write_all(&iv)?;
        file.write_all(&ciphertext)?;

        Ok(())
    }

    /// Дешифрует файл в режиме CBC
    pub fn decrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let mut file = fs::File::open(src_path)?;
        
        // Читаем IV
        let mut iv = vec![0u8; IV_SIZE];
        file.read_exact(&mut iv)?;

        // Читаем оставшиеся данные
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        // Дешифруем
        let plaintext = self.decrypt_cbc(&ciphertext, &iv)?;
        fs::write(dest_path, plaintext)?;

        Ok(())
    }

    /// Шифрует данные в режиме CBC
    pub fn encrypt_cbc(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        // Используем CBC шифрование из Kuznechik
        let ciphertext_blocks = self.cipher.encrypt_cbc(plaintext.to_vec(), iv.to_vec());
        
        // Конвертируем блоки в байты
        let mut result = Vec::new();
        for block in ciphertext_blocks {
            result.extend_from_slice(&block.get_block());
        }
        
        Ok(result)
    }

    /// Дешифрует данные в режиме CBC
    pub fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        // Используем CBC дешифрование из Kuznechik
        let plaintext_chunks = self.cipher.decrypt_cbc(ciphertext.to_vec(), iv.to_vec());
        
        // Объединяем все чанки в один вектор
        let mut result = Vec::new();
        for chunk in plaintext_chunks {
            result.extend_from_slice(&chunk);
        }
        
        Ok(result)
    }
}