// src/crypto/kuznechik_cipher.rs
use anyhow::{Context, Result};
use libgost_rs::Kuznechik;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 32; // 2 блока по 16 байт для режима CBC

/// Реализация блочного шифра «Кузнечик» в режиме CBC
pub struct KuznechikCipher {
    cipher: Kuznechik,
    key: Zeroizing<[u8; KEY_SIZE]>, // ключ хранится в Zeroizing для автоматической очистки
}

impl KuznechikCipher {
    /// Создаёт новый экземпляр с заданным ключом
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self {
            cipher: Kuznechik::new(key),
            key: Zeroizing::new(key),
        }
    }

    /// Генерирует случайный ключ
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Генерирует случайный вектор инициализации (32 байта)
    pub fn generate_iv() -> [u8; IV_SIZE] {
        let mut iv = [0u8; IV_SIZE];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    /// Шифрует файл в режиме CBC и сохраняет результат вместе с IV
    pub fn encrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let plaintext = fs::read(src_path)
            .with_context(|| format!("Не удалось прочитать исходный файл: {}", src_path.display()))?;

        if plaintext.is_empty() {
            let iv = Self::generate_iv();
            let mut file = fs::File::create(dest_path)?;
            file.write_all(&iv)?;
            return Ok(());
        }

        let padded_plaintext = Self::padding(&plaintext);
        let iv = Self::generate_iv();
        let iv_vec = iv.to_vec();

        let ciphertext_blocks = self.cipher.encrypt_cbc(padded_plaintext, iv_vec.clone());

        let total_size: usize = ciphertext_blocks.iter().map(|b| b.len()).sum();
        let mut ciphertext = Vec::with_capacity(total_size);
        for block in ciphertext_blocks {
            ciphertext.extend_from_slice(&block);
        }

        let mut file = fs::File::create(dest_path)
            .with_context(|| format!("Не удалось создать выходной файл: {}", dest_path.display()))?;
        file.write_all(&iv)?;
        file.write_all(&ciphertext)?;

        Ok(())
    }

    /// Дешифрует файл в режиме CBC, ожидая IV в начале
    pub fn decrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let mut file = fs::File::open(src_path)
            .with_context(|| format!("Не удалось открыть исходный файл: {}", src_path.display()))?;

        let mut iv = [0u8; IV_SIZE];
        match file.read_exact(&mut iv) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e).context("Не удалось прочитать IV из зашифрованного файла"),
        }

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        if ciphertext.is_empty() {
            fs::write(dest_path, b"")?;
            return Ok(());
        }

        let plaintext_chunks = self.cipher.decrypt_cbc(ciphertext, iv.to_vec());

        let mut plaintext = Vec::new();
        for chunk in plaintext_chunks {
            plaintext.extend_from_slice(&chunk);
        }

        let unpadded = Self::unpadding(&plaintext)
            .with_context(|| "Не удалось удалить дополнение PKCS#7")?;

        fs::write(dest_path, unpadded)
            .with_context(|| format!("Не удалось записать выходной файл: {}", dest_path.display()))?;

        Ok(())
    }

    /// Добавляет PKCS#7-дополнение
    pub fn padding(data: &[u8]) -> Vec<u8> {
        let block_size = BLOCK_SIZE;
        let data_len = data.len();
        let padding_len = block_size - (data_len % block_size);

        let mut padded = Vec::with_capacity(data_len + padding_len);
        padded.extend_from_slice(data);
        padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        padded
    }

    /// Убирает PKCS#7-дополнение
    pub fn unpadding(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let last_byte = *data.last().unwrap() as usize;
        if last_byte == 0 || last_byte > BLOCK_SIZE || last_byte > data.len() {
            return Err(anyhow::anyhow!("Некорректная длина дополнения: {}", last_byte));
        }

        let padding_start = data.len() - last_byte;
        for &byte in &data[padding_start..] {
            if byte as usize != last_byte {
                return Err(anyhow::anyhow!(
                    "Некорректный байт дополнения: ожидалось {}, получено {}",
                    last_byte, byte
                ));
            }
        }

        Ok(data[..padding_start].to_vec())
    }

    /// Шифрует произвольные данные в режиме CBC с заданным ключом и IV.
    /// Возвращает зашифрованные байты (содержащие PKCS#7 дополнение).
    pub fn encrypt_data(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Kuznechik::new(*key);
        let padded = Self::padding(data);
        let ciphertext_blocks = cipher.encrypt_cbc(padded, iv.to_vec());
        Ok(ciphertext_blocks.into_iter().flatten().collect())
    }

    /// Дешифрует данные, зашифрованные `encrypt_data`.
    pub fn decrypt_data(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Kuznechik::new(*key);
        let plaintext_chunks = cipher.decrypt_cbc(ciphertext.to_vec(), iv.to_vec());
        let mut plaintext = Vec::new();
        for chunk in plaintext_chunks {
            plaintext.extend_from_slice(&chunk);
        }
        Self::unpadding(&plaintext)
    }
}

impl Clone for KuznechikCipher {
    fn clone(&self) -> Self {
        Self::new(*self.key)
    }
}

impl std::fmt::Debug for KuznechikCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KuznechikCipher")
            .field("cipher", &"экземпляр Кузнечика")
            .finish()
    }
}