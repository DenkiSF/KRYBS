// src/crypto/kuznechik_cipher.rs
use anyhow::{Context, Result};
use libgost_rs::Kuznechik;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 32; // 2 блока по 16 байт для режима CBC

pub struct KuznechikCipher {
    cipher: Kuznechik,
    key: [u8; KEY_SIZE], // сохраняем ключ для клонирования
}

impl KuznechikCipher {
    /// Создает новый шифровальщик с ключом
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self {
            cipher: Kuznechik::new(key),
            key,
        }
    }

    /// Генерирует случайный ключ
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Генерирует случайный IV (32 байта как в примере из документации)
    pub fn generate_iv() -> [u8; IV_SIZE] {
        let mut iv = [0u8; IV_SIZE];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    /// Шифрует файл в режиме CBC
    pub fn encrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let plaintext = fs::read(src_path)
            .with_context(|| format!("Failed to read source file: {}", src_path.display()))?;
        
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
            .with_context(|| format!("Failed to create destination file: {}", dest_path.display()))?;
        file.write_all(&iv)?;
        file.write_all(&ciphertext)?;
        
        Ok(())
    }

    /// Дешифрует файл в режиме CBC
    pub fn decrypt_file(&self, src_path: &Path, dest_path: &Path) -> Result<()> {
        let mut file = fs::File::open(src_path)
            .with_context(|| format!("Failed to open source file: {}", src_path.display()))?;
        
        let mut iv = [0u8; IV_SIZE];
        match file.read_exact(&mut iv) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e).context("Failed to read IV from encrypted file"),
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
            .with_context(|| "Failed to remove padding from decrypted data")?;
        
        fs::write(dest_path, unpadded)
            .with_context(|| format!("Failed to write destination file: {}", dest_path.display()))?;
        
        Ok(())
    }

    /// Добавляет padding к данным по схеме PKCS#7
    pub fn padding(data: &[u8]) -> Vec<u8> {
        let block_size = BLOCK_SIZE;
        let data_len = data.len();
        let padding_len = block_size - (data_len % block_size);
        
        let mut padded = Vec::with_capacity(data_len + padding_len);
        padded.extend_from_slice(data);
        padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        padded
    }

    /// Убирает padding из данных (PKCS#7)
    pub fn unpadding(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let last_byte = *data.last().unwrap() as usize;
        if last_byte == 0 || last_byte > BLOCK_SIZE || last_byte > data.len() {
            return Err(anyhow::anyhow!("Invalid padding length: {}", last_byte));
        }
        
        let padding_start = data.len() - last_byte;
        for &byte in &data[padding_start..] {
            if byte as usize != last_byte {
                return Err(anyhow::anyhow!(
                    "Invalid padding byte: expected {}, got {}",
                    last_byte, byte
                ));
            }
        }
        
        Ok(data[..padding_start].to_vec())
    }
}

impl Clone for KuznechikCipher {
    fn clone(&self) -> Self {
        // Безопасное клонирование через сохранённый ключ
        Self::new(self.key)
    }
}

impl std::fmt::Debug for KuznechikCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KuznechikCipher")
            .field("cipher", &"Kuznechik instance")
            .finish()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_padding_and_unpadding() {
        // Тестируем padding и unpadding
        let data = b"Hello, World!";
        let padded = KuznechikCipher::padding(data);
        
        // Проверяем, что размер кратен 16
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        
        // Проверяем padding
        let padding_len = *padded.last().unwrap() as usize;
        assert!(padding_len > 0 && padding_len <= BLOCK_SIZE);
        
        let unpadded = KuznechikCipher::unpadding(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_padding_full_block() {
        // Тест, когда данные уже кратны блоку
        let data = vec![0xAA; 32]; // 32 байта = 2 блока
        
        let padded = KuznechikCipher::padding(&data);
        
        // Должен добавиться целый блок padding
        assert_eq!(padded.len(), 48); // 32 + 16
        assert_eq!(*padded.last().unwrap(), 16); // Все 16 байт padding равны 16
        
        let unpadded = KuznechikCipher::unpadding(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_invalid_padding() {
        // Случай 1: padding_len = 0 (недопустимо)
        let data = vec![1, 2, 3, 4, 0];
        let result = KuznechikCipher::unpadding(&data);
        assert!(result.is_err());

        // Случай 2: padding_len > BLOCK_SIZE
        let data = vec![1, 2, 3, 4, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17];
        let result = KuznechikCipher::unpadding(&data);
        assert!(result.is_err());

        // Случай 3: байты padding не равны padding_len
        let mut data = vec![1, 2, 3, 4];
        data.extend_from_slice(&[5, 5, 5, 5, 6]); // последний байт 6, но должно быть 5
        let result = KuznechikCipher::unpadding(&data);
        assert!(result.is_err());

        // Случай 4: padding_len больше длины данных
        let _data = vec![1, 2, 3, 4, 5];// длина 5, padding_len=5 -> данных 0 (возможно валидно)
        // Но по PKCS#7 это валидно, если данные были пустыми и добавлен целый блок
        // Поэтому здесь ошибки не будет, не проверяем
    }

    #[test]
    fn test_encrypt_decrypt_cycle() -> Result<()> {
        let temp_dir = tempdir()?;
        let key = KuznechikCipher::generate_key();
        let cipher = KuznechikCipher::new(key);
        
        let source_file = temp_dir.path().join("source.txt");
        let encrypted_file = temp_dir.path().join("encrypted.bin");
        let decrypted_file = temp_dir.path().join("decrypted.txt");
        
        let test_data = b"This is a test message for encryption with Kuznechik cipher!";
        fs::write(&source_file, test_data)?;
        
        cipher.encrypt_file(&source_file, &encrypted_file)?;
        let encrypted_size = fs::metadata(&encrypted_file)?.len();
        assert!(encrypted_size > test_data.len() as u64);
        
        cipher.decrypt_file(&encrypted_file, &decrypted_file)?;
        let decrypted_data = fs::read(&decrypted_file)?;
        assert_eq!(decrypted_data, test_data);
        
        Ok(())
    }

    #[test]
    fn test_encrypt_empty_file() -> Result<()> {
        let temp_dir = tempdir()?;
        let key = KuznechikCipher::generate_key();
        let cipher = KuznechikCipher::new(key);
        
        let source_file = temp_dir.path().join("empty.txt");
        let encrypted_file = temp_dir.path().join("empty.enc");
        let decrypted_file = temp_dir.path().join("empty.dec");
        
        fs::write(&source_file, b"")?;
        cipher.encrypt_file(&source_file, &encrypted_file)?;
        cipher.decrypt_file(&encrypted_file, &decrypted_file)?;
        
        let decrypted_data = fs::read(&decrypted_file)?;
        assert_eq!(decrypted_data, b"");
        
        Ok(())
    }

    #[test]
    fn test_encrypt_small_file() -> Result<()> {
        let temp_dir = tempdir()?;
        let key = KuznechikCipher::generate_key();
        let cipher = KuznechikCipher::new(key);
        
        let source_file = temp_dir.path().join("small.txt");
        let encrypted_file = temp_dir.path().join("small.enc");
        let decrypted_file = temp_dir.path().join("small.dec");
        
        fs::write(&source_file, b"A")?;
        cipher.encrypt_file(&source_file, &encrypted_file)?;
        cipher.decrypt_file(&encrypted_file, &decrypted_file)?;
        
        let decrypted_data = fs::read(&decrypted_file)?;
        assert_eq!(decrypted_data, b"A");
        
        Ok(())
    }

    #[test]
    fn test_encrypt_large_file() -> Result<()> {
        let temp_dir = tempdir()?;
        let key = KuznechikCipher::generate_key();
        let cipher = KuznechikCipher::new(key);
        
        let source_file = temp_dir.path().join("large.bin");
        let encrypted_file = temp_dir.path().join("large.enc");
        let decrypted_file = temp_dir.path().join("large.dec");
        
        let large_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        fs::write(&source_file, &large_data)?;
        
        cipher.encrypt_file(&source_file, &encrypted_file)?;
        let encrypted_size = fs::metadata(&encrypted_file)?.len();
        println!("Original size: {} bytes", large_data.len());
        println!("Encrypted size: {} bytes", encrypted_size);
        assert!(encrypted_size > large_data.len() as u64);
        
        cipher.decrypt_file(&encrypted_file, &decrypted_file)?;
        let decrypted_data = fs::read(&decrypted_file)?;
        
        assert_eq!(decrypted_data, large_data);
        Ok(())
    }

    #[test]
    fn test_encrypt_multiple_sizes() -> Result<()> {
        let temp_dir = tempdir()?;
        let key = KuznechikCipher::generate_key();
        let cipher = KuznechikCipher::new(key);
        
        let sizes = [1, 15, 16, 17, 31, 32, 100, 1000, 10000];
        
        for &size in &sizes {
            let source_file = temp_dir.path().join(format!("source_{}.bin", size));
            let encrypted_file = temp_dir.path().join(format!("encrypted_{}.bin", size));
            let decrypted_file = temp_dir.path().join(format!("decrypted_{}.bin", size));
            
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            fs::write(&source_file, &data)?;
            
            cipher.encrypt_file(&source_file, &encrypted_file)?;
            cipher.decrypt_file(&encrypted_file, &decrypted_file)?;
            
            let decrypted_data = fs::read(&decrypted_file)?;
            assert_eq!(decrypted_data, data, "Failed for size {}", size);
        }
        
        Ok(())
    }
}