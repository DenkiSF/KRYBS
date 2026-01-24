// src/crypto/ctr.rs
use crate::crypto::kuznechik::{Kuznechik, BLOCK_SIZE, KEY_SIZE};
use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use streebog::{Digest, Streebog256};

const HEADER: &[u8; 4] = b"KRYB";
const VERSION: u8 = 0x01;
const NONCE_SIZE: usize = 16;
const MAC_SIZE: usize = 32; // Streebog256
const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB

pub struct CryptoFile;

impl CryptoFile {
    pub fn encrypt_file(input: &Path, output: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
        let input_file = File::open(input)
            .with_context(|| format!("Failed to open input file: {}", input.display()))?;
        let output_file = File::create(output)
            .with_context(|| format!("Failed to create output file: {}", output.display()))?;

        let mut reader = BufReader::new(input_file);
        let mut writer = BufWriter::new(output_file);

        // Генерируем nonce: 12 случайных байт + 4 нулевых байта счетчика
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce[0..12]);
        // Последние 4 байта (счетчик) остаются нулями

        // Пишем заголовок
        writer.write_all(HEADER)?;
        writer.write_all(&[VERSION])?;
        writer.write_all(&nonce)?;

        let kuz = Kuznechik::new(*master_key);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut counter: u32 = 0;

        // Создаем контекст для MAC
        let mut mac_ctx = Streebog256::new();

        // Обновляем MAC заголовком
        mac_ctx.update(HEADER);
        mac_ctx.update(&[VERSION]);
        mac_ctx.update(&nonce);

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Шифруем чанк в режиме CTR
            let encrypted_chunk = Self::ctr_transform(&kuz, &nonce, counter, &buffer[..bytes_read]);
            
            // Обновляем MAC шифртекстом
            mac_ctx.update(&encrypted_chunk);
            
            writer.write_all(&encrypted_chunk)?;
            
            // Увеличиваем счетчик на количество блоков
            let blocks = (bytes_read + BLOCK_SIZE - 1) / BLOCK_SIZE;
            counter += blocks as u32;
        }

        writer.flush()?;

        // Вычисляем MAC
        let mac = mac_ctx.finalize();
        
        // Записываем MAC в конец файла
        writer.write_all(&mac)?;
        writer.flush()?;

        Ok(())
    }

    pub fn decrypt_file(input: &Path, output: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
        let input_file = File::open(input)
            .with_context(|| format!("Failed to open input file: {}", input.display()))?;
        let output_file = File::create(output)
            .with_context(|| format!("Failed to create output file: {}", output.display()))?;

        let mut reader = BufReader::new(input_file);
        let mut writer = BufWriter::new(output_file);

        // Читаем заголовок
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        if &header != HEADER {
            return Err(anyhow::anyhow!("Invalid file header"));
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(anyhow::anyhow!("Unsupported version: {}", version[0]));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        reader.read_exact(&mut nonce)?;

        // Получаем размер файла для определения позиции MAC
        let file_size = reader.get_ref().metadata()?.len();
        let data_size = file_size - (HEADER.len() + 1 + NONCE_SIZE + MAC_SIZE) as u64;

        let kuz = Kuznechik::new(*master_key);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut counter: u32 = 0;
        let mut total_read: u64 = 0;

        // Создаем контекст для MAC
        let mut mac_ctx = Streebog256::new();
        mac_ctx.update(HEADER);
        mac_ctx.update(&[VERSION]);
        mac_ctx.update(&nonce);

        loop {
            let bytes_to_read = std::cmp::min(
                buffer.len(),
                (data_size - total_read) as usize,
            ) as usize;
            
            if bytes_to_read == 0 {
                break;
            }

            let bytes_read = reader.read(&mut buffer[..bytes_to_read])?;
            if bytes_read == 0 {
                break;
            }

            // Обновляем MAC считанным шифртекстом
            mac_ctx.update(&buffer[..bytes_read]);

            // Дешифруем чанк
            let decrypted_chunk = Self::ctr_transform(&kuz, &nonce, counter, &buffer[..bytes_read]);
            writer.write_all(&decrypted_chunk)?;

            total_read += bytes_read as u64;
            let blocks = (bytes_read + BLOCK_SIZE - 1) / BLOCK_SIZE;
            counter += blocks as u32;
        }

        writer.flush()?;

        // Читаем и проверяем MAC
        let mut stored_mac = [0u8; MAC_SIZE];
        reader.read_exact(&mut stored_mac)?;

        let computed_mac = mac_ctx.finalize();

        if stored_mac != computed_mac[..] {
            return Err(anyhow::anyhow!("MAC verification failed - file corrupted"));
        }

        Ok(())
    }

    pub fn verify_file(enc_file: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
        let input_file = File::open(enc_file)
            .with_context(|| format!("Failed to open file: {}", enc_file.display()))?;
        let mut reader = BufReader::new(input_file);

        // Читаем заголовок
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        if &header != HEADER {
            return Err(anyhow::anyhow!("Invalid file header"));
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(anyhow::anyhow!("Unsupported version: {}", version[0]));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        reader.read_exact(&mut nonce)?;

        // Получаем размер файла
        let file_size = reader.get_ref().metadata()?.len();
        let data_size = file_size - (HEADER.len() + 1 + NONCE_SIZE + MAC_SIZE) as u64;

        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut total_read: u64 = 0;

        // Вычисляем MAC
        let mut mac_ctx = Streebog256::new();
        mac_ctx.update(HEADER);
        mac_ctx.update(&[VERSION]);
        mac_ctx.update(&nonce);

        loop {
            let bytes_to_read = std::cmp::min(
                buffer.len(),
                (data_size - total_read) as usize,
            ) as usize;
            
            if bytes_to_read == 0 {
                break;
            }

            let bytes_read = reader.read(&mut buffer[..bytes_to_read])?;
            if bytes_read == 0 {
                break;
            }

            mac_ctx.update(&buffer[..bytes_read]);
            total_read += bytes_read as u64;
        }

        // Читаем и проверяем MAC
        let mut stored_mac = [0u8; MAC_SIZE];
        reader.read_exact(&mut stored_mac)?;

        let computed_mac = mac_ctx.finalize();

        if stored_mac != computed_mac[..] {
            return Err(anyhow::anyhow!("MAC verification failed"));
        }

        Ok(())
    }

    fn ctr_transform(kuz: &Kuznechik, nonce: &[u8; NONCE_SIZE], start_counter: u32, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = start_counter;

        for chunk in data.chunks(BLOCK_SIZE) {
            // Создаем блок для шифрования: nonce[0..12] + counter (big-endian)
            let mut block = [0u8; BLOCK_SIZE];
            block[0..12].copy_from_slice(&nonce[0..12]);
            block[12..16].copy_from_slice(&counter.to_be_bytes());

            // Генерируем ключевой поток
            let keystream = kuz.encrypt_block(block);

            // XOR с данными
            for (i, &byte) in chunk.iter().enumerate() {
                result.push(byte ^ keystream[i]);
            }

            counter += 1;
        }

        result
    }
}

// Функции для интеграции с существующим кодом
pub fn encrypt_file(input: &Path, output: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
    CryptoFile::encrypt_file(input, output, master_key)
}

pub fn decrypt_file(input: &Path, output: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
    CryptoFile::decrypt_file(input, output, master_key)
}

pub fn verify_file(enc_file: &Path, master_key: &[u8; KEY_SIZE]) -> Result<()> {
    CryptoFile::verify_file(enc_file, master_key)
}