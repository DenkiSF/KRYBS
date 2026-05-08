// src/crypto/wrapped_kuznechik.rs

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

use crate::cipher::core::Kuznechik;
use rand::RngCore;
use rand::rngs::OsRng;

const MAGIC: [u8; 4] = *b"KRYB";
const VERSION_MGM: u8 = 2; // устаревший формат (весь файл в одном блоке)
const VERSION_CHUNK: u8 = 3; // чанковый формат
const IV_LEN: usize = 8; // синхропосылка 8 байт
const MAC_LEN: usize = 16; // имитовставка 128 бит
const DEK_SIZE: usize = 32;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 МБ

/// Контейнер envelope encryption с MGM-шифрованием.
///
/// Формат файла (VERSION_CHUNK = 3):
///   MAGIC(4) | VERSION(1) | IV_KEK(8) | ENC_DEK(32) | MAC_DEK(16)
///   [CHUNK_LEN(4) | IV(8) | MAC(16) | CIPHERTEXT(CHUNK_LEN)] × n
#[derive(Debug, Clone)]
pub struct WrappedKuznechik {
    kek: Zeroizing<[u8; 32]>,
}

impl WrappedKuznechik {
    pub fn new(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
        }
    }

    /// Шифрует открытый файл `src` в обёрнутый контейнер `dest`.
    /// Файл читается по чанкам — потребление памяти O(CHUNK_SIZE).
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        // 1. Генерируем случайный DEK
        let mut dek = Zeroizing::new([0u8; DEK_SIZE]);
        OsRng.fill_bytes(&mut *dek);

        // 2. Шифруем DEK на KEK
        let mut iv_kek = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv_kek);
        let kek_cipher = Kuznechik::new(*self.kek);
        let (encrypted_dek, mac_dek) = kek_cipher.encrypt_mgm(&*dek, b"", &iv_kek, 128);

        // 3. Записываем заголовок
        let out_file = File::create(dest).context("Не удалось создать выходной файл")?;
        let mut out = BufWriter::new(out_file);
        out.write_all(&MAGIC)?;
        out.write_all(&[VERSION_CHUNK])?;
        out.write_all(&iv_kek)?;
        out.write_all(&encrypted_dek)?;
        out.write_all(&mac_dek)?;

        // 4. Читаем и шифруем по чанкам
        let in_file = File::open(src).context("Не удалось открыть исходный файл")?;
        let mut reader = BufReader::new(in_file);
        let data_cipher = Kuznechik::new(*dek);

        loop {
            let mut chunk = Vec::with_capacity(CHUNK_SIZE);
            reader
                .by_ref()
                .take(CHUNK_SIZE as u64)
                .read_to_end(&mut chunk)
                .context("Ошибка чтения исходного файла")?;
            if chunk.is_empty() {
                break;
            }

            let mut iv_chunk = [0u8; IV_LEN];
            OsRng.fill_bytes(&mut iv_chunk);
            let (ciphertext, mac) = data_cipher.encrypt_mgm(&chunk, b"", &iv_chunk, 128);

            out.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
            out.write_all(&iv_chunk)?;
            out.write_all(&mac)?;
            out.write_all(&ciphertext)?;
        }

        out.flush()
            .context("Не удалось завершить запись выходного файла")?;
        Ok(())
    }

    /// Дешифрует обёрнутый контейнер `src` в открытый файл `dest`.
    /// Поддерживает VERSION_MGM (2) и VERSION_CHUNK (3).
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        let mut file =
            BufReader::new(File::open(src).context("Не удалось открыть зашифрованный файл")?);

        // Читаем и проверяем магию и версию
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Не является обёрнутым контейнером (неверная магия)");
        }
        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION_MGM && version[0] != VERSION_CHUNK {
            anyhow::bail!("Неподдерживаемая версия формата {}", version[0]);
        }

        // Читаем общую часть заголовка
        let mut iv_kek = [0u8; IV_LEN];
        let mut encrypted_dek = [0u8; DEK_SIZE];
        let mut mac_dek = [0u8; MAC_LEN];
        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut encrypted_dek)?;
        file.read_exact(&mut mac_dek)?;

        // Расшифровываем DEK
        let kek_cipher = Kuznechik::new(*self.kek);
        let dek_vec = kek_cipher
            .decrypt_mgm(&encrypted_dek, b"", &iv_kek, &mac_dek, 128)
            .map_err(|e| anyhow::anyhow!("Не удалось расшифровать DEK: {}", e))?;
        let dek: [u8; DEK_SIZE] = dek_vec
            .as_slice()
            .try_into()
            .context("Некорректный размер DEK")?;
        let data_cipher = Kuznechik::new(dek);

        let out_file = File::create(dest).context("Не удалось создать выходной файл")?;
        let mut out = BufWriter::new(out_file);

        if version[0] == VERSION_MGM {
            // Устаревший формат: iv_data(8) | mac_data(16) | ciphertext(n)
            let mut iv_data = [0u8; IV_LEN];
            let mut mac_data = [0u8; MAC_LEN];
            file.read_exact(&mut iv_data)?;
            file.read_exact(&mut mac_data)?;
            let mut ciphertext = Vec::new();
            file.read_to_end(&mut ciphertext)?;
            let plaintext = data_cipher
                .decrypt_mgm(&ciphertext, b"", &iv_data, &mac_data, 128)
                .map_err(|e| anyhow::anyhow!("Не удалось расшифровать данные: {}", e))?;
            out.write_all(&plaintext)?;
        } else {
            // Чанковый формат: [CHUNK_LEN(4) | IV(8) | MAC(16) | CIPHERTEXT] × n
            let mut len_buf = [0u8; 4];
            loop {
                match file.read_exact(&mut len_buf) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e).context("Ошибка чтения размера чанка"),
                }
                let chunk_len = u32::from_be_bytes(len_buf) as usize;

                let mut iv_chunk = [0u8; IV_LEN];
                let mut mac_chunk = [0u8; MAC_LEN];
                file.read_exact(&mut iv_chunk)?;
                file.read_exact(&mut mac_chunk)?;

                let mut ciphertext = vec![0u8; chunk_len];
                file.read_exact(&mut ciphertext)?;

                let plaintext = data_cipher
                    .decrypt_mgm(&ciphertext, b"", &iv_chunk, &mac_chunk, 128)
                    .map_err(|e| anyhow::anyhow!("Не удалось расшифровать чанк: {}", e))?;
                out.write_all(&plaintext)?;
            }
        }

        out.flush()
            .context("Не удалось завершить запись расшифрованного файла")?;
        Ok(())
    }

    /// Атомарная смена KEK: записывает новый заголовок во временный файл, затем переименовывает.
    /// При сбое в середине операции оригинальный файл не повреждается.
    pub fn reencrypt_dek(old_kek: &[u8; 32], new_kek: &[u8; 32], path: &Path) -> Result<()> {
        // 1. Читаем и проверяем заголовок оригинала
        let mut file = File::open(path).context("Не удалось открыть файл для перешифрования")?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Файл не является обёрнутым контейнером");
        }
        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION_MGM && version[0] != VERSION_CHUNK {
            anyhow::bail!(
                "Версия формата {} не поддерживается для перешифрования",
                version[0]
            );
        }

        let mut iv_kek = [0u8; IV_LEN];
        let mut encrypted_dek = [0u8; DEK_SIZE];
        let mut mac_dek = [0u8; MAC_LEN];
        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut encrypted_dek)?;
        file.read_exact(&mut mac_dek)?;
        // file теперь указывает на начало данных (offset 61) — готово для копирования

        // 2. Расшифровываем DEK старым KEK
        let old_cipher = Kuznechik::new(*old_kek);
        let dek_vec = old_cipher
            .decrypt_mgm(&encrypted_dek, b"", &iv_kek, &mac_dek, 128)
            .map_err(|e| anyhow::anyhow!("Не удалось расшифровать DEK старым ключом: {}", e))?;
        let dek: [u8; DEK_SIZE] = dek_vec.as_slice().try_into()?;

        // 3. Шифруем DEK новым KEK
        let mut new_iv_kek = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut new_iv_kek);
        let new_cipher = Kuznechik::new(*new_kek);
        let (new_encrypted_dek, new_mac_dek) = new_cipher.encrypt_mgm(&dek, b"", &new_iv_kek, 128);

        // 4. Пишем новый заголовок + данные во временный файл
        let tmp_path = path.with_extension("rekey.tmp");
        let write_result: Result<()> = (|| {
            let tmp_file = File::create(&tmp_path)
                .context("Не удалось создать временный файл для перешифрования")?;
            let mut out = BufWriter::new(tmp_file);
            out.write_all(&MAGIC)?;
            out.write_all(&[version[0]])?;
            out.write_all(&new_iv_kek)?;
            out.write_all(&new_encrypted_dek)?;
            out.write_all(&new_mac_dek)?;
            // Копируем данные (чанки/шифротекст) из оригинала
            let mut reader = BufReader::new(file);
            io::copy(&mut reader, &mut out)
                .context("Ошибка копирования данных во временный файл")?;
            out.flush()?;
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        // 5. Атомарная замена оригинала временным файлом
        fs::rename(&tmp_path, path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            anyhow::anyhow!("Не удалось атомарно заменить файл: {}", e)
        })?;

        Ok(())
    }

    /// Проверяет, является ли файл обёрнутым контейнером KRYB.
    pub fn is_wrapped(path: &Path) -> Result<bool> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_ok() && magic == MAGIC {
            let mut version = [0u8; 1];
            if file.read_exact(&mut version).is_ok()
                && (version[0] == VERSION_MGM || version[0] == VERSION_CHUNK)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
