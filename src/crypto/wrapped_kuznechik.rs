// src/crypto/wrapped_kuznechik.rs

use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use zeroize::Zeroizing;

use crate::cipher::core::Kuznechik;
use rand::rngs::OsRng;
use rand::RngCore;

const MAGIC: [u8; 4] = *b"KRYB";
const VERSION_MGM: u8 = 2;          // новая версия с MGM
const IV_LEN: usize = 8;            // синхропосылка 8 байт
const MAC_LEN: usize = 16;          // имитовставка 128 бит
const DEK_SIZE: usize = 32;

/// Контейнер envelope encryption с MGM-шифрованием.
#[derive(Debug, Clone)]
pub struct WrappedKuznechik {
    kek: Zeroizing<[u8; 32]>,
}

impl WrappedKuznechik {
    pub fn new(kek: [u8; 32]) -> Self {
        Self { kek: Zeroizing::new(kek) }
    }

    /// Шифрует открытый файл `src` в обёрнутый контейнер `dest`.
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        // 1. Генерируем случайный DEK
        let mut dek = [0u8; DEK_SIZE];
        OsRng.fill_bytes(&mut dek);

        // 2. Читаем открытые данные
        let plaintext = fs::read(src).context("Не удалось прочитать исходный файл")?;

        // 3. Шифруем данные на DEK (MGM)
        let mut iv_data = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv_data);
        let data_cipher = Kuznechik::new(dek);
        let (ciphertext_data, mac_data) = data_cipher.encrypt_mgm(&plaintext, b"", &iv_data, 128);

        // 4. Шифруем DEK на KEK (MGM)
        let mut iv_kek = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv_kek);
        let kek_cipher = Kuznechik::new(*self.kek);
        let (encrypted_dek, mac_dek) = kek_cipher.encrypt_mgm(&dek, b"", &iv_kek, 128);

        // 5. Записываем контейнер
        let mut out = File::create(dest).context("Не удалось создать выходной файл")?;
        out.write_all(&MAGIC)?;
        out.write_all(&[VERSION_MGM])?;
        out.write_all(&iv_kek)?;
        out.write_all(&encrypted_dek)?;
        out.write_all(&mac_dek)?;
        out.write_all(&iv_data)?;
        out.write_all(&mac_data)?;
        out.write_all(&ciphertext_data)?;

        Ok(())
    }

    /// Дешифрует обёрнутый контейнер `src` в открытый файл `dest`.
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        let mut file = File::open(src).context("Не удалось открыть зашифрованный файл")?;

        // Читаем и проверяем магию и версию
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Не является обёрнутым контейнером (неверная магия)");
        }
        let mut version = [0; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION_MGM {
            anyhow::bail!("Неподдерживаемая версия формата {}", version[0]);
        }

        // Читаем заголовок: iv_kek, encrypted_dek, mac_dek, iv_data, mac_data
        let mut iv_kek = [0u8; IV_LEN];
        let mut encrypted_dek = [0u8; DEK_SIZE];   // шифротекст DEK ровно 32 байта
        let mut mac_dek = [0u8; MAC_LEN];
        let mut iv_data = [0u8; IV_LEN];
        let mut mac_data = [0u8; MAC_LEN];

        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut encrypted_dek)?;
        file.read_exact(&mut mac_dek)?;
        file.read_exact(&mut iv_data)?;
        file.read_exact(&mut mac_data)?;

        // Расшифровываем DEK с помощью KEK
        let kek_cipher = Kuznechik::new(*self.kek);
        let dek_vec = kek_cipher.decrypt_mgm(&encrypted_dek, b"", &iv_kek, &mac_dek, 128)
            .map_err(|e| anyhow::anyhow!("Не удалось расшифровать DEK: {}", e))?;
        let dek: [u8; DEK_SIZE] = dek_vec.as_slice().try_into()
            .context("Некорректный размер DEK")?;

        // Читаем оставшийся шифротекст данных
        let mut ciphertext_data = Vec::new();
        file.read_to_end(&mut ciphertext_data)?;

        // Расшифровываем данные
        let data_cipher = Kuznechik::new(dek);
        let plaintext = data_cipher.decrypt_mgm(&ciphertext_data, b"", &iv_data, &mac_data, 128)
            .map_err(|e| anyhow::anyhow!("Не удалось расшифровать данные: {}", e))?;

        fs::write(dest, plaintext).context("Не удалось записать расшифрованный файл")?;
        Ok(())
    }

    /// Быстрая смена KEK: перезаписывает только iv_kek, encrypted_dek и mac_dek в заголовке.
    pub fn reencrypt_dek(old_kek: &[u8; 32], new_kek: &[u8; 32], path: &Path) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Файл не является обёрнутым контейнером");
        }
        let mut version = [0; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION_MGM {
            anyhow::bail!("Версия формата {} не поддерживается для перешифрования", version[0]);
        }

        let mut iv_kek = [0u8; IV_LEN];
        let mut encrypted_dek = [0u8; DEK_SIZE];
        let mut mac_dek = [0u8; MAC_LEN];
        // Пропускаем iv_data и mac_data (мы их не меняем)
        let mut iv_data = [0u8; IV_LEN];
        let mut mac_data = [0u8; MAC_LEN];

        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut encrypted_dek)?;
        file.read_exact(&mut mac_dek)?;
        file.read_exact(&mut iv_data)?;
        file.read_exact(&mut mac_data)?;

        // Расшифровываем DEK старым KEK
        let old_cipher = Kuznechik::new(*old_kek);
        let dek_vec = old_cipher.decrypt_mgm(&encrypted_dek, b"", &iv_kek, &mac_dek, 128)
            .map_err(|e| anyhow::anyhow!("Не удалось расшифровать DEK старым ключом: {}", e))?;
        let dek: [u8; DEK_SIZE] = dek_vec.as_slice().try_into()?;

        // Зашифровываем DEK новым KEK
        let mut new_iv_kek = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut new_iv_kek);
        let new_cipher = Kuznechik::new(*new_kek);
        let (new_encrypted_dek, new_mac_dek) = new_cipher.encrypt_mgm(&dek, b"", &new_iv_kek, 128);

        // Перезаписываем только iv_kek, encrypted_dek, mac_dek в начале файла
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&MAGIC)?;
        file.write_all(&[VERSION_MGM])?;
        file.write_all(&new_iv_kek)?;
        file.write_all(&new_encrypted_dek)?;
        file.write_all(&new_mac_dek)?;
        // Оставшаяся часть файла (iv_data, mac_data, ciphertext) остаётся без изменений

        Ok(())
    }

    /// Проверяет, является ли файл обёрнутым контейнером KRYB (версии 2).
    pub fn is_wrapped(path: &Path) -> Result<bool> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };
        let mut magic = [0; 4];
        if file.read_exact(&mut magic).is_ok() && magic == MAGIC {
            let mut version = [0; 1];
            if file.read_exact(&mut version).is_ok() && version[0] == VERSION_MGM {
                return Ok(true);
            }
        }
        Ok(false)
    }
}