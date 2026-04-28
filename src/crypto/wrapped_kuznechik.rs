// src/crypto/wrapped_kuznechik.rs

use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use zeroize::Zeroizing;

use super::kuznechik_cipher::KuznechikCipher;

/// Магическая сигнатура обёрнутого контейнера
const MAGIC: [u8; 4] = *b"KRYB";
/// Версия формата
const VERSION: u8 = 1;

/// Реализация envelope encryption: ключ данных (DEK) шифруется мастер-ключом (KEK).
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

    /// Шифрует данные и сохраняет в формате KRYB.
    pub fn encrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        let dek = KuznechikCipher::generate_key();
        let iv_data = KuznechikCipher::generate_iv();

        let plaintext = fs::read(src).context("Не удалось прочитать исходный файл")?;
        let ciphertext_data = KuznechikCipher::encrypt_data(&plaintext, &dek, &iv_data)?;

        let iv_kek = KuznechikCipher::generate_iv();
        let cipher_dek = KuznechikCipher::encrypt_data(&dek, &self.kek, &iv_kek)?;
        if cipher_dek.len() != 48 {
            anyhow::bail!("Неожиданная длина зашифрованного DEK: {}", cipher_dek.len());
        }

        let mut out = fs::File::create(dest).context("Не удалось создать выходной файл")?;
        out.write_all(&MAGIC)?;
        out.write_all(&[VERSION])?;
        out.write_all(&iv_kek)?;
        out.write_all(&cipher_dek)?;
        out.write_all(&iv_data)?;
        out.write_all(&ciphertext_data)?;

        Ok(())
    }

    /// Дешифрует контейнер KRYB.
    pub fn decrypt_file(&self, src: &Path, dest: &Path) -> Result<()> {
        let mut file = fs::File::open(src).context("Не удалось открыть зашифрованный файл")?;

        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Не является обёрнутым контейнером Кузнечика (неверная магия)");
        }
        let mut version = [0; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            anyhow::bail!("Неподдерживаемая версия формата {}", version[0]);
        }

        let mut iv_kek = [0; 32];
        let mut cipher_dek = [0; 48];
        let mut iv_data = [0; 32];
        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut cipher_dek)?;
        file.read_exact(&mut iv_data)?;

        let dek_vec = KuznechikCipher::decrypt_data(&cipher_dek, &self.kek, &iv_kek)?;
        let dek: [u8; 32] = dek_vec.as_slice().try_into()
            .context("Длина DEK после расшифровки не совпадает")?;

        let mut ciphertext_data = Vec::new();
        file.read_to_end(&mut ciphertext_data)?;

        let plaintext = KuznechikCipher::decrypt_data(&ciphertext_data, &dek, &iv_data)?;
        fs::write(dest, plaintext).context("Не удалось записать расшифрованный файл")?;
        Ok(())
    }

    /// Перешифровывает DEK на месте: расшифровывает старым KEK и зашифровывает новым KEK.
    pub fn reencrypt_dek(old_kek: &[u8; 32], new_kek: &[u8; 32], path: &Path) -> Result<()> {
        let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;

        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            anyhow::bail!("Файл {} не является обёрнутым архивом", path.display());
        }
        let mut version = [0; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            anyhow::bail!("Неподдерживаемая версия формата");
        }

        let mut iv_kek = [0; 32];
        let mut cipher_dek = [0; 48];
        let mut iv_data = [0; 32];
        file.read_exact(&mut iv_kek)?;
        file.read_exact(&mut cipher_dek)?;
        file.read_exact(&mut iv_data)?;

        let dek_vec = KuznechikCipher::decrypt_data(&cipher_dek, old_kek, &iv_kek)?;
        let dek: [u8; 32] = dek_vec.as_slice().try_into()
            .context("Длина DEK при перешифровании не совпадает")?;

        let new_iv_kek = KuznechikCipher::generate_iv();
        let new_cipher_dek = KuznechikCipher::encrypt_data(&dek, new_kek, &new_iv_kek)?;
        if new_cipher_dek.len() != 48 {
            anyhow::bail!("Длина перешифрованного DEK не совпадает");
        }

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&MAGIC)?;
        file.write_all(&[VERSION])?;
        file.write_all(&new_iv_kek)?;
        file.write_all(&new_cipher_dek)?;
        file.write_all(&iv_data)?;

        Ok(())
    }

    /// Проверяет, является ли файл обёрнутым контейнером KRYB.
    pub fn is_wrapped(path: &Path) -> Result<bool> {
        let mut file = fs::File::open(path)?;
        let mut magic = [0; 4];
        if file.read_exact(&mut magic).is_ok() && magic == MAGIC {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}