// src/backup.rs

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use flate2::{read::GzDecoder, write::GzEncoder};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info};
use serde::Serialize;
use serde_json::{Value, json};
use std::fs;
use std::io::copy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::{Archive, Builder, Header};

use crate::config::Config;
use crate::crypto::Crypto;
use crate::source::BackupSource;
use crate::storage::{BackupInfo, BackupStorage, BackupType};
use crate::utils::{bytes_to_human, calculate_file_hash};

pub use crate::source::file::FileInfo;

// ============================================================================
// Структуры данных
// ============================================================================

/// Результат операции создания резервной копии
#[derive(Debug, Clone, Serialize)]
pub struct BackupResult {
    pub id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: usize,
    pub size_bytes: u64,
    pub archive_size: u64,
    pub encrypted: bool,
    pub duration_secs: f64,
}

/// Результат проверки резервной копии
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub backup_id: String,
    pub quick: bool,
    pub archive_ok: bool,
    pub decryption_ok: bool,
    pub extraction_ok: bool,
    pub files_checked: u64,
    pub files_matched: u64,
    pub files_missing: Vec<String>,
    pub files_corrupted: Vec<String>,
    pub errors: Vec<String>,
}

impl VerificationResult {
    /// Проверка прошла успешно, если все проверки выполнены и нет отсутствующих/повреждённых файлов
    pub fn is_ok(&self) -> bool {
        self.archive_ok
            && self.decryption_ok
            && self.extraction_ok
            && self.files_missing.is_empty()
            && self.files_corrupted.is_empty()
    }
}

/// Основной движок резервного копирования
#[derive(Debug)]
pub struct BackupEngine {
    pub storage: BackupStorage,
    pub config: Arc<Config>,
    pub crypto: Crypto,
}

/// Вспомогательная структура для результата создания архива одного источника
#[derive(Debug, Clone)]
pub struct SingleSourceResult {
    pub file_count: usize,
    pub metadata: Value,
}

// ============================================================================
// Реализация BackupEngine
// ============================================================================

impl BackupEngine {
    /// Создаёт новый экземпляр движка, инициализируя криптографию, если ключ доступен
    pub fn new(storage: BackupStorage, config: Config) -> Result<Self> {
        let crypto = if config.crypto.master_key_path.exists() {
            match Crypto::load_key(&config.crypto.master_key_path) {
                Ok(key) => {
                    println!("[ИНФО] Шифрование включено (Кузнечик ГОСТ 34.12-2018)");
                    Crypto::new_with_key(*key)
                }
                Err(e) => {
                    eprintln!(
                        "[ПРЕДУПРЕЖДЕНИЕ] Не удалось загрузить ключ шифрования: {}",
                        e
                    );
                    eprintln!("[ПРЕДУПРЕЖДЕНИЕ] Продолжаем без шифрования");
                    Crypto::new_without_encryption()
                }
            }
        } else {
            println!("[ИНФО] Ключ шифрования не найден, шифрование отключено");
            Crypto::new_without_encryption()
        };

        Ok(Self {
            storage,
            config: Arc::new(config),
            crypto,
        })
    }

    // ------------------------------------------------------------------------
    // Основной метод создания резервной копии по списку универсальных источников
    // ------------------------------------------------------------------------

    /// Создаёт полную резервную копию из переданных источников данных
    pub async fn create_backup_from_sources(
        &self,
        mut sources: Vec<Box<dyn BackupSource>>,
        profile_name: Option<&str>,
        progress: bool,
    ) -> Result<BackupResult> {
        let start_time = Utc::now();
        let profile = profile_name.unwrap_or("manual").to_string();

        info!(
            "Запуск резервного копирования: профиль '{}', источников: {}",
            profile,
            sources.len()
        );

        // Отфильтровываем пустые источники
        sources.retain(|s| !s.is_empty());
        if sources.is_empty() {
            bail!("Нет данных для резервного копирования: все источники пусты");
        }

        let total_size_hint: u64 = sources.iter().filter_map(|s| s.size_hint()).sum();

        info!(
            "Общий оценочный размер: {}",
            bytes_to_human(total_size_hint)
        );

        let backup_id = self.storage.generate_id(BackupType::Full, start_time);
        let backup_dir = self.storage.backup_path(&backup_id);
        fs::create_dir_all(&backup_dir).context("Не удалось создать каталог резервной копии")?;

        // === ОСНОВНАЯ ЛОГИКА: Обработка нескольких источников ===
        let mut source_archives = Vec::new();
        let mut total_file_count = 0;

        for (i, mut source) in sources.into_iter().enumerate() {
            let source_name = source.name().to_string();
            info!(
                "Обработка источника {}: {} ({} байт)",
                i,
                source_name,
                source.size_hint().unwrap_or(0)
            );

            // Создаём временный архив для текущего источника
            let source_tar_path = backup_dir.join(format!(
                "source_{}_{}.tar.gz",
                i,
                source_name.replace('/', "_")
            ));
            let source_tar_result = self
                .create_single_source_archive(source.as_mut(), &source_tar_path)
                .await?;
            let file_count = source_tar_result.file_count;
            source_archives.push((source_name, source_tar_path, source_tar_result));
            total_file_count += file_count;
        }

        // Объединяем все временные архивы в один финальный
        let final_archive_path = backup_dir.join("data.tar.gz");
        self.create_combined_archive(&source_archives, &final_archive_path, progress)?;

        let final_archive_size = fs::metadata(&final_archive_path)?.len();

        // Шифрование (если включено)
        let (encrypted_path, encrypted_size, is_encrypted) = if self.crypto.is_enabled() {
            let enc_path = final_archive_path.with_file_name("data.tar.gz.enc");
            info!("Шифрование объединённого архива...");
            self.crypto.encrypt_file(&final_archive_path, &enc_path)?;
            if self.config.crypto.delete_plain {
                fs::remove_file(&final_archive_path)?;
            }
            let size = fs::metadata(&enc_path)?.len();
            (enc_path, size, true)
        } else {
            (final_archive_path, final_archive_size, false)
        };

        // Формируем манифест до удаления временных файлов, чтобы прочитать их размеры
        let manifest = self.create_multi_source_manifest(&source_archives, is_encrypted)?;

        // Удаляем временные архивы источников – они больше не нужны
        for (_, source_path, _) in &source_archives {
            if source_path.exists() {
                fs::remove_file(source_path)?;
            }
        }
        let manifest_path = backup_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        let backup_info = BackupInfo {
            id: backup_id.clone(),
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.clone(),
            file_count: total_file_count as u64,
            size_encrypted: encrypted_size,
            checksum: Some(calculate_file_hash(&encrypted_path)?),
            encrypted: Some(is_encrypted),
        };

        self.storage.write_local_index(&backup_info)?;

        let end_time = Utc::now();
        let duration_secs = end_time
            .signed_duration_since(start_time)
            .num_milliseconds() as f64
            / 1000.0;

        let result = BackupResult {
            id: backup_id,
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile,
            file_count: total_file_count,
            size_bytes: total_size_hint,
            archive_size: encrypted_size,
            encrypted: is_encrypted,
            duration_secs,
        };

        info!("УСПЕХ: резервная копия создана {}", result.id);
        Ok(result)
    }

    /// Проверяет соответствие восстановленных файлов данным из манифеста
    pub fn verify_restored(&self, backup_id: &str, dest: &Path) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            backup_id: backup_id.to_string(),
            quick: false,
            archive_ok: true,
            decryption_ok: true,
            extraction_ok: true,
            files_checked: 0,
            files_matched: 0,
            files_missing: Vec::new(),
            files_corrupted: Vec::new(),
            errors: Vec::new(),
        };

        // Загружаем манифест
        let backup_path = self.storage.backup_path(backup_id);
        let manifest_path = backup_path.join("manifest.json");
        if !manifest_path.exists() {
            result.errors.push("Манифест не найден".to_string());
            return Ok(result);
        }
        let manifest_content = fs::read_to_string(manifest_path)?;
        let manifest: Value = serde_json::from_str(&manifest_content)?;

        // Получаем список файлов из манифеста
        let files = match manifest.get("files").and_then(|v| v.as_array()) {
            Some(f) => f,
            None => {
                result
                    .errors
                    .push("В манифесте отсутствует список файлов".to_string());
                return Ok(result);
            }
        };

        result.files_checked = files.len() as u64;

        for file_entry in files {
            let rel_path = file_entry["rel_path"].as_str().unwrap_or("");
            let expected_hash = file_entry["hash"].as_str().unwrap_or("");
            let expected_size = file_entry["size"].as_u64().unwrap_or(0);

            let file_path = dest.join(rel_path);

            if !file_path.exists() {
                result.files_missing.push(rel_path.to_string());
                continue;
            }

            let metadata = match fs::metadata(&file_path) {
                Ok(m) => m,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (не удалось прочитать метаданные)", rel_path));
                    continue;
                }
            };

            if metadata.len() != expected_size {
                result
                    .files_corrupted
                    .push(format!("{} (размер не совпадает)", rel_path));
                continue;
            }

            let actual_hash = match calculate_file_hash(&file_path) {
                Ok(h) => h,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (не удалось вычислить хеш)", rel_path));
                    continue;
                }
            };

            if actual_hash == expected_hash {
                result.files_matched += 1;
            } else {
                result
                    .files_corrupted
                    .push(format!("{} (хеш не совпадает)", rel_path));
            }
        }

        Ok(result)
    }

    /// Создаёт архив для одного источника (просто копирует поток данных в файл)
    async fn create_single_source_archive(
        &self,
        source: &mut dyn BackupSource,
        tar_path: &Path,
    ) -> Result<SingleSourceResult> {
        let source_meta = source.metadata();
        let file_count = source_meta
            .get("file_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let mut reader = source.read()?;
        let mut file = fs::File::create(tar_path)?;
        copy(&mut reader, &mut file)?;

        Ok(SingleSourceResult {
            file_count,
            metadata: source_meta,
        })
    }

    /// Объединяет архивы от разных источников в один общий tar.gz
    fn create_combined_archive(
        &self,
        source_archives: &[(String, PathBuf, SingleSourceResult)],
        final_path: &Path,
        _progress: bool,
    ) -> Result<()> {
        let file = fs::File::create(final_path)?;
        let encoder = GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = Builder::new(encoder);

        for (i, (source_name, source_path, _)) in source_archives.iter().enumerate() {
            let mut source_file = fs::File::open(source_path)?;
            let mut header = Header::new_gnu();
            header.set_size(fs::metadata(source_path)?.len());
            header.set_cksum();

            let archive_name = format!("source_{}.tar.gz", i);
            debug!(
                "Добавление в общий архив: {} -> {}",
                source_name, archive_name
            );

            tar_builder.append_data(&mut header, archive_name, &mut source_file)?;
        }

        tar_builder.into_inner()?.finish()?;
        Ok(())
    }

    /// Создаёт манифест в формате JSON для резервной копии из нескольких источников
    fn create_multi_source_manifest(
        &self,
        source_archives: &[(String, PathBuf, SingleSourceResult)],
        encrypted: bool,
    ) -> Result<Value> {
        let mut all_files = Vec::new();
        let mut sources_info = Vec::new();

        for (name, path, result) in source_archives {
            sources_info.push(json!({
                "name": name,
                "file_count": result.file_count,
                "size": fs::metadata(path).map(|m| m.len()).unwrap_or(0)
            }));

            if let Some(files) = result.metadata.get("files").and_then(|v| v.as_array()) {
                all_files.extend(files.clone());
            }
        }

        Ok(json!({
            "backup_type": "full",
            "timestamp": Utc::now().to_rfc3339(),
            "encrypted": encrypted,
            "encryption_algorithm": if encrypted { "ГОСТ Р 34.12-2018 (Кузнечик)" } else { "none" },
            "sources": sources_info,
            "files": all_files,
        }))
    }

    // ------------------------------------------------------------------------
    // Валидация архива
    // ------------------------------------------------------------------------

    /// Проверяет структуру архива (tar.gz), не заглядывая в содержимое
    pub fn validate_archive(&self, path: &Path) -> Result<()> {
        println!("[ИНФО] Проверка архива: {}", path.display());

        let file = fs::File::open(path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let mut count = 0;
        for entry in archive.entries()? {
            let entry = entry?;
            if entry.header().path().is_err() {
                return Err(anyhow::anyhow!("Некорректный путь в элементе архива"));
            }
            count += 1;
        }

        println!("[ИНФО] Проверка архива пройдена: {} файлов", count);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Верификация резервной копии
    // ------------------------------------------------------------------------

    /// Выполняет проверку целостности указанной резервной копии
    pub async fn verify_backup(
        &self,
        backup_id: &str,
        quick: bool,
        progress: bool,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            backup_id: backup_id.to_string(),
            quick,
            archive_ok: false,
            decryption_ok: false,
            extraction_ok: false,
            files_checked: 0,
            files_matched: 0,
            files_missing: Vec::new(),
            files_corrupted: Vec::new(),
            errors: Vec::new(),
        };

        let backup_info = match self.storage.read_backup_info(backup_id) {
            Ok(info) => info,
            Err(e) => {
                result
                    .errors
                    .push(format!("Не удалось прочитать информацию о копии: {}", e));
                return Ok(result);
            }
        };

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            result.errors.push("Архив не найден".to_string());
            return Ok(result);
        };

        let manifest_path = backup_path.join("manifest.json");
        if !manifest_path.exists() {
            result.errors.push("Файл манифеста не найден".to_string());
            return Ok(result);
        }

        result.archive_ok = true;

        // Создаём временную директорию для процесса верификации
        let temp_dir = tempfile::tempdir()?;
        let mut archive_to_use = archive_path.to_path_buf();

        if is_encrypted {
            if !self.crypto.is_enabled() {
                result
                    .errors
                    .push("Архив зашифрован, но шифрование отключено".to_string());
                return Ok(result);
            }

            println!("[ПРОВЕРКА] Тестирование расшифровки...");
            let decrypted_path = temp_dir.path().join("data.tar.gz");

            match self.crypto.decrypt_file(archive_path, &decrypted_path) {
                Ok(_) => {
                    result.decryption_ok = true;
                    archive_to_use = decrypted_path;
                }
                Err(e) => {
                    result.errors.push(format!("Ошибка расшифровки: {}", e));
                    return Ok(result);
                }
            }
        } else {
            result.decryption_ok = true;
        }

        println!("[ПРОВЕРКА] Проверка структуры архива...");
        let file = match std::fs::File::open(&archive_to_use) {
            Ok(f) => f,
            Err(e) => {
                result
                    .errors
                    .push(format!("Не удалось открыть архив: {}", e));
                return Ok(result);
            }
        };

        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        for entry in archive.entries()? {
            match entry {
                Ok(_) => {}
                Err(e) => {
                    result
                        .errors
                        .push(format!("Повреждённый элемент архива: {}", e));
                    result.extraction_ok = false;
                    return Ok(result);
                }
            }
        }
        result.extraction_ok = true;

        // Читаем реальное число файлов из манифеста.
        // entry_count — это число вложенных source-архивов, а не отдельных файлов.
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;
        result.files_checked = manifest["files"]
            .as_array()
            .map(|f| f.len() as u64)
            .unwrap_or(0);

        if quick {
            println!("[ПРОВЕРКА] Быстрая проверка пройдена (структура архива корректна)");
            return Ok(result);
        }

        println!("[ПРОВЕРКА] Выполняется полная проверка (сравнение содержимого файлов)...");
        let extract_path = temp_dir.path();

        let file = std::fs::File::open(&archive_to_use)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        if progress {
            println!("[ПРОВЕРКА] Извлечение архива для проверки...");
        }
        archive.unpack(extract_path)?;

        // Распаковываем все вложенные архивы источников
        let entries: Vec<_> = fs::read_dir(extract_path)?.collect::<Result<Vec<_>, _>>()?;
        for entry in entries {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("gz") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with("source_") && filename.ends_with(".tar.gz") {
                        println!("[ПРОВЕРКА] Извлечение вложенного архива: {}", filename);
                        let inner_file = fs::File::open(&path)?;
                        let inner_decoder = GzDecoder::new(inner_file);
                        let mut inner_archive = Archive::new(inner_decoder);
                        inner_archive.unpack(extract_path)?;
                        // Удаляем уже распакованный вложенный архив
                        fs::remove_file(&path)?;
                    }
                }
            }
        }

        let files = manifest["files"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Некорректный формат манифеста"))?;
        let total_files = files.len();

        let pb = if progress {
            let bar = indicatif::ProgressBar::new(total_files as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} Проверка файлов [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            bar.set_message("Проверка файлов...");
            Some(bar)
        } else {
            None
        };

        for file_entry in files {
            let rel_path = file_entry["rel_path"].as_str().unwrap_or("");
            let expected_hash = file_entry["hash"].as_str().unwrap_or("");
            let expected_size = file_entry["size"].as_u64().unwrap_or(0);

            let file_path = extract_path.join(rel_path);

            if !file_path.exists() {
                result.files_missing.push(rel_path.to_string());
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
                continue;
            }

            let metadata = match std::fs::metadata(&file_path) {
                Ok(m) => m,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (не удалось прочитать метаданные)", rel_path));
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    continue;
                }
            };

            if metadata.len() != expected_size {
                result
                    .files_corrupted
                    .push(format!("{} (размер не совпадает)", rel_path));
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
                continue;
            }

            let actual_hash = match calculate_file_hash(&file_path) {
                Ok(h) => h,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (не удалось вычислить хеш)", rel_path));
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    continue;
                }
            };

            if actual_hash == expected_hash {
                result.files_matched += 1;
            } else {
                result
                    .files_corrupted
                    .push(format!("{} (хеш не совпадает)", rel_path));
            }

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Проверка завершена");
        }

        result.files_checked = total_files as u64;
        Ok(result)
    }

    // ------------------------------------------------------------------------
    // Восстановление
    // ------------------------------------------------------------------------

    /// Восстанавливает данные из резервной копии в указанный каталог
    pub async fn restore_backup(
        &self,
        backup_id: &str,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        println!("[ИНФО] Восстановление резервной копии: {}", backup_id);
        println!("[ИНФО] Целевой каталог: {}", destination.display());

        let backup_info = self.storage.read_backup_info(backup_id).context(format!(
            "Не удалось прочитать информацию о копии: {}",
            backup_id
        ))?;

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            return Err(anyhow::anyhow!("Архив не найден: {}", backup_info.id));
        };

        println!("[ИНФО] Архив: {}", archive_path.display());
        println!("[ИНФО] Зашифрован: {}", is_encrypted);

        if is_encrypted && !self.crypto.is_enabled() {
            return Err(anyhow::anyhow!(
                "Резервная копия зашифрована, но шифрование не включено. Загрузите ключ шифрования."
            ));
        }

        let temp_dir = tempfile::tempdir()?;
        let temp_archive = temp_dir.path().join("data.tar.gz");

        if is_encrypted {
            println!("[ИНФО] Расшифровка архива с помощью шифра Кузнечик...");
            self.crypto
                .decrypt_file(archive_path, &temp_archive)
                .context("Не удалось расшифровать архив")?;
        } else {
            fs::copy(archive_path, &temp_archive)?;
        }

        self.extract_archive(
            &temp_archive,
            destination,
            specific_path,
            overwrite,
            progress,
        )
        .await?;

        println!(
            "[УСПЕХ] Восстановление завершено в {}",
            destination.display()
        );
        Ok(())
    }

    /// Распаковывает архив (возможно, составной) в целевой каталог
    /// Распаковывает архив (возможно, составной) в целевой каталог
    async fn extract_archive(
        &self,
        archive_path: &Path,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        let file = fs::File::open(archive_path).context(format!(
            "Не удалось открыть архив: {}",
            archive_path.display()
        ))?;

        let pb = if progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(ProgressStyle::default_spinner().template("{spinner} Извлечение: {msg}")?);
            pb.set_message("Начало...");
        }

        // Сначала распаковываем основной архив во временную директорию
        let temp_extract_dir = tempfile::tempdir()?;
        let mut archive = Archive::new(GzDecoder::new(file));
        archive.unpack(temp_extract_dir.path())?;

        // Затем распаковываем все вложенные архивы источников
        let entries: Vec<_> =
            fs::read_dir(temp_extract_dir.path())?.collect::<Result<Vec<_>, _>>()?;
        for entry in entries {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("gz") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with("source_") && filename.ends_with(".tar.gz") {
                        if let Some(ref pb) = pb {
                            pb.set_message(format!("Извлечение вложенного архива: {}", filename));
                        }
                        let inner_file = fs::File::open(&path)?;
                        let inner_decoder = GzDecoder::new(inner_file);
                        let mut inner_archive = Archive::new(inner_decoder);
                        inner_archive.unpack(temp_extract_dir.path())?;
                    }
                }
            }
        }

        // Удаляем служебные архивы источников, чтобы они не попали в результат восстановления
        let all_entries: Vec<_> =
            fs::read_dir(temp_extract_dir.path())?.collect::<Result<Vec<_>, _>>()?;
        for entry in all_entries {
            let fname = entry.file_name();
            if let Some(name) = fname.to_str() {
                if name.starts_with("source_")
                    && (name.ends_with(".tar.gz") || name.ends_with(".tgz"))
                {
                    fs::remove_file(entry.path())?;
                }
            }
        }

        // Копируем все файлы из временной директории в целевую с учётом фильтра и перезаписи
        let copy_options = fs_extra::dir::CopyOptions::new()
            .overwrite(overwrite)
            .skip_exist(!overwrite);

        let items_to_copy: Vec<_> = fs::read_dir(temp_extract_dir.path())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        for item in items_to_copy {
            if let Some(specific) = specific_path {
                if !item
                    .strip_prefix(temp_extract_dir.path())?
                    .starts_with(specific)
                {
                    continue;
                }
            }

            let dest_item = destination.join(item.strip_prefix(temp_extract_dir.path())?);
            if let Some(parent) = dest_item.parent() {
                fs::create_dir_all(parent)?;
            }

            if item.is_dir() {
                fs_extra::dir::copy(&item, destination, &copy_options)?;
            } else {
                fs::copy(&item, &dest_item)?;
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Извлечение завершено");
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Утилиты
    // ------------------------------------------------------------------------

    /// Возвращает статус шифрования
    pub fn encryption_status(&self) -> &'static str {
        if self.crypto.is_enabled() {
            "ВКЛЮЧЕНО (Кузнечик ГОСТ 34.12-2018)"
        } else {
            "ОТКЛЮЧЕНО"
        }
    }

    /// Проверяет, прошло ли достаточно времени с последней копии профиля
    pub fn check_backup_interval(
        &self,
        profile: &str,
        min_interval: Duration,
    ) -> Result<Option<Duration>> {
        let last_time = self.storage.last_backup_time_for_profile(profile)?;

        if let Some(last) = last_time {
            let elapsed = Utc::now() - last;
            if elapsed < min_interval {
                let time_left = min_interval - elapsed;
                return Ok(Some(time_left));
            }
        }

        Ok(None)
    }
}
