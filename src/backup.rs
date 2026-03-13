// src/backup.rs

use anyhow::{bail, Context, Result};
use log::info;
use serde_json::{json, Value};
use std::fs;
use std::io::copy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use flate2::{read::GzDecoder, write::GzEncoder};
use tar::{Archive, Builder, Header};
use indicatif::{ProgressBar, ProgressStyle};
use filetime::FileTime;
use serde::Serialize;

use crate::config::Config;
use crate::crypto::Crypto;
use crate::source::{BackupSource, file::FileSource};
use crate::storage::{BackupInfo, BackupStorage, BackupType};
use crate::utils::{calculate_file_hash, bytes_to_human};

#[cfg(unix)]
use nix::unistd::{chown, Gid, Uid};

pub use crate::source::file::FileInfo;

// ============================================================================
// Structures
// ============================================================================

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
    pub fn is_ok(&self) -> bool {
        self.archive_ok
            && self.decryption_ok
            && self.extraction_ok
            && self.files_missing.is_empty()
            && self.files_corrupted.is_empty()
    }
}

#[derive(Debug)]
pub struct BackupEngine {
    pub storage: BackupStorage,
    pub config: Arc<Config>,
    pub crypto: Crypto,
}

#[derive(Debug, Clone)]
pub struct SingleSourceResult {
    pub file_count: usize,
    pub metadata: Value,
}

// ============================================================================
// Implementation BackupEngine
// ============================================================================

impl BackupEngine {
    pub fn new(storage: BackupStorage, config: Config) -> Result<Self> {
        let crypto = if config.crypto.master_key_path.exists() {
            match Crypto::load_key(&config.crypto.master_key_path) {
                Ok(key) => {
                    println!("[INFO] Encryption enabled with Kuznechik cipher");
                    Crypto::new_with_key(*key)  // разыменовываем Zeroizing
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to load encryption key: {}", e);
                    eprintln!("[WARN] Continuing without encryption");
                    Crypto::new_without_encryption()
                }
            }
        } else {
            println!("[INFO] Encryption key not found, encryption disabled");
            Crypto::new_without_encryption()
        };

        Ok(Self {
            storage,
            config: Arc::new(config),
            crypto,
        })
    }

    // ------------------------------------------------------------------------
    // New core method: create backup from generic sources
    // ------------------------------------------------------------------------

    pub async fn create_backup_from_sources(
        &self,
        mut sources: Vec<Box<dyn BackupSource>>,
        profilename: Option<&str>,
        progress: bool,
    ) -> Result<BackupResult> {
        let start_time = Utc::now();
        let profile = profilename.unwrap_or("manual").to_string();
        
        info!("Starting backup for profile: {}, sources: {}", profile, sources.len());
        
        // Фильтр пустых источников
        sources.retain(|s| !s.is_empty());
        if sources.is_empty() {
            bail!("No data to backup: all sources empty");
        }
        
        let total_size_hint: u64 = sources.iter()
            .filter_map(|s| s.size_hint())
            .sum();
        
        info!("Total estimated size: {}", bytes_to_human(total_size_hint));
        
        let backup_id = self.storage.generate_id(BackupType::Full, start_time);
        let backup_dir = self.storage.backup_path(&backup_id);
        fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;
        
        // === ОСНОВНАЯ ЛОГИКА: Multiple Sources ===
        let mut source_archives = Vec::new();
        let mut total_file_count = 0;
        
        for (i, mut source) in sources.into_iter().enumerate() {
            let source_name = source.name().to_string();
            info!("Processing source {}: {} ({} bytes)", i, source_name, source.size_hint().unwrap_or(0));
            
            // Создаем временный архив для источника
            let source_tar_path = backup_dir.join(format!("source_{}_{}.tar.gz", i, source_name.replace('/', "_")));
            let source_tar_result = self.create_single_source_archive(source.as_mut(), &source_tar_path).await?;
            let file_count = source_tar_result.file_count;
            source_archives.push((source_name, source_tar_path, source_tar_result));
            total_file_count += file_count;
        }
        
        // Объединяем в финальный архив
        let final_archive_path = backup_dir.join("data.tar.gz");
        self.create_combined_archive(&source_archives, &final_archive_path, progress)?;
        
        let final_archive_size = fs::metadata(&final_archive_path)?.len();
        
        // Шифрование (если включено)
        let (encrypted_path, encrypted_size, is_encrypted) = if self.crypto.is_enabled() {
            let enc_path = final_archive_path.with_file_name("data.tar.gz.enc");
            info!("Encrypting combined archive...");
            self.crypto.encrypt_file(&final_archive_path, &enc_path)?;
            if self.config.crypto.delete_plain {
                fs::remove_file(&final_archive_path)?;
            }
            let size = fs::metadata(&enc_path)?.len();
            (enc_path, size, true)
        } else {
            (final_archive_path, final_archive_size, false)
        };
        
        // Удаляем временные архивы источников (больше не нужны)
        for (_, source_path, _) in &source_archives {
            if source_path.exists() {
                fs::remove_file(source_path)?;
            }
        }
        
        // Манифест с информацией о sources
        let manifest = self.create_multi_source_manifest(&source_archives, is_encrypted)?;
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
        let duration_secs = end_time.signed_duration_since(start_time).num_milliseconds() as f64 / 1000.0;
        
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
        
        info!("SUCCESS: Backup created {}", result.id);
        Ok(result)
    }

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
            result.errors.push("Manifest not found".to_string());
            return Ok(result);
        }
        let manifest_content = fs::read_to_string(manifest_path)?;
        let manifest: Value = serde_json::from_str(&manifest_content)?;

        // Получаем список файлов
        let files = match manifest.get("files").and_then(|v| v.as_array()) {
            Some(f) => f,
            None => {
                result.errors.push("No files list in manifest".to_string());
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
                    result.files_corrupted.push(format!("{} (can't read metadata)", rel_path));
                    continue;
                }
            };

            if metadata.len() != expected_size {
                result.files_corrupted.push(format!("{} (size mismatch)", rel_path));
                continue;
            }

            let actual_hash = match calculate_file_hash(&file_path) {
                Ok(h) => h,
                Err(_) => {
                    result.files_corrupted.push(format!("{} (can't compute hash)", rel_path));
                    continue;
                }
            };

            if actual_hash == expected_hash {
                result.files_matched += 1;
            } else {
                result.files_corrupted.push(format!("{} (hash mismatch)", rel_path));
            }
        }

        Ok(result)
    }

    /// Создает архив для одного источника (просто копирует поток данных в файл)
    async fn create_single_source_archive(
        &self,
        source: &mut dyn BackupSource,
        tar_path: &Path,
    ) -> Result<SingleSourceResult> {
        // Сначала получаем метаданные (immutable borrow)
        let source_meta = source.metadata();
        let file_count = source_meta.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        // Затем читаем данные (mutable borrow)
        let mut reader = source.read()?;
        let mut file = fs::File::create(tar_path)?;
        copy(&mut reader, &mut file)?;

        Ok(SingleSourceResult {
            file_count,
            metadata: source_meta,
        })
    }

    /// Объединяет source архивы в один tar.gz
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
            
            // Используем индекс для имени внутри архива – гарантированно относительный путь
            let archive_name = format!("source_{}.tar.gz", i);
            println!("DEBUG: adding to combined archive: {} -> {}", source_name, archive_name);
            
            tar_builder.append_data(&mut header, archive_name, &mut source_file)?;
        }
        
        tar_builder.into_inner()?.finish()?;
        Ok(())
    }

    /// Манифест для multi-source
    fn create_multi_source_manifest(
        &self,
        source_archives: &[(String, PathBuf, SingleSourceResult)],
        encrypted: bool,
    ) -> Result<Value> {
        let mut all_files = Vec::new();
        let mut sources_info = Vec::new();

        for (name, path, result) in source_archives {
            // Добавляем информацию об источнике
            sources_info.push(json!({
                "name": name,
                "path": path.display().to_string(),
                "file_count": result.file_count,
                "size": fs::metadata(path).map(|m| m.len()).unwrap_or(0)
            }));

            // Извлекаем список файлов из метаданных источника
            if let Some(files) = result.metadata.get("files").and_then(|v| v.as_array()) {
                all_files.extend(files.clone());
            }
        }

        Ok(json!({
            "backup_type": "full",
            "timestamp": Utc::now().to_rfc3339(),
            "encrypted": encrypted,
            "encryption_algorithm": if encrypted { "GOST R 34.12-2015 Kuznechik" } else { "none" },
            "sources": sources_info,
            "files": all_files,      // общий список всех файлов
        }))
    }

    // ------------------------------------------------------------------------
    // Legacy method for backward compatibility
    // ------------------------------------------------------------------------

    pub async fn create_backup(
        &self,
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        profile_name: Option<&str>,
        progress: bool,
    ) -> Result<BackupResult> {
        let source = FileSource::new(paths, exclude_patterns)?;
        let sources: Vec<Box<dyn BackupSource>> = vec![Box::new(source)];
        self.create_backup_from_sources(sources, profile_name, progress).await
    }

    // ------------------------------------------------------------------------
    // Helper: create manifest from sources (deprecated? можно оставить)
    // ------------------------------------------------------------------------

    fn create_manifest_from_sources(
        &self,
        sources: &[Box<dyn BackupSource>],
        encrypted: bool,
    ) -> Result<serde_json::Value> {
        let sources_meta: Vec<serde_json::Value> = sources.iter().map(|s| s.metadata()).collect();

        let total_files: u64 = sources_meta
            .iter()
            .filter_map(|m| m["file_count"].as_u64())
            .sum();

        let total_size: u64 = sources_meta
            .iter()
            .filter_map(|m| m["total_size"].as_u64())
            .sum();

        Ok(serde_json::json!({
            "backup_type": "full",
            "timestamp": Utc::now().to_rfc3339(),
            "encrypted": encrypted,
            "encryption_algorithm": if encrypted { "GOST R 34.12-2015 (Kuznechik)" } else { "none" },
            "sources": sources_meta,
            "total_files": total_files,
            "total_size": total_size,
        }))
    }

    // ------------------------------------------------------------------------
    // Archive validation
    // ------------------------------------------------------------------------

    pub fn validate_archive(&self, path: &Path) -> Result<()> {
        println!("[INFO] Validating archive: {}", path.display());

        let file = fs::File::open(path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let mut count = 0;
        for entry in archive.entries()? {
            let entry = entry?;
            if entry.header().path().is_err() {
                return Err(anyhow::anyhow!("Invalid path in archive entry"));
            }
            count += 1;
        }

        println!("[INFO] Archive validation passed: {} files", count);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Backup verification
    // ------------------------------------------------------------------------

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
                result.errors.push(format!("Failed to read backup info: {}", e));
                return Ok(result);
            }
        };

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let encrypted_path_wrong = backup_path.join("data.tar.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if encrypted_path_wrong.exists() {
            (&encrypted_path_wrong, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            result.errors.push("Archive not found".to_string());
            return Ok(result);
        };

        let manifest_path = backup_path.join("manifest.json");
        if !manifest_path.exists() {
            result.errors.push("Manifest file not found".to_string());
            return Ok(result);
        }

        result.archive_ok = true;

        // Создаём временную директорию для всего процесса верификации
        let temp_dir = tempfile::tempdir()?;
        let mut archive_to_use = archive_path.to_path_buf();

        if is_encrypted {
            if !self.crypto.is_enabled() {
                result
                    .errors
                    .push("Archive is encrypted but encryption is disabled".to_string());
                return Ok(result);
            }

            println!("[VERIFY] Testing decryption...");
            let decrypted_path = temp_dir.path().join("data.tar.gz");

            match self.crypto.decrypt_file(archive_path, &decrypted_path) {
                Ok(_) => {
                    result.decryption_ok = true;
                    archive_to_use = decrypted_path;
                }
                Err(e) => {
                    result.errors.push(format!("Decryption failed: {}", e));
                    return Ok(result);
                }
            }
        } else {
            result.decryption_ok = true;
        }

        println!("[VERIFY] Validating archive structure...");
        let file = match std::fs::File::open(&archive_to_use) {
            Ok(f) => f,
            Err(e) => {
                result.errors.push(format!("Failed to open archive: {}", e));
                return Ok(result);
            }
        };

        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let mut entry_count = 0;
        for entry in archive.entries()? {
            match entry {
                Ok(_) => entry_count += 1,
                Err(e) => {
                    result
                        .errors
                        .push(format!("Corrupted entry in archive: {}", e));
                    result.extraction_ok = false;
                    return Ok(result);
                }
            }
        }
        result.extraction_ok = true;
        result.files_checked = entry_count as u64;

        if quick {
            println!("[VERIFY] Quick verification passed (archive integrity OK)");
            return Ok(result);
        }

        println!("[VERIFY] Performing full verification (comparing file contents)...");
        let extract_path = temp_dir.path();

        let file = std::fs::File::open(&archive_to_use)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        if progress {
            println!("[VERIFY] Extracting archive for verification...");
        }
        archive.unpack(extract_path)?;

        // --- Дополнительно: распаковываем все вложенные архивы ---
        // Ищем все файлы вида source_*.tar.gz и распаковываем их в ту же директорию
        let entries: Vec<_> = fs::read_dir(extract_path)?.collect::<Result<Vec<_>, _>>()?;
        for entry in entries {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("gz") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with("source_") && filename.ends_with(".tar.gz") {
                        println!("[VERIFY] Extracting nested archive: {}", filename);
                        let inner_file = fs::File::open(&path)?;
                        let inner_decoder = GzDecoder::new(inner_file);
                        let mut inner_archive = Archive::new(inner_decoder);
                        inner_archive.unpack(extract_path)?;
                        // Удаляем вложенный архив после распаковки
                        fs::remove_file(&path)?;
                    }
                }
            }
        }

        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

        let files = manifest["files"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid manifest format"))?;
        let total_files = files.len();

        let pb = if progress {
            let bar = indicatif::ProgressBar::new(total_files as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} Verifying files [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            bar.set_message("Checking files...");
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
                        .push(format!("{} (can't read metadata)", rel_path));
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    continue;
                }
            };

            if metadata.len() != expected_size {
                result
                    .files_corrupted
                    .push(format!("{} (size mismatch)", rel_path));
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
                        .push(format!("{} (can't compute hash)", rel_path));
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
                    .push(format!("{} (hash mismatch)", rel_path));
            }

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Verification complete");
        }

        result.files_checked = total_files as u64;
        Ok(result)
    }

    // ------------------------------------------------------------------------
    // Restore
    // ------------------------------------------------------------------------

    pub async fn restore_backup(
        &self,
        backup_id: &str,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        println!("[INFO] Restoring backup: {}", backup_id);
        println!("[INFO] Destination: {}", destination.display());

        let backup_info = self
            .storage
            .read_backup_info(backup_id)
            .context(format!("Failed to read backup info: {}", backup_id))?;

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let encrypted_path_wrong = backup_path.join("data.tar.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if encrypted_path_wrong.exists() {
            (&encrypted_path_wrong, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            return Err(anyhow::anyhow!("Archive not found: {}", backup_info.id));
        };

        println!("[INFO] Archive: {}", archive_path.display());
        println!("[INFO] Encrypted: {}", is_encrypted);

        if is_encrypted && !self.crypto.is_enabled() {
            return Err(anyhow::anyhow!(
                "Backup is encrypted but encryption is not enabled. Load encryption key first."
            ));
        }

        let temp_dir = tempfile::tempdir()?;
        let temp_archive = temp_dir.path().join("data.tar.gz");

        if is_encrypted {
            println!("[INFO] Decrypting archive with Kuznechik cipher...");
            self.crypto
                .decrypt_file(archive_path, &temp_archive)
                .context("Failed to decrypt archive")?;
        } else {
            fs::copy(archive_path, &temp_archive)?;
        }

        self.extract_archive(&temp_archive, destination, specific_path, overwrite, progress)
            .await?;

        println!("[SUCCESS] Restore completed to {}", destination.display());
        Ok(())
    }

    async fn extract_archive(
        &self,
        archive_path: &Path,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        let file = fs::File::open(archive_path)
            .context(format!("Failed to open archive: {}", archive_path.display()))?;

        let pb = if progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(ProgressStyle::default_spinner().template("{spinner} Extracting: {msg}")?);
            pb.set_message("Starting...");
        }

        // Сначала распаковываем основной архив во временную директорию
        let temp_extract_dir = tempfile::tempdir()?;
        let mut archive = Archive::new(GzDecoder::new(file));
        archive.unpack(temp_extract_dir.path())?;

        // Затем распаковываем все вложенные архивы
        let entries: Vec<_> = fs::read_dir(temp_extract_dir.path())?.collect::<Result<Vec<_>, _>>()?;
        for entry in entries {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("gz") {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with("source_") && filename.ends_with(".tar.gz") {
                        if let Some(ref pb) = pb {
                            pb.set_message(format!("Extracting nested: {}", filename));
                        }
                        let inner_file = fs::File::open(&path)?;
                        let inner_decoder = GzDecoder::new(inner_file);
                        let mut inner_archive = Archive::new(inner_decoder);
                        inner_archive.unpack(temp_extract_dir.path())?;
                    }
                }
            }
        }

        // Теперь копируем/перемещаем все файлы из временной директории в целевую,
        // применяя фильтр specific_path и overwrite
        let copy_options = fs_extra::dir::CopyOptions::new()
            .overwrite(overwrite)
            .skip_exist(!overwrite);

        // Копируем содержимое временной директории в destination
        let items_to_copy: Vec<_> = fs::read_dir(temp_extract_dir.path())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        for item in items_to_copy {
            if let Some(specific) = specific_path {
                if !item.strip_prefix(temp_extract_dir.path())?.starts_with(specific) {
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
            pb.finish_with_message("Extraction completed");
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------------

    pub fn encryption_status(&self) -> &'static str {
        if self.crypto.is_enabled() {
            "ENABLED (Kuznechik GOST R 34.12-2015)"
        } else {
            "DISABLED"
        }
    }

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

// ============================================================================
// Helper functions (no longer needed, all moved to utils)
// ============================================================================

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_paths_empty() {
        let temp_dir = tempdir().unwrap();
        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(&[temp_dir.path().to_path_buf()], &[], false)
            .await
            .unwrap();

        assert_eq!(files.len(), 0);
    }

    #[tokio::test]
    async fn test_scan_paths_with_files() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(&[temp_dir.path().to_path_buf()], &[], false)
            .await
            .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, file_path);
        assert_eq!(files[0].size, 12);
    }

    #[test]
    fn test_calculate_file_hash() -> Result<()> {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content")?;

        let hash = utils::calculate_file_hash(&file_path)?;
        assert_eq!(hash.len(), 64);
        Ok(())
    }

    #[test]
    fn test_build_globset() -> Result<()> {
        let patterns = vec!["*.tmp".to_string(), "cache/*".to_string()];

        let globset = utils::build_globset(&patterns)?;
        assert!(globset.is_some());

        let globset = globset.unwrap();
        assert!(globset.is_match("test.tmp"));
        assert!(globset.is_match("cache/file.txt"));
        assert!(!globset.is_match("test.txt"));

        Ok(())
    }

    #[tokio::test]
    async fn test_create_and_validate_archive() -> Result<()> {
        let temp_dir = tempdir()?;

        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file1, "content 1")?;
        fs::write(&file2, "content 2")?;

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config)?;

        let info1 = engine.get_file_info(&file1)?; // синхронный вызов
        let info2 = engine.get_file_info(&file2)?;

        let files = vec![info1, info2];

        let archive_path = temp_dir.path().join("test.tar.gz");
        let size = engine.create_tar(&files, &archive_path, false).await?;

        assert!(archive_path.exists());
        assert!(size > 0);

        engine.validate_archive(&archive_path)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_scan_paths_with_exclude() -> Result<()> {
        let temp_dir = tempdir()?;

        let file1 = temp_dir.path().join("include.txt");
        let file2 = temp_dir.path().join("exclude.tmp");
        fs::write(&file1, "include")?;
        fs::write(&file2, "exclude")?;

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(
                &[temp_dir.path().to_path_buf()],
                &["*.tmp".to_string()],
                false,
            )
            .await?;

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path.file_name().unwrap(), "include.txt");
        Ok(())
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::config::{Config, CoreConfig, CryptoConfig};
    use crate::storage::BackupStorage;
    use crate::utils;
    use tempfile::tempdir;
    use std::fs;
    use std::path::PathBuf;

    fn test_config(temp_root: &std::path::Path) -> Config {
        let backup_dir = temp_root.join("backups");
        let key_path = temp_root.join("master.key");
        let key = Crypto::generate_key();
        Crypto::save_key(&key, &key_path).unwrap();
        Config {
            core: CoreConfig {
                backup_dir: backup_dir.clone(),
                ..CoreConfig::default()
            },
            crypto: CryptoConfig {
                master_key_path: key_path,
                delete_plain: true,
                ..CryptoConfig::default()
            },
            ..Config::default()
        }
    }

    fn create_test_files(dir: &std::path::Path) -> Vec<PathBuf> {
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        let subdir = dir.join("subdir");
        let file3 = subdir.join("file3.txt");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(&file1, b"content 1").unwrap();
        fs::write(&file2, b"content 2 with longer text").unwrap();
        fs::write(&file3, b"content 3 in subdir").unwrap();
        vec![file1, file2, file3]
    }

    async fn create_test_backup(
        engine: &BackupEngine,
        source_paths: Vec<PathBuf>,
        profile: &str,
    ) -> BackupResult {
        engine
            .create_backup(source_paths, vec![], Some(profile), false)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_verify_backup_quick_unencrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(result.is_ok());
        assert!(result.quick);
        assert!(result.archive_ok);
        assert!(result.decryption_ok);
        assert!(result.extraction_ok);
        assert_eq!(result.files_checked, 3);
        assert!(result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_full_unencrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(result.is_ok());
        assert!(!result.quick);
        assert_eq!(result.files_checked, 3);
        assert_eq!(result.files_matched, 3);
        assert!(result.files_missing.is_empty());
        assert!(result.files_corrupted.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_quick_encrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config)?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(result.is_ok());
        assert!(result.decryption_ok);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_full_encrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config)?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(result.is_ok());
        assert_eq!(result.files_matched, 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_corrupted_archive() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");
        let mut archive = fs::OpenOptions::new().append(true).open(&archive_path)?;
        use std::io::Write;
        archive.write_all(b"CORRUPT")?;
        archive.sync_all()?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(!result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_corrupted_file() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");

        let extract_dir = tempfile::tempdir()?;
        let file = fs::File::open(&archive_path)?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        archive.unpack(extract_dir.path())?;

        let file1_path = extract_dir.path().join("file1.txt");
        fs::write(&file1_path, b"MODIFIED CONTENT")?;

        let new_archive_path = backup_path.join("data.tar.gz.modified");
        let tar_file = fs::File::create(&new_archive_path)?;
        let encoder = flate2::write::GzEncoder::new(tar_file, flate2::Compression::default());
        let mut builder = Builder::new(encoder);
        builder.append_dir_all(".", extract_dir.path())?;
        builder.into_inner()?.finish()?;

        fs::remove_file(&archive_path)?;
        fs::rename(&new_archive_path, &archive_path)?;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(!result.is_ok());
        assert_eq!(result.files_corrupted.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_missing_manifest() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let manifest_path = backup_path.join("manifest.json");
        fs::remove_file(&manifest_path)?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.contains("Manifest")));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_missing_archive() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");
        fs::remove_file(&archive_path)?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.contains("Archive not found")));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_wrong_key() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config.clone())?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let wrong_key_path = temp_root.path().join("wrong.key");
        let wrong_key = Crypto::generate_key();
        Crypto::save_key(&wrong_key, &wrong_key_path)?;
        let mut wrong_config = config;
        wrong_config.crypto.master_key_path = wrong_key_path;
        let wrong_engine = BackupEngine::new(storage, wrong_config)?;

        let result = wrong_engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(!result.decryption_ok);
        assert!(result.errors.iter().any(|e| e.contains("Decryption failed")));
        Ok(())
    }
}

#[cfg(test)]
mod interval_tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::BackupStorage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_check_interval_no_backups() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage, config)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(24))?;
        assert_eq!(result, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_check_interval_with_recent_backup() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let backup_info = BackupInfo {
            id: "test-backup".to_string(),
            backup_type: BackupType::Full,
            timestamp: Utc::now(),
            profile: "test-profile".to_string(),
            file_count: 0,
            size_encrypted: 0,
            checksum: None,
            encrypted: Some(false),
        };
        storage.write_local_index(&backup_info)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(1))?;
        assert!(result.is_some());
        assert!(result.unwrap() < Duration::hours(1));
        Ok(())
    }

    #[tokio::test]
    async fn test_check_interval_old_backup() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let old_time = Utc::now() - Duration::days(2);
        let backup_info = BackupInfo {
            id: "old-backup".to_string(),
            backup_type: BackupType::Full,
            timestamp: old_time,
            profile: "test-profile".to_string(),
            file_count: 0,
            size_encrypted: 0,
            checksum: None,
            encrypted: Some(false),
        };
        storage.write_local_index(&backup_info)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(24))?;
        assert_eq!(result, None);
        Ok(())
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::BackupStorage;
    use crate::utils;
    use tempfile::tempdir;

    #[tokio::test]
    #[cfg(unix)]
    async fn test_backup_restore_symlink() -> Result<()> {
        use std::os::unix;

        let temp_root = tempdir()?;
        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;

        let real_file = source_dir.join("real.txt");
        fs::write(&real_file, "content")?;
        let symlink_path = source_dir.join("link.txt");
        unix::fs::symlink(&real_file, &symlink_path)?;

        let backup_dir = temp_root.path().join("backups");
        let storage = BackupStorage::new(&backup_dir.display().to_string());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let result = engine
            .create_backup(vec![source_dir.clone()], vec![], Some("test"), false)
            .await?;

        let restore_dir = temp_root.path().join("restore");
        engine
            .restore_backup(&result.id, &restore_dir, None, true, false)
            .await?;

        let restored_symlink = restore_dir.join("source").join("link.txt");
        assert!(restored_symlink.exists());
        assert!(restored_symlink
            .symlink_metadata()?
            .file_type()
            .is_symlink());

        let target = fs::read_link(&restored_symlink)?;
        let expected_target = restore_dir.join("source").join("real.txt");
        assert_eq!(target, expected_target);

        let restored_content = fs::read_to_string(&expected_target)?;
        assert_eq!(restored_content, "content");
        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_backup_restore_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_root = tempdir()?;
        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;

        let file_path = source_dir.join("exec.sh");
        fs::write(&file_path, "#!/bin/sh\necho hello")?;

        let mut perms = fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&file_path, perms)?;

        let backup_dir = temp_root.path().join("backups");
        let storage = BackupStorage::new(&backup_dir.display().to_string());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage, config)?;

        let result = engine
            .create_backup(vec![file_path.clone()], vec![], Some("test"), false)
            .await?;

        let restore_dir = temp_root.path().join("restore");
        engine
            .restore_backup(&result.id, &restore_dir, None, true, false)
            .await?;

        let restored_file = restore_dir.join("exec.sh");
        assert!(restored_file.exists());

        let restored_mode = restored_file.metadata()?.permissions().mode();
        assert!(restored_mode & 0o111 != 0);
        assert_eq!(restored_mode & 0o777, 0o755);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::tempdir;

        #[tokio::test]
        async fn test_multiple_sources() -> Result<()> {
            let temp_dir = tempdir()?;
            let config = Config::default();
            let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
            let engine = BackupEngine::new(storage, config)?;

            // File source
            let file_source = FileSource::new(
                vec![temp_dir.path().join("file1.txt")],
                vec![]
            )?;

            // Mock postgres source (или реальный если есть БД)
            let pg_source = Box::new(MockPostgresSource::new("testdb"));

            let sources: Vec<Box<dyn BackupSource>> = vec![
                Box::new(file_source),
                pg_source,
            ];

            let result = engine.create_backup_from_sources(sources, Some("multi-test"), false).await?;

            assert!(result.file_count > 0);
            assert!(result.id.len() > 0);
            Ok(())
        }
    }
}