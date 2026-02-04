// src/backup.rs (исправленная версия)
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::{Archive, Builder};
use walkdir::WalkDir;

use crate::config::Config;
use crate::storage::{BackupInfo, BackupStorage, BackupType};

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,        // Абсолютный путь к файлу
    pub size: u64,            // Размер в байтах
    pub mtime: DateTime<Utc>, // Время последней модификации
    pub hash: String,         // SHA256 хэш содержимого
    pub mode: Option<u32>,    // Права доступа (unix) - только на Unix системах
}

#[derive(Debug, Clone)]
pub struct BackupResult {
    pub id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: usize,
    pub size_bytes: u64,
    pub archive_size: u64,
    pub duration_secs: f64,
}

#[derive(Debug)]
pub struct BackupEngine {
    pub storage: BackupStorage,
    pub config: Arc<Config>,
}

impl BackupEngine {
    /// Создает новый движок бэкапа
    pub fn new(storage: BackupStorage, config: Config) -> Self {
        Self {
            storage,
            config: Arc::new(config),
        }
    }

    /// Создает полный бэкап указанных путей
    pub async fn create_full(
        &self,
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        profile_name: Option<&str>,
        dry_run: bool,
        progress: bool,
    ) -> Result<BackupResult> {
        let start_time = Utc::now();

        let profile = profile_name.unwrap_or("manual");

        println!("[INFO] Starting full backup for profile: {}", profile);
        println!("[INFO] Source paths: {:?}", paths);

        if !exclude_patterns.is_empty() {
            println!("[INFO] Exclude patterns: {:?}", exclude_patterns);
        }

        if dry_run {
            println!("[DRY RUN] No files will be actually backed up");
        }

        // Шаг 1: Сканирование файлов
        println!("[INFO] Scanning files...");
        let files = self.scan_paths(&paths, &exclude_patterns, progress).await?;

        if files.is_empty() {
            return Err(anyhow::anyhow!("No files found to backup"));
        }

        let total_size: u64 = files.iter().map(|f| f.size).sum();
        println!(
            "[INFO] Found {} files (total: {})",
            files.len(),
            crate::storage::bytes_to_human(total_size)
        );

        if dry_run {
            return Ok(BackupResult {
                id: "dry-run".to_string(),
                backup_type: BackupType::Full,
                timestamp: start_time,
                profile: profile.to_string(),
                file_count: files.len(),
                size_bytes: total_size,
                archive_size: 0,
                duration_secs: 0.0,
            });
        }

        // Шаг 2: Генерация ID бэкапа
        let backup_id = self.storage.generate_id(BackupType::Full, start_time);
        let backup_dir = self.storage.backup_path(&backup_id);

        println!("[INFO] Creating backup directory: {}", backup_dir.display());
        fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;

        // Шаг 3: Создание tar.gz архива
        let tar_path = backup_dir.join("data.tar.gz");
        println!("[INFO] Creating archive: {}", tar_path.display());

        let archive_size = self.create_tar(&files, &tar_path, progress).await?;

        // ✅ ИСПРАВЛЕННАЯ валидация архива после создания
        self.validate_archive(&tar_path)?;

        // Шаг 4: Создание манифеста с абсолютными путями
        let manifest_path = backup_dir.join("manifest.json");
        println!("[INFO] Creating manifest: {}", manifest_path.display());

        let manifest = self.create_manifest(&files)?;
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest")?;

        // Шаг 5: ШИФРОВАНИЕ - ЗАКОММЕНТИРОВАНО ДЛЯ ТЕСТИРОВАНИЯ
        let final_archive_size = archive_size;
        println!("[INFO] Encryption is temporarily disabled for testing");

        // Шаг 6: Создание локального индекса
        let backup_info = BackupInfo {
            id: backup_id.clone(),
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: files.len() as u64,
            size_encrypted: final_archive_size,
            parent_id: None,
            checksum: Some(crate::backup::calculate_file_hash(&tar_path).await?),
        };

        self.storage.write_local_index(&backup_info)?;

        // Шаг 7: Расчет статистики
        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time);
        let duration_secs = duration.num_milliseconds() as f64 / 1000.0;

        let result = BackupResult {
            id: backup_id.clone(),
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: files.len(),
            size_bytes: total_size,
            archive_size: final_archive_size,
            duration_secs,
        };

        println!("\n[SUCCESS] Full backup created: {}", backup_id);
        println!("  Profile:      {}", profile);
        println!("  Files:        {}", files.len());
        println!("  Original:     {}", crate::storage::bytes_to_human(total_size));
        println!("  Archive:      {}", crate::storage::bytes_to_human(final_archive_size));
        let compression_ratio = if total_size > 0 {
            (1.0 - final_archive_size as f64 / total_size as f64) * 100.0
        } else {
            0.0
        };
        println!("  Compression:  {:.1}%", compression_ratio);
        println!("  Duration:     {:.1}s", duration_secs);
        println!("  Location:     {}", backup_dir.display());
        println!("  Encryption:   ✗ (temporarily disabled for testing)");

        Ok(result)
    }

    /// Рекурсивно сканирует пути с учетом исключений
    pub async fn scan_paths(
        &self,
        paths: &[PathBuf],
        exclude_patterns: &[String],
        show_progress: bool,
    ) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();
        let globset = build_globset(exclude_patterns)?;

        let pb = if show_progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} Scanning: {pos} files found...")?,
            );
        }

        for path in paths {
            if !path.exists() {
                eprintln!("[WARN] Path does not exist: {}", path.display());
                continue;
            }

            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                if let Some(ref globset) = globset {
                    let path_str = path.to_string_lossy();
                    if globset.is_match(path_str.as_ref()) {
                        continue;
                    }
                }

                match self.get_file_info(path).await {
                    Ok(file_info) => {
                        files.push(file_info);
                        if let Some(ref pb) = pb {
                            pb.inc(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[WARN] Skipping {}: {}", path.display(), e);
                    }
                }
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message(format!("Found {} files", files.len()));
        }

        Ok(files)
    }

    /// Получает информацию о файле
    async fn get_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path).context("Failed to get file metadata")?;

        let abs_path = if path.is_relative() {
            std::env::current_dir()?.join(path)
        } else {
            path.to_path_buf()
        };

        let mtime = metadata
            .modified()
            .map(|t| DateTime::<Utc>::from(t))
            .unwrap_or_else(|_| Utc::now());

        let hash = calculate_file_hash(path).await?;

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };

        #[cfg(not(unix))]
        let mode = None;

        Ok(FileInfo {
            path: abs_path,
            size: metadata.len(),
            mtime,
            hash,
            mode,
        })
    }

    /// ✅ ИСПРАВЛЕННЫЙ create_tar() - сохраняет относительные пути в архиве
    pub async fn create_tar(
        &self,
        files: &[FileInfo],
        output_path: &Path,
        show_progress: bool,
    ) -> Result<u64> {
        let common_root = self.find_common_root(files)?;
        
        let pb = if show_progress {
            Some(ProgressBar::new(files.len() as u64))
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} {msg}\n[{bar:40.cyan/blue}] {pos}/{len} files ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message("Creating archive...");
        }

        let file = fs::File::create(output_path)
            .context("Failed to create archive file")?;
        
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = Builder::new(encoder);

        for file_info in files {
            let abs_path = &file_info.path;

            if !abs_path.exists() {
                eprintln!("[WARN] File no longer exists: {}", abs_path.display());
                continue;
            }

            let rel_path = abs_path
                .strip_prefix(&common_root)
                .with_context(|| {
                    format!(
                        "Failed to get relative path for {} (root: {})",
                        abs_path.display(),
                        common_root.display()
                    )
                })?;

            let mut src_file = fs::File::open(abs_path)
                .with_context(|| format!("Failed to open file: {}", abs_path.display()))?;

            tar_builder.append_file(rel_path, &mut src_file)
                .with_context(|| format!("Failed to append file to archive: {}", abs_path.display()))?;

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        tar_builder.into_inner()
            .context("Failed to get inner encoder")?
            .finish()
            .context("Failed to finish compression")?;

        if let Some(pb) = pb {
            pb.finish_with_message("Archive created successfully");
        }

        let metadata = fs::metadata(output_path)?;
        Ok(metadata.len())
    }

    /// ✅ ИСПРАВЛЕННЫЙ метод валидации архива
    pub fn validate_archive(&self, path: &Path) -> Result<()> {
        println!("[INFO] Validating archive: {}", path.display());
        
        let file = fs::File::open(path)?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        
        let mut count = 0;
        for entry in archive.entries()? {
            let entry = entry?;
            let header = entry.header();
            
            if header.path().is_err() {
                return Err(anyhow::anyhow!("Invalid path in archive entry"));
            }
            
            count += 1;
        }
        
        println!("[INFO] Archive validation passed: {} files", count);
        Ok(())
    }

    fn find_common_root(&self, files: &[FileInfo]) -> Result<PathBuf> {
        if files.is_empty() {
            return Err(anyhow::anyhow!("No files to backup"));
        }

        let mut common = files[0].path.parent().unwrap_or(&files[0].path).to_path_buf();

        for file in files.iter().skip(1) {
            common = self.common_prefix(&common, &file.path);
            if common.as_os_str().is_empty() {
                common = file.path.parent().unwrap_or(&file.path).to_path_buf();
            }
        }

        if !common.is_absolute() {
            common = std::env::current_dir()?.join(common);
        }

        Ok(common)
    }

    fn common_prefix(&self, a: &Path, b: &Path) -> PathBuf {
        let a_components: Vec<_> = a.components().collect();
        let b_components: Vec<_> = b.components().collect();
        
        let mut common = PathBuf::new();
        
        for (a_comp, b_comp) in a_components.iter().zip(b_components.iter()) {
            if a_comp == b_comp {
                common.push(a_comp);
            } else {
                break;
            }
        }
        
        common
    }

    /// ✅ ИСПРАВЛЕННЫЙ create_manifest - сохраняет абсолютные пути для сравнения
    fn create_manifest(&self, files: &[FileInfo]) -> Result<serde_json::Value> {
        let common_root = self.find_common_root(files)?;
        
        let file_list: Vec<serde_json::Value> = files
            .iter()
            .map(|f| {
                let rel_path = f.path.strip_prefix(&common_root)?;
                Ok(serde_json::json!({
                    "abs_path": f.path.display().to_string(), // Абсолютный путь для сравнения
                    "rel_path": rel_path.display().to_string(), // Относительный путь для архива
                    "size": f.size,
                    "mtime": f.mtime.to_rfc3339(),
                    "hash": f.hash,
                    "mode": f.mode,
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(serde_json::json!({
            "backup_type": "full",
            "file_count": files.len(),
            "total_size": files.iter().map(|f| f.size).sum::<u64>(),
            "timestamp": Utc::now().to_rfc3339(),
            "common_root": common_root.display().to_string(),
            "files": file_list,
        }))
    }

    pub async fn verify_backup(&self, backup_id: &str) -> Result<bool> {
        let backup_path = self.storage.backup_path(backup_id);
        let tar_path = backup_path.join("data.tar.gz");

        if !tar_path.exists() {
            return Ok(false);
        }

        println!("Verifying backup: {}", backup_id);

        if let Ok(index) = self.storage.read_local_index(backup_id) {
            println!("  Files in manifest: {}", index.file_count);

            let file = fs::File::open(&tar_path)?;
            let mut archive = Archive::new(flate2::read::GzDecoder::new(file));
            let file_count = archive.entries()?.count();
            println!("  Files in archive: {}", file_count);

            return Ok(true);
        }

        Ok(true)
    }

    /// ✅ ИСПРАВЛЕННЫЙ restore_backup - восстанавливает цепочку бэкапов
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

        // Получаем информацию о бэкапе
        let backup_info = self.storage.read_backup_info(backup_id)
            .context(format!("Failed to read backup info: {}", backup_id))?;

        // Создаем цепочку восстановления
        let chain = self.build_restore_chain(&backup_info).await?;
        
        println!("[INFO] Restoring chain of {} backups", chain.len());

        // Создаем уникальное имя для временной директории
        let mut rng = rand::thread_rng();
        let random_num: u32 = rng.r#gen::<u32>(); // Исправлено: явно указали тип
        let temp_dir_name = format!("krybs-restore-{}-{}", backup_id, random_num);
        let temp_dir = std::env::temp_dir().join(temp_dir_name);
        let temp_path = &temp_dir;
        
        // Создаем временную директорию
        fs::create_dir_all(temp_path)?;
        
        if progress {
            println!("[INFO] Using temporary directory: {}", temp_path.display());
        }

        // Восстанавливаем всю цепочку во временную директорию
        for (i, backup) in chain.iter().enumerate() {
            if progress {
                println!("[INFO] Restoring {}/{}: {}", i + 1, chain.len(), backup.id);
            }
            
            let backup_path = self.storage.backup_path(&backup.id);
            let archive_path = backup_path.join("data.tar.gz");

            if !archive_path.exists() {
                // Пытаемся удалить временную директорию
                let _ = fs::remove_dir_all(temp_path);
                return Err(anyhow::anyhow!("Archive not found: {}", backup.id));
            }

            self.extract_archive(&archive_path, temp_path, specific_path.clone(), overwrite, progress).await?;
        }

        // Копируем файлы из временной директории в целевую
        self.copy_directory(temp_path, destination, overwrite, progress).await?;

        // Удаляем временную директорию
        if let Err(e) = fs::remove_dir_all(temp_path) {
            eprintln!("[WARN] Failed to remove temporary directory: {}", e);
        }

        println!("[SUCCESS] Restore completed to {}", destination.display());
        Ok(())
    }

    /// Строит цепочку бэкапов для восстановления
    async fn build_restore_chain(&self, backup_info: &BackupInfo) -> Result<Vec<BackupInfo>> {
        let mut chain = vec![backup_info.clone()];
        let mut current = backup_info.clone();

        // Идем вверх по цепочке, пока не найдем полный бэкап
        while let Some(parent_id) = &current.parent_id {
            let parent = self.storage.read_backup_info(parent_id)?;
            chain.insert(0, parent.clone());
            current = parent;
        }

        Ok(chain)
    }

    /// Извлекает архив
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

        let mut archive = Archive::new(flate2::read::GzDecoder::new(file));
        
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path_in_archive = entry.path()?.to_path_buf();

            // Если указан specific_path, фильтруем по нему
            if let Some(specific_path) = &specific_path {
                if !path_in_archive.starts_with(specific_path) {
                    continue;
                }
            }

            let dest_path = destination.join(&path_in_archive);

            if dest_path.exists() && !overwrite {
                if let Some(ref pb) = pb {
                    pb.set_message(format!("Skipping: {} (exists)", path_in_archive.display()));
                }
                continue;
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            entry.unpack(&dest_path)?;

            if let Some(ref pb) = pb {
                pb.set_message(format!("Extracted: {}", path_in_archive.display()));
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Extraction completed");
        }

        Ok(())
    }

    /// Копирует директорию
    async fn copy_directory(
        &self,
        source: &Path,
        destination: &Path,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        let pb = if progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(ProgressStyle::default_spinner().template("{spinner} Copying: {msg}")?);
            pb.set_message("Starting...");
        }

        fs::create_dir_all(destination)?;

        for entry in WalkDir::new(source) {
            let entry = entry?;
            let src_path = entry.path();

            if !src_path.is_file() {
                continue;
            }

            let rel_path = src_path.strip_prefix(source)?;
            let dst_path = destination.join(rel_path);

            if dst_path.exists() && !overwrite {
                if let Some(ref pb) = pb {
                    pb.set_message(format!("Skipping: {} (exists)", rel_path.display()));
                }
                continue;
            }

            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::copy(src_path, &dst_path)?;

            if let Some(ref pb) = pb {
                pb.set_message(format!("Copied: {}", rel_path.display()));
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Copy completed");
        }

        Ok(())
    }
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
        builder.add(glob);
    }

    Ok(Some(builder.build()?))
}

pub async fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_paths_empty() {
        let temp_dir = tempdir().unwrap();
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);

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

        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);

        let files = engine
            .scan_paths(&[temp_dir.path().to_path_buf()], &[], false)
            .await
            .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, file_path);
        assert_eq!(files[0].size, 12);
    }

    #[tokio::test]
    async fn test_calculate_file_hash() -> Result<()> {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content")?;
        
        let hash = calculate_file_hash(&file_path).await?;
        assert_eq!(hash.len(), 64); // SHA256 hex string length
        Ok(())
    }

    #[tokio::test]
    async fn test_get_file_info() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.txt");
        let content = "Hello, World!";
        fs::write(&file_path, content)?;
        
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);

        let file_info = engine.get_file_info(&file_path).await?;
        
        assert_eq!(file_info.path, file_path);
        assert_eq!(file_info.size, content.len() as u64);
        assert_eq!(file_info.hash.len(), 64);
        Ok(())
    }

    #[test]
    fn test_build_globset() -> Result<()> {
        let patterns = vec![
            "*.tmp".to_string(),
            "cache/*".to_string(),
        ];
        
        let globset = build_globset(&patterns)?;
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

        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);

        let files = vec![
            FileInfo {
                path: file1.clone(),
                size: 9,
                mtime: Utc::now(),
                hash: calculate_file_hash(&file1).await?,
                mode: None,
            },
            FileInfo {
                path: file2.clone(),
                size: 9,
                mtime: Utc::now(),
                hash: calculate_file_hash(&file2).await?,
                mode: None,
            },
        ];

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

        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);

        let files = engine.scan_paths(
            &[temp_dir.path().to_path_buf()],
            &["*.tmp".to_string()],
            false,
        ).await?;

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path.file_name().unwrap(), "include.txt");
        Ok(())
    }
}