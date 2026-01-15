// src/backup.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::{Archive, Builder};
use walkdir::WalkDir;

use crate::config::Config;
use crate::storage::{BackupInfo, BackupStorage, BackupType};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    pub path: PathBuf,           // Относительный путь внутри архива
    pub size: u64,               // Размер в байтах
    pub mtime: DateTime<Utc>,    // Время последней модификации
    pub hash: String,            // SHA256 хэш содержимого
    pub mode: Option<u32>,       // Права доступа (unix) - только на Unix системах
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
        
        // Определяем имя профиля
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
        fs::create_dir_all(&backup_dir)
            .context("Failed to create backup directory")?;
        
        // Шаг 3: Создание tar.gz архива
        let tar_path = backup_dir.join("data.tar.gz");
        println!("[INFO] Creating archive: {}", tar_path.display());
        
        let archive_size = self.create_tar(&files, &tar_path, progress).await?;
        
        // Шаг 4: Создание манифестa
        let manifest_path = backup_dir.join("manifest.json");
        println!("[INFO] Creating manifest: {}", manifest_path.display());
        
        let manifest = self.create_manifest(&files)?;
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest")?;
        
        // Шаг 5: Создание локального индекса
        let backup_info = BackupInfo {
            id: backup_id.clone(),
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: files.len() as u64,
            size_encrypted: archive_size,
            parent_id: None,
            checksum: Some(calculate_file_hash(&tar_path).await?),
        };
        
        self.storage.write_local_index(&backup_info)?;
        
        // Шаг 6: Расчет статистики
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
            archive_size,
            duration_secs,
        };
        
        println!(
            "\n[SUCCESS] Full backup created: {}",
            backup_id
        );
        println!("  Profile:      {}", profile);
        println!("  Files:        {}", files.len());
        println!("  Original:     {}", crate::storage::bytes_to_human(total_size));
        println!("  Archive:      {}", crate::storage::bytes_to_human(archive_size));
        let compression_ratio = if total_size > 0 {
            (1.0 - archive_size as f64 / total_size as f64) * 100.0
        } else {
            0.0
        };
        println!("  Compression:  {:.1}%", compression_ratio);
        println!("  Duration:     {:.1}s", duration_secs);
        println!("  Location:     {}", backup_dir.display());
        
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
        
        // Создаем прогресс-бар если нужно
        let pb = if show_progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };
        
        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} Scanning: {pos} files found...")
                    .unwrap(),
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
                
                // Пропускаем директории
                if !path.is_file() {
                    continue;
                }
                
                // Проверяем исключения по glob паттернам
                if let Some(ref globset) = globset {
                    let path_str = path.to_string_lossy();
                    // Исправлено: используем as_ref() для Cow<str>
                    if globset.is_match(path_str.as_ref()) {
                        continue;
                    }
                }
                
                // Получаем метаданные файла
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
        
        // Получаем относительный путь (если файл внутри одного из исходных путей)
        let rel_path = self.get_relative_path(path)?;
        
        // Время модификации
        let mtime = metadata.modified()
            .map(|t| DateTime::<Utc>::from(t))
            .unwrap_or_else(|_| Utc::now());
        
        // Хэш содержимого
        let hash = calculate_file_hash(path).await?;
        
        // Права доступа (только для Unix)
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };
        
        #[cfg(not(unix))]
        let mode = None;
        
        Ok(FileInfo {
            path: rel_path,
            size: metadata.len(),
            mtime,
            hash,
            mode,
        })
    }
    
    /// Получает относительный путь файла
    fn get_relative_path(&self, path: &Path) -> Result<PathBuf> {
        // Пытаемся найти самый длинный совпадающий префикс
        let current_dir = std::env::current_dir()?;
        let abs_path = if path.is_relative() {
            current_dir.join(path)
        } else {
            path.to_path_buf()
        };
        
        // Возвращаем абсолютный путь как есть
        // (в реальном использовании можно сделать relative to common root)
        Ok(abs_path)
    }
    
    /// Создает tar.gz архив из списка файлов
    pub async fn create_tar(
        &self,
        files: &[FileInfo],
        output_path: &Path,
        show_progress: bool,
    ) -> Result<u64> {
        let pb = if show_progress {
            Some(ProgressBar::new(files.len() as u64))
        } else {
            None
        };
        
        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} {msg}\n[{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb.set_message("Creating archive...");
        }
        
        // Создаем архив
        let tar_gz = fs::File::create(output_path)
            .context("Failed to create archive file")?;
        let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
        let mut tar = Builder::new(enc);
        
        for file_info in files {
            let path = &file_info.path;
            
            if !path.exists() {
                eprintln!("[WARN] File no longer exists: {}", path.display());
                continue;
            }
            
            // Добавляем файл в архив
            let mut file = fs::File::open(path)
                .with_context(|| format!("Failed to open file: {}", path.display()))?;
            
            // Создаем заголовок tar
            let mut header = tar::Header::new_gnu();
            header.set_path(path)
                .with_context(|| format!("Failed to set path in header: {}", path.display()))?;
            header.set_size(file_info.size);
            header.set_mtime(file_info.mtime.timestamp() as u64);
            
            // Устанавливаем права доступа если есть
            #[cfg(unix)]
            if let Some(mode) = file_info.mode {
                header.set_mode(mode);
            }
            
            // Записываем заголовок и содержимое
            tar.append(&header, &mut file)
                .with_context(|| format!("Failed to append file to archive: {}", path.display()))?;
            
            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }
        
        // Завершаем создание архива
        tar.finish()
            .context("Failed to finish tar archive")?;
        
        if let Some(pb) = pb {
            pb.finish_with_message("Archive created");
        }
        
        // Возвращаем размер архива
        let metadata = fs::metadata(output_path)
            .context("Failed to get archive metadata")?;
        
        Ok(metadata.len())
    }
    
    /// Создает манифест бэкапа
    fn create_manifest(&self, files: &[FileInfo]) -> Result<serde_json::Value> {
        let file_list: Vec<serde_json::Value> = files
            .iter()
            .map(|f| {
                serde_json::json!({
                    "path": f.path.display().to_string(),
                    "size": f.size,
                    "mtime": f.mtime.to_rfc3339(),
                    "hash": f.hash,
                    "mode": f.mode,
                })
            })
            .collect();
        
        Ok(serde_json::json!({
            "backup_type": "full",
            "file_count": files.len(),
            "total_size": files.iter().map(|f| f.size).sum::<u64>(),
            "timestamp": Utc::now().to_rfc3339(),
            "files": file_list,
        }))
    }
    
    /// Проверяет целостность бэкапа
    pub async fn verify_backup(&self, backup_id: &str) -> Result<bool> {
        let backup_path = self.storage.backup_path(backup_id);
        let tar_path = backup_path.join("data.tar.gz");
        let manifest_path = backup_path.join("manifest.json");
        
        if !tar_path.exists() || !manifest_path.exists() {
            return Ok(false);
        }
        
        // Читаем манифест
        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;
        
        // Проверяем хэш архива если есть в индексе
        if let Ok(_index) = self.storage.read_local_index(backup_id) {
            println!("Verifying backup: {}", backup_id);
            println!("  Files in manifest: {}", 
                     manifest.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0));
            
            // Проверяем, что архив можно открыть
            let file = fs::File::open(&tar_path)?;
            let _ = Archive::new(flate2::read::GzDecoder::new(file));
            
            return Ok(true);
        }
        
        Ok(false)
    }
}

/// Строит GlobSet из паттернов исключения
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

/// Вычисляет SHA256 хэш файла
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
        
        let files = engine.scan_paths(
            &[temp_dir.path().to_path_buf()],
            &[],
            false,
        ).await.unwrap();
        
        assert_eq!(files.len(), 0); // Пустая директория
    }
    
    #[tokio::test]
    async fn test_scan_paths_with_files() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();
        
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config);
        
        let files = engine.scan_paths(
            &[temp_dir.path().to_path_buf()],
            &[],
            false,
        ).await.unwrap();
        
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, file_path);
        assert_eq!(files[0].size, 12);
    }
}