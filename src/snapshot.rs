// src/snapshot.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::backup::{BackupEngine, BackupResult, FileInfo};
use crate::config::{Config, Profile};
use crate::storage::{BackupInfo, BackupStorage, BackupType};

/// Статистика изменений между бэкапами
#[derive(Debug, Clone)]
pub struct DeltaStats {
    pub new_files: usize,
    pub changed_files: usize,
    pub deleted_files: usize,
    pub unchanged_files: usize,
    pub total_files_current: usize,
    pub total_files_previous: usize,
}

impl DeltaStats {
    /// Выводит статистику в удобном формате
    pub fn display(&self) -> String {
        format!(
            "Delta: {} new, {} changed, {} deleted ({} unchanged, {} → {} files)",
            self.new_files,
            self.changed_files,
            self.deleted_files,
            self.unchanged_files,
            self.total_files_previous,
            self.total_files_current
        )
    }
}

/// Информация о файле в манифесте
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub abs_path: String,      // Абсолютный путь для сравнения
    pub rel_path: String,      // Относительный путь для архива
    pub size: u64,
    pub mtime: String,
    pub hash: String,
    pub mode: Option<u32>,
}

/// Манифест бэкапа
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub backup_type: String,
    pub file_count: usize,
    pub total_size: u64,
    pub timestamp: String,
    pub common_root: Option<String>, // Общий корень для относительных путей
    pub files: Vec<ManifestFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

/// Движок для создания снепшотов
#[derive(Debug)]
pub struct SnapshotEngine {
    pub backup_engine: BackupEngine,
    pub storage: BackupStorage,
}

impl SnapshotEngine {
    /// Создает новый движок снепшотов
    pub fn new(storage: BackupStorage, config: Config) -> Self {
        let backup_engine = BackupEngine::new(storage.clone(), config);
        Self {
            backup_engine,
            storage,
        }
    }

    /// Создает снепшот на основе родительского бэкапа
    pub async fn create_snapshot(
        &self,
        parent_id: &str,
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        profile_name: Option<&str>,
        dry_run: bool,
        progress: bool,
    ) -> Result<BackupResult> {
        let start_time = Utc::now();

        println!("[INFO] Creating snapshot from parent: {}", parent_id);

        // Проверяем существование родительского бэкапа
        let parent_path = self.storage.backup_path(parent_id);
        if !parent_path.exists() {
            return Err(anyhow::anyhow!("Parent backup not found: {}", parent_id));
        }

        // Загружаем манифест родительского бэкапа
        println!("[INFO] Loading parent manifest...");
        let parent_manifest = self.load_manifest(parent_id).await?;
        println!(
            "[INFO] Parent manifest loaded: {} files, {}",
            parent_manifest.file_count,
            crate::storage::bytes_to_human(parent_manifest.total_size)
        );

        // Получаем общий корень из родительского манифеста
        let common_root = parent_manifest.common_root
            .as_ref()
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("Parent manifest missing common_root"))?;

        // Преобразуем манифест в FileInfo для сравнения
        let parent_files = self.manifest_to_fileinfo(&parent_manifest, &common_root)?;

        // Сканируем текущую файловую систему
        println!("[INFO] Scanning current filesystem...");
        let current_files: Vec<FileInfo> = self
            .backup_engine
            .scan_paths(&paths, &exclude_patterns, progress)
            .await?;

        if current_files.is_empty() {
            return Err(anyhow::anyhow!("No files found to backup"));
        }

        // Вычисляем дельту изменений
        println!("[INFO] Computing delta...");
        let (delta_files, stats) = self.compute_delta(&parent_files, &current_files)?;

        println!("[INFO] {}", stats.display());

        if delta_files.is_empty() {
            println!("[INFO] No changes detected, skipping snapshot creation");
            return Ok(BackupResult {
                id: "no-changes".to_string(),
                backup_type: BackupType::Snapshot,
                timestamp: start_time,
                profile: profile_name.unwrap_or("manual").to_string(),
                file_count: 0,
                size_bytes: 0,
                archive_size: 0,
                duration_secs: 0.0,
            });
        }

        if dry_run {
            println!(
                "[DRY RUN] Would create snapshot with {} changed files",
                delta_files.len()
            );
            return Ok(BackupResult {
                id: "dry-run-snapshot".to_string(),
                backup_type: BackupType::Snapshot,
                timestamp: start_time,
                profile: profile_name.unwrap_or("manual").to_string(),
                file_count: delta_files.len(),
                size_bytes: delta_files.iter().map(|f| f.size).sum(),
                archive_size: 0,
                duration_secs: 0.0,
            });
        }

        // Определяем имя профиля
        let profile = profile_name.unwrap_or("manual");

        // Генерируем ID для снепшота
        let snapshot_id = self.storage.generate_id(BackupType::Snapshot, start_time);
        let snapshot_dir = self.storage.backup_path(&snapshot_id);

        println!(
            "[INFO] Creating snapshot directory: {}",
            snapshot_dir.display()
        );
        fs::create_dir_all(&snapshot_dir).context("Failed to create snapshot directory")?;

        // Создаем tar.gz архив только с измененными файлами
        let tar_path = snapshot_dir.join("data.tar.gz");
        println!("[INFO] Creating delta archive: {}", tar_path.display());

        let archive_size = self
            .backup_engine
            .create_tar(&delta_files, &tar_path, progress)
            .await?;

        // Создаем манифест снепшота с ссылкой на родителя
        let manifest_path = snapshot_dir.join("manifest.json");
        println!("[INFO] Creating snapshot manifest...");

        let manifest = self.create_snapshot_manifest(&delta_files, parent_id, &common_root)?;
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest")?;

        // ШИФРОВАНИЕ снепшота - ЗАКОММЕНТИРОВАНО ДЛЯ ТЕСТИРОВАНИЯ
        let final_archive_size = archive_size;
        println!("[INFO] Encryption is temporarily disabled for testing");

        // Создаем локальный индекс
        let backup_info = BackupInfo {
            id: snapshot_id.clone(),
            backup_type: BackupType::Snapshot,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: delta_files.len() as u64,
            size_encrypted: final_archive_size,
            parent_id: Some(parent_id.to_string()),
            checksum: Some(crate::backup::calculate_file_hash(&tar_path).await?),
        };

        self.storage.write_local_index(&backup_info)?;

        // Расчет статистики
        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time);
        let duration_secs = duration.num_milliseconds() as f64 / 1000.0;

        let result = BackupResult {
            id: snapshot_id.clone(),
            backup_type: BackupType::Snapshot,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: delta_files.len(),
            size_bytes: delta_files.iter().map(|f| f.size).sum(),
            archive_size: final_archive_size,
            duration_secs,
        };

        println!("\n[SUCCESS] Snapshot created: {}", snapshot_id);
        println!("  Parent:       {}", parent_id);
        println!("  Delta files:  {}", delta_files.len());
        println!(
            "  Archive size: {}",
            crate::storage::bytes_to_human(final_archive_size)
        );
        println!("  Duration:     {:.1}s", duration_secs);
        println!("  Location:     {}", snapshot_dir.display());
        println!("  Encryption:   ✗ (temporarily disabled for testing)");

        Ok(result)
    }

    /// Автоматический режим: решает делать full или snapshot на основе расписания
    pub async fn auto_backup(
        &self,
        profile: &Profile,
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        force_full: bool,
        snapshot_only: bool,
        progress: bool,
    ) -> Result<BackupResult> {
        println!("[INFO] Auto backup for profile: {}", profile.name);

        // Получаем последний полный бэкап для этого профиля
        let last_full = self.get_last_full_backup(&profile.name).await?;

        // Проверяем, нужно ли делать полный бэкап
        let should_do_full = if force_full {
            true
        } else if snapshot_only {
            false
        } else if let Some(last_full) = &last_full {
            // Проверяем по расписанию профиля
            let days_since_full = (Utc::now() - last_full.timestamp).num_days() as u32;
            let full_interval = profile.get_full_interval(&self.backup_engine.config.schedule);

            if days_since_full >= full_interval {
                println!(
                    "[INFO] Last full backup was {} days ago, interval is {} days -> creating full backup",
                    days_since_full, full_interval
                );
                true
            } else {
                println!(
                    "[INFO] Last full backup was {} days ago, interval is {} days -> creating snapshot",
                    days_since_full, full_interval
                );
                false
            }
        } else {
            // Нет предыдущих бэкапов -> делаем полный
            println!("[INFO] No previous full backup found -> creating first full backup");
            true
        };

        if should_do_full {
            println!("[INFO] Creating FULL backup...");
            self.backup_engine
                .create_full(
                    paths,
                    exclude_patterns,
                    Some(&profile.name),
                    false,
                    progress,
                )
                .await
        } else if let Some(last_full) = last_full {
            println!("[INFO] Creating SNAPSHOT from: {}", last_full.id);
            self.create_snapshot(
                &last_full.id,
                paths,
                exclude_patterns,
                Some(&profile.name),
                false,
                progress,
            )
            .await
        } else {
            Err(anyhow::anyhow!(
                "Cannot create snapshot: no parent backup found"
            ))
        }
    }

    /// Вычисляет дельту между двумя наборами файлов
    fn compute_delta(
        &self,
        parent_files: &[FileInfo],
        current_files: &[FileInfo],
    ) -> Result<(Vec<FileInfo>, DeltaStats)> {
        let mut delta_files = Vec::new();
        let mut stats = DeltaStats {
            new_files: 0,
            changed_files: 0,
            deleted_files: 0,
            unchanged_files: 0,
            total_files_current: current_files.len(),
            total_files_previous: parent_files.len(),
        };

        // Создаем HashMap для быстрого поиска родительских файлов по пути
        let parent_map: HashMap<String, &FileInfo> = parent_files
            .iter()
            .map(|f| (f.path.display().to_string(), f))
            .collect();

        // Проверяем текущие файлы
        for current in current_files {
            let current_path = current.path.display().to_string();
            
            if let Some(parent) = parent_map.get(&current_path) {
                if self.is_changed(parent, current) {
                    delta_files.push(current.clone());
                    stats.changed_files += 1;
                } else {
                    stats.unchanged_files += 1;
                }
            } else {
                // Новый файл
                delta_files.push(current.clone());
                stats.new_files += 1;
            }
        }

        // Находим удаленные файлы
        let current_paths: std::collections::HashSet<_> = current_files
            .iter()
            .map(|f| f.path.display().to_string())
            .collect();

        for parent in parent_files {
            let parent_path = parent.path.display().to_string();
            if !current_paths.contains(&parent_path) {
                stats.deleted_files += 1;
                // Для удаленных файлов мы пока ничего не делаем
                // В будущем можно сохранять информацию об удалениях в манифесте
            }
        }

        Ok((delta_files, stats))
    }

    /// Проверяет, изменился ли файл
    fn is_changed(&self, parent: &FileInfo, current: &FileInfo) -> bool {
        // Сравниваем размер, время модификации и хэш
        if parent.size != current.size {
            return true;
        }

        // Разница во времени более 1 секунды
        let time_diff = (parent.mtime - current.mtime).num_seconds().abs();
        if time_diff > 1 {
            return true;
        }

        // Сравниваем хэши
        parent.hash != current.hash
    }

    /// Загружает манифест из бэкапа
    async fn load_manifest(&self, backup_id: &str) -> Result<BackupManifest> {
        let backup_path = self.storage.backup_path(backup_id);

        // Работаем только с незашифрованными файлами (временно)
        let plain_manifest_path = backup_path.join("manifest.json");
        let content = tokio::fs::read_to_string(&plain_manifest_path).await?;

        let manifest: BackupManifest = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse manifest from {}", backup_id))?;

        Ok(manifest)
    }

    /// Преобразует манифест в FileInfo
    fn manifest_to_fileinfo(&self, manifest: &BackupManifest, common_root: &PathBuf) -> Result<Vec<FileInfo>> {
        let mut files = Vec::with_capacity(manifest.files.len());

        for file in &manifest.files {
            let mtime = DateTime::parse_from_rfc3339(&file.mtime)
                .context("Failed to parse mtime")?
                .with_timezone(&Utc);

            // Восстанавливаем абсолютный путь
            let abs_path = if file.abs_path.starts_with('/') {
                PathBuf::from(&file.abs_path)
            } else {
                // Если в манифесте нет абсолютного пути, используем относительный + common_root
                common_root.join(&file.rel_path)
            };

            files.push(FileInfo {
                path: abs_path,
                size: file.size,
                mtime,
                hash: file.hash.clone(),
                mode: file.mode,
            });
        }

        Ok(files)
    }

    /// Создает манифест для снепшота
    fn create_snapshot_manifest(
        &self,
        files: &[FileInfo],
        parent_id: &str,
        common_root: &PathBuf,
    ) -> Result<BackupManifest> {
        let file_list: Vec<ManifestFile> = files
            .iter()
            .map(|f| {
                // Вычисляем относительный путь от common_root
                let rel_path = f.path.strip_prefix(common_root)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| f.path.display().to_string());

                ManifestFile {
                    abs_path: f.path.display().to_string(),
                    rel_path,
                    size: f.size,
                    mtime: f.mtime.to_rfc3339(),
                    hash: f.hash.clone(),
                    mode: f.mode,
                }
            })
            .collect();

        Ok(BackupManifest {
            backup_type: "snapshot".to_string(),
            file_count: files.len(),
            total_size: files.iter().map(|f| f.size).sum(),
            timestamp: Utc::now().to_rfc3339(),
            common_root: Some(common_root.display().to_string()),
            files: file_list,
            parent_id: Some(parent_id.to_string()),
        })
    }

    /// Получает последний полный бэкап для профиля
    pub async fn get_last_full_backup(&self, profile_name: &str) -> Result<Option<BackupInfo>> {
        let all_full = self.storage.list_full()?;

        // Фильтруем по профилю и сортируем по времени (новые сначала)
        let mut profile_backups: Vec<_> = all_full
            .into_iter()
            .filter(|b| b.profile == profile_name)
            .collect();

        profile_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(profile_backups.into_iter().next())
    }

    /// Проверяет целостность цепочки бэкапов
    pub async fn verify_chain(&self, chain_id: &str) -> Result<bool> {
        let chain = self.storage.get_chain(chain_id)?;

        if chain.is_empty() {
            return Ok(false);
        }

        println!("Verifying chain starting from: {}", chain[0].id);

        let mut all_ok = true;
        for (i, backup) in chain.iter().enumerate() {
            print!("  {}. {} [{}]... ", i + 1, backup.id, backup.backup_type);

            let backup_path = self.storage.backup_path(&backup.id);
            let exists = backup_path.exists();

            if exists {
                // Проверяем наличие файлов (зашифрованных или незашифрованных)
                let has_plain = backup_path.join("data.tar.gz").exists();

                if has_plain {
                    println!("OK");
                } else {
                    println!("MISSING FILES");
                    all_ok = false;
                }
            } else {
                println!("MISSING DIRECTORY");
                all_ok = false;
            }

            // Для снепшотов проверяем существование родителя
            if let Some(parent_id) = &backup.parent_id {
                let parent_path = self.storage.backup_path(parent_id);
                if !parent_path.exists() {
                    println!("    Parent {} not found!", parent_id);
                    all_ok = false;
                }
            }
        }

        Ok(all_ok)
    }

    /// Очищает старые снепшоты по политике хранения
    pub async fn cleanup_old_snapshots(
        &self,
        profile_name: &str,
        keep_last: Option<usize>,
        max_age_days: Option<u32>,
        dry_run: bool,
    ) -> Result<usize> {
        let all_chains = self.storage.list_all_chained()?;
        let mut to_delete = Vec::new();

        for (chain_id, chain) in all_chains {
            // Находим полный бэкап в цепочке
            if let Some(full_backup) = chain.first() {
                if full_backup.profile != profile_name {
                    continue; // Не наш профиль
                }

                // Получаем снепшоты (все кроме первого - full)
                let snapshots: Vec<_> = chain.iter().skip(1).collect();

                // Применяем политику keep_last
                if let Some(keep_last) = keep_last {
                    if snapshots.len() > keep_last {
                        let to_keep = &snapshots[..keep_last];
                        let to_remove = &snapshots[keep_last..];

                        for snapshot in to_remove {
                            to_delete.push(snapshot.id.clone());
                        }

                        println!(
                            "Chain {}: keeping last {} of {} snapshots",
                            chain_id,
                            to_keep.len(),
                            snapshots.len()
                        );
                    }
                }

                // Применяем политику max_age
                if let Some(max_age_days) = max_age_days {
                    let cutoff = Utc::now() - Duration::days(max_age_days as i64);

                    for snapshot in snapshots {
                        if snapshot.timestamp < cutoff {
                            to_delete.push(snapshot.id.clone());
                        }
                    }
                }
            }
        }

        // Удаляем дубликаты
        to_delete.sort();
        to_delete.dedup();

        if to_delete.is_empty() {
            println!("No snapshots to delete");
            return Ok(0);
        }

        println!("Found {} snapshots to delete:", to_delete.len());
        for id in &to_delete {
            println!("  - {}", id);
        }

        if dry_run {
            println!("[DRY RUN] Would delete {} snapshots", to_delete.len());
            return Ok(to_delete.len());
        }

        // Удаляем снепшоты
        let mut deleted = 0;
        for id in &to_delete {
            print!("Deleting {}... ", id);

            let backup_path = self.storage.backup_path(id);
            if backup_path.exists() {
                if let Err(e) = fs::remove_dir_all(&backup_path) {
                    println!("ERROR: {}", e);
                } else {
                    println!("OK");
                    deleted += 1;
                }
            } else {
                println!("NOT FOUND");
            }
        }

        println!("Deleted {} snapshots", deleted);
        Ok(deleted)
    }

    /// Проверяет целостность бэкапа
    pub async fn verify_backup(&self, backup_id: &str) -> Result<bool> {
        let backup_path = self.storage.backup_path(backup_id);
        
        if !backup_path.exists() {
            println!("Backup directory not found: {}", backup_id);
            return Ok(false);
        }

        let required_files = vec!["data.tar.gz", "manifest.json", "index-local.json"];
        let mut ok = true;

        for file in required_files {
            let file_path = backup_path.join(file);
            if !file_path.exists() {
                println!("Missing file: {}", file);
                ok = false;
            }
        }

        if ok {
            // Проверяем целостность архива
            let archive_path = backup_path.join("data.tar.gz");
            match self.backup_engine.validate_archive(&archive_path) {
                Ok(_) => println!("Archive validation passed"),
                Err(e) => {
                    println!("Archive validation failed: {}", e);
                    ok = false;
                }
            }
        }

        Ok(ok)
    }
}