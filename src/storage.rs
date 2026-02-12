// src/storage.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    #[serde(rename = "full")]
    Full,
}

impl std::fmt::Display for BackupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupType::Full => write!(f, "full"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: u64,
    pub size_encrypted: u64, // в байтах
    pub checksum: Option<String>, // SHA256 зашифрованного архива
    pub encrypted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIndex {
    pub backup_id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: u64,
    pub size_encrypted: String, // человекочитаемый формат
    pub encrypted: Option<bool>,
    pub checksum: Option<String>, // SHA256 зашифрованного архива
}

impl From<&BackupInfo> for LocalIndex {
    fn from(info: &BackupInfo) -> Self {
        LocalIndex {
            backup_id: info.id.clone(),
            backup_type: info.backup_type,
            timestamp: info.timestamp,
            profile: info.profile.clone(),
            file_count: info.file_count,
            size_encrypted: bytes_to_human(info.size_encrypted),
            encrypted: info.encrypted,
            checksum: info.checksum.clone(),
        }
    }
}

impl From<BackupInfo> for LocalIndex {
    fn from(info: BackupInfo) -> Self {
        LocalIndex::from(&info)
    }
}

/// Преобразует байты в человекочитаемый формат
pub fn bytes_to_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2}{}", size, UNITS[unit_idx])
}

#[derive(Debug, Clone)]
pub struct BackupStorage {
    backup_dir: PathBuf,
}

impl BackupStorage {
    /// Создает новое хранилище по указанному пути
    pub fn new(root: &str) -> Self {
        Self {
            backup_dir: PathBuf::from(root),
        }
    }

    /// Инициализирует структуру директорий
    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.backup_dir)
            .context("Failed to create backup directory")?;
        Ok(())
    }

    /// Возвращает путь к каталогу бэкапа по его ID
    pub fn backup_path(&self, id: &str) -> PathBuf {
        self.backup_dir.join(id)
    }

    /// Возвращает время последнего бэкапа для указанного профиля
    pub fn last_backup_time_for_profile(&self, profile: &str) -> Result<Option<DateTime<Utc>>> {
        let backups = self.list_all()?;
        
        // Фильтруем бэкапы по профилю и находим самый свежий
        let last = backups
            .into_iter()
            .filter(|b| b.profile == profile)
            .max_by_key(|b| b.timestamp)
            .map(|b| b.timestamp);
        
        Ok(last)
    }
    
    /// Читает локальный индекс бэкапа
    pub fn read_local_index(&self, id: &str) -> Result<LocalIndex> {
        let backup_path = self.backup_path(id);
        let index_path = backup_path.join("index-local.json");

        let content = fs::read_to_string(&index_path)
            .with_context(|| format!("Failed to read index for backup {}", id))?;

        let index: LocalIndex = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse index for backup {}", id))?;

        Ok(index)
    }

    /// Записывает локальный индекс бэкапа
    pub fn write_local_index(&self, info: &BackupInfo) -> Result<()> {
        let backup_path = self.backup_path(&info.id);

        fs::create_dir_all(&backup_path)
            .with_context(|| format!("Failed to create backup directory for {}", info.id))?;

        let index = LocalIndex::from(info);
        let index_path = backup_path.join("index-local.json");

        let content = serde_json::to_string_pretty(&index)
            .context("Failed to serialize index")?;

        fs::write(&index_path, content)
            .with_context(|| format!("Failed to write index to {}", index_path.display()))?;

        Ok(())
    }

    /// Возвращает список всех бэкапов
    pub fn list_all(&self) -> Result<Vec<BackupInfo>> {
        self.list_backups_in_dir(&self.backup_dir)
    }

    /// Возвращает все бэкапы (для совместимости – каждый бэкап отдельная цепочка)
    pub fn list_all_chained(&self) -> Result<HashMap<String, Vec<BackupInfo>>> {
        let mut chains = HashMap::new();
        let backups = self.list_all()?;
        for backup in backups {
            chains.insert(backup.id.clone(), vec![backup.clone()]);
        }
        Ok(chains)
    }

    /// Возвращает информацию о цепочке бэкапов (для совместимости)
    pub fn get_chain(&self, chain_id: &str) -> Result<Vec<BackupInfo>> {
        let backup = self.read_backup_info(chain_id)?;
        Ok(vec![backup])
    }

    /// Читает полную информацию о бэкапе из индекса
    pub fn read_backup_info(&self, id: &str) -> Result<BackupInfo> {
        let local_index = self.read_local_index(id)?;

        // Конвертируем человекочитаемый размер обратно в байты
        let size_bytes = human_to_bytes(&local_index.size_encrypted).unwrap_or(0);

        Ok(BackupInfo {
            id: local_index.backup_id,
            backup_type: local_index.backup_type,
            timestamp: local_index.timestamp,
            profile: local_index.profile,
            file_count: local_index.file_count,
            size_encrypted: size_bytes,
            checksum: local_index.checksum.clone(), // ✅ теперь контрольная сумма сохраняется
            encrypted: local_index.encrypted,
        })
    }

    /// Вспомогательный метод для списка бэкапов в директории
    fn list_backups_in_dir(&self, dir: &Path) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();

        if !dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(dir).context("Failed to read backup directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_dir() {
                let backup_id = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                match self.read_backup_info(&backup_id) {
                    Ok(info) => backups.push(info),
                    Err(e) => {
                        eprintln!("Warning: Failed to read backup {}: {}", backup_id, e);
                    }
                }
            }
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(backups)
    }

    /// Генерирует ID для нового бэкапа
    pub fn generate_id(&self, backup_type: BackupType, timestamp: DateTime<Utc>) -> String {
        let date_str = timestamp.format("%Y%m%d-%H%M%S").to_string();
        match backup_type {
            BackupType::Full => format!("full-{}", date_str),
        }
    }

    /// Проверяет целостность бэкапа (базовая проверка наличия файлов)
    pub fn verify_backup(&self, id: &str) -> Result<bool> {
        let backup_path = self.backup_path(id);

        if !backup_path.exists() {
            return Ok(false);
        }

        let required_files = ["index-local.json", "data.tar.gz", "manifest.json"];
        for file in required_files {
            if !backup_path.join(file).exists() {
                return Ok(false);
            }
        }

        match self.read_local_index(id) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Возвращает статистику хранилища
    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let mut stats = StorageStats {
            total_backups: 0,
            total_size: 0,
            profiles: HashMap::new(),
        };

        if let Ok(backups) = self.list_all() {
            stats.total_backups = backups.len();
            for backup in backups {
                stats.total_size += backup.size_encrypted;
                *stats.profiles.entry(backup.profile).or_insert(0) += 1;
            }
        }

        Ok(stats)
    }
}

/// Статистика хранилища
#[derive(Debug)]
pub struct StorageStats {
    pub total_backups: usize,
    pub total_size: u64,
    pub profiles: HashMap<String, usize>,
}

impl StorageStats {
    pub fn display(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Total backups: {}\n", self.total_backups));
        output.push_str(&format!(
            "Total size: {}\n",
            bytes_to_human(self.total_size)
        ));

        if !self.profiles.is_empty() {
            output.push_str("Backups by profile:\n");
            for (profile, count) in &self.profiles {
                output.push_str(&format!("  {}: {}\n", profile, count));
            }
        }

        output
    }
}

/// Преобразует человекочитаемый размер в байты
fn human_to_bytes(human: &str) -> Option<u64> {
    let human = human.trim().to_lowercase();
    let units = [
        ("tb", 1024u64.pow(4)),
        ("gb", 1024u64.pow(3)),
        ("mb", 1024u64.pow(2)),
        ("kb", 1024u64),
        ("b", 1),
    ];

    for (unit, multiplier) in units {
        if human.ends_with(unit) {
            let num_str = &human[..human.len() - unit.len()];
            if let Ok(num) = num_str.trim().parse::<f64>() {
                return Some((num * multiplier as f64) as u64);
            }
        }
    }

    human.parse::<u64>().ok()
}