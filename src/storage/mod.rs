// src/storage/mod.rs

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::utils; // для bytes_to_human и human_to_bytes

pub mod s3_uploader;

/// Тип резервной копии (в настоящий момент поддерживается только полная)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    #[serde(rename = "full")]
    Full,
}

impl std::fmt::Display for BackupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupType::Full => write!(f, "полная"),
        }
    }
}

/// Информация о резервной копии, хранящаяся в памяти
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: u64,
    pub size_encrypted: u64,            // размер в байтах
    pub checksum: Option<String>,       // хеш (Стрибог) зашифрованного архива
    pub encrypted: Option<bool>,
}

/// Локальный индекс (сериализуется в JSON и сохраняется на диск)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIndex {
    pub backup_id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: u64,
    pub size_encrypted: String,         // человекочитаемый размер
    pub encrypted: Option<bool>,
    pub checksum: Option<String>,
}

impl From<&BackupInfo> for LocalIndex {
    fn from(info: &BackupInfo) -> Self {
        LocalIndex {
            backup_id: info.id.clone(),
            backup_type: info.backup_type,
            timestamp: info.timestamp,
            profile: info.profile.clone(),
            file_count: info.file_count,
            size_encrypted: utils::bytes_to_human(info.size_encrypted),
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

/// Хранилище резервных копий – управляет директориями, индексами и метаданными
#[derive(Debug, Clone)]
pub struct BackupStorage {
    backup_dir: PathBuf,
}

impl BackupStorage {
    /// Создаёт новое хранилище по указанному корневому пути
    pub fn new(root: &str) -> Self {
        Self {
            backup_dir: PathBuf::from(root),
        }
    }

    /// Инициализирует структуру каталогов (создаёт корневую папку, если её нет)
    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.backup_dir)
            .context("Не удалось создать каталог резервных копий")?;
        Ok(())
    }

    /// Возвращает путь к каталогу конкретной резервной копии по её идентификатору
    pub fn backup_path(&self, id: &str) -> PathBuf {
        self.backup_dir.join(id)
    }

    /// Возвращает время последней резервной копии для указанного профиля
    pub fn last_backup_time_for_profile(&self, profile: &str) -> Result<Option<DateTime<Utc>>> {
        let backups = self.list_all()?;
        let last = backups
            .into_iter()
            .filter(|b| b.profile == profile)
            .max_by_key(|b| b.timestamp)
            .map(|b| b.timestamp);
        Ok(last)
    }

    /// Читает локальный индекс резервной копии
    pub fn read_local_index(&self, id: &str) -> Result<LocalIndex> {
        let backup_path = self.backup_path(id);
        let index_path = backup_path.join("index-local.json");

        let content = fs::read_to_string(&index_path)
            .with_context(|| format!("Не удалось прочитать индекс для копии {}", id))?;

        let index: LocalIndex = serde_json::from_str(&content)
            .with_context(|| format!("Не удалось разобрать индекс для копии {}", id))?;

        Ok(index)
    }

    /// Записывает локальный индекс резервной копии
    pub fn write_local_index(&self, info: &BackupInfo) -> Result<()> {
        let backup_path = self.backup_path(&info.id);
        fs::create_dir_all(&backup_path)
            .with_context(|| format!("Не удалось создать каталог для копии {}", info.id))?;

        let index = LocalIndex::from(info);
        let index_path = backup_path.join("index-local.json");

        let content = serde_json::to_string_pretty(&index)
            .context("Не удалось сериализовать индекс")?;

        fs::write(&index_path, content)
            .with_context(|| format!("Не удалось записать индекс в {}", index_path.display()))?;

        Ok(())
    }

    /// Возвращает список всех резервных копий
    pub fn list_all(&self) -> Result<Vec<BackupInfo>> {
        self.list_backups_in_dir(&self.backup_dir)
    }

    /// Читает полную информацию о резервной копии из индекса
    pub fn read_backup_info(&self, id: &str) -> Result<BackupInfo> {
        let local_index = self.read_local_index(id)?;
        // Преобразуем человекочитаемый размер обратно в байты
        let size_bytes = utils::human_to_bytes(&local_index.size_encrypted).unwrap_or(0);

        Ok(BackupInfo {
            id: local_index.backup_id,
            backup_type: local_index.backup_type,
            timestamp: local_index.timestamp,
            profile: local_index.profile,
            file_count: local_index.file_count,
            size_encrypted: size_bytes,
            checksum: local_index.checksum.clone(),
            encrypted: local_index.encrypted,
        })
    }

    /// Вспомогательный метод для чтения списка копий из указанной директории
    fn list_backups_in_dir(&self, dir: &Path) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();

        if !dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(dir).context("Не удалось прочитать каталог резервных копий")? {
            let entry = entry.context("Не удалось прочитать запись каталога")?;
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
                        eprintln!("Предупреждение: не удалось прочитать информацию о копии {}: {}", backup_id, e);
                    }
                }
            }
        }

        // Сортируем от новых к старым
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(backups)
    }

    /// Генерирует идентификатор для новой резервной копии
    pub fn generate_id(&self, backup_type: BackupType, timestamp: DateTime<Utc>) -> String {
        let date_str = timestamp.format("%Y%m%d-%H%M%S").to_string();
        match backup_type {
            BackupType::Full => format!("full-{}", date_str),
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
    /// Человекочитаемое представление статистики
    pub fn display(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Всего копий: {}\n", self.total_backups));
        output.push_str(&format!(
            "Общий размер: {}\n",
            utils::bytes_to_human(self.total_size)
        ));

        if !self.profiles.is_empty() {
            output.push_str("Копий по профилям:\n");
            for (profile, count) in &self.profiles {
                output.push_str(&format!("  {}: {}\n", profile, count));
            }
        }

        output
    }
}