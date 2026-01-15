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
    #[serde(rename = "snapshot")]
    Snapshot,
}

impl std::fmt::Display for BackupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupType::Full => write!(f, "full"),
            BackupType::Snapshot => write!(f, "snapshot"),
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
    pub parent_id: Option<String>,
    pub checksum: Option<String>, // SHA256 зашифрованного архива
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIndex {
    pub backup_id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: u64,
    pub size_encrypted: String, // Человекочитаемый формат
    pub parent_id: Option<String>,
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
            parent_id: info.parent_id.clone(),
        }
    }
}

impl From<BackupInfo> for LocalIndex {
    fn from(info: BackupInfo) -> Self {
        LocalIndex::from(&info)
    }
}

/// Преобразует байты в человекочитаемый формат
pub fn bytes_to_human(bytes: u64) -> String {  // Добавлено `pub`
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
    _root: PathBuf,  // Добавлено подчеркивание
    full_dir: PathBuf,
    snap_dir: PathBuf,
    chains_dir: PathBuf,
}

impl BackupStorage {
    /// Создает новое хранилище по указанному пути
    pub fn new(root: &str) -> Self {
        let root_path = PathBuf::from(root);
        Self {
            full_dir: root_path.join("full"),
            snap_dir: root_path.join("snap"),
            chains_dir: root_path.join("chains"),
            _root: root_path,  // Добавлено подчеркивание
        }
    }
    
    /// Инициализирует структуру директорий
    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.full_dir)
            .context("Failed to create full backup directory")?;
        fs::create_dir_all(&self.snap_dir)
            .context("Failed to create snapshot directory")?;
        fs::create_dir_all(&self.chains_dir)
            .context("Failed to create chains directory")?;
        
        Ok(())
    }
    
    /// Возвращает путь к каталогу бэкапа по его ID
    pub fn backup_path(&self, id: &str) -> PathBuf {
        // Определяем тип бэкапа по префиксу ID
        if id.starts_with("full-") {
            self.full_dir.join(id)
        } else if id.starts_with("snap-") {
            self.snap_dir.join(id)
        } else {
            // Если префикс не указан, пробуем найти в обеих директориях
            let full_path = self.full_dir.join(id);
            if full_path.exists() {
                full_path
            } else {
                self.snap_dir.join(id)
            }
        }
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
        
        // Создаем директорию бэкапа если её нет
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
    
    /// Возвращает список всех полных бэкапов
    pub fn list_full(&self) -> Result<Vec<BackupInfo>> {
        self.list_backups_in_dir(&self.full_dir, BackupType::Full, None)
    }
    
    /// Возвращает список снепшотов для указанного родительского бэкапа
    pub fn list_snapshots(&self, parent_id: &str) -> Result<Vec<BackupInfo>> {
        self.list_backups_in_dir(&self.snap_dir, BackupType::Snapshot, Some(parent_id))
    }
    
    /// Возвращает все бэкапы (полные и снепшоты) сгруппированные по цепочкам
    pub fn list_all_chained(&self) -> Result<HashMap<String, Vec<BackupInfo>>> {
        let mut chains = HashMap::new();
        
        // Находим все полные бэкапы
        let full_backups = self.list_full()?;
        
        for full_backup in full_backups {
            let mut chain = vec![full_backup.clone()];
            
            // Находим все снепшоты для этого полного бэкапа
            let snapshots = self.list_snapshots(&full_backup.id)?;
            chain.extend(snapshots);
            
            chains.insert(full_backup.id.clone(), chain);
        }
        
        Ok(chains)
    }
    
    /// Возвращает информацию о цепочке бэкапов
    pub fn get_chain(&self, chain_id: &str) -> Result<Vec<BackupInfo>> {
        let mut chain = Vec::new();
        
        // Проверяем, существует ли бэкап с таким ID
        let backup_path = self.backup_path(chain_id);
        if !backup_path.exists() {
            // Если не существует, возможно это ID полного бэкапа без префикса
            let full_id = if chain_id.starts_with("full-") {
                chain_id.to_string()
            } else {
                format!("full-{}", chain_id)
            };
            
            let full_path = self.full_dir.join(&full_id);
            if !full_path.exists() {
                return Err(anyhow::anyhow!("Chain not found: {}", chain_id));
            }
            
            // Добавляем полный бэкап
            if let Ok(full_info) = self.read_backup_info(&full_id) {
                chain.push(full_info);
            }
            
            // Добавляем снепшоты
            let snapshots = self.list_snapshots(&full_id)?;
            chain.extend(snapshots);
        } else {
            // Это конкретный бэкап, находим его цепочку
            let info = self.read_backup_info(chain_id)?;
            
            if info.backup_type == BackupType::Full {
                // Если это полный бэкап, собираем всю его цепочку
                let info_clone = info.clone();  // Клонируем для использования
                chain.push(info);
                let snapshots = self.list_snapshots(&info_clone.id)?;
                chain.extend(snapshots);
            } else if let Some(parent_id) = &info.parent_id {
                // Если это снепшот, находим родительский full и всю цепочку
                let parent_id_clone = parent_id.clone();
                let info_id = info.id.clone();
                
                if let Ok(parent_info) = self.read_backup_info(&parent_id_clone) {
                    chain.push(parent_info);
                }
                chain.push(info);
                
                // Ищем другие снепшоты того же родителя
                let other_snapshots = self.list_snapshots(&parent_id_clone)?;
                for snapshot in other_snapshots {
                    if snapshot.id != info_id {
                        chain.push(snapshot);
                    }
                }
                
                // Сортируем по времени
                chain.sort_by_key(|b| b.timestamp);
            }
        }
        
        Ok(chain)
    }
    
    /// Читает полную информацию о бэкапе из индекса
    fn read_backup_info(&self, id: &str) -> Result<BackupInfo> {
        let local_index = self.read_local_index(id)?;
        
        // Конвертируем human-readable размер обратно в байты
        let size_bytes = human_to_bytes(&local_index.size_encrypted)
            .unwrap_or(0);
        
        Ok(BackupInfo {
            id: local_index.backup_id,
            backup_type: local_index.backup_type,
            timestamp: local_index.timestamp,
            profile: local_index.profile,
            file_count: local_index.file_count,
            size_encrypted: size_bytes,
            parent_id: local_index.parent_id,
            checksum: None, // Для полной информации нужен манифест
        })
    }
    
    /// Вспомогательный метод для списка бэкапов в директории
    fn list_backups_in_dir(
        &self, 
        dir: &Path, 
        _backup_type: BackupType,
        parent_filter: Option<&str>
    ) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();
        
        if !dir.exists() {
            return Ok(backups);
        }
        
        for entry in fs::read_dir(dir).context("Failed to read backup directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();
            
            if path.is_dir() {
                let backup_id = path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                
                // Пропускаем если не соответствует фильтру родителя
                if let Some(parent_id) = parent_filter {
                    if let Ok(index) = self.read_local_index(&backup_id) {
                        if index.parent_id.as_deref() != Some(parent_id) {
                            continue;
                        }
                    } else {
                        continue; // Не можем прочитать индекс, пропускаем
                    }
                }
                
                // Читаем информацию о бэкапе
                match self.read_backup_info(&backup_id) {
                    Ok(info) => backups.push(info),
                    Err(e) => {
                        eprintln!("Warning: Failed to read backup {}: {}", backup_id, e);
                    }
                }
            }
        }
        
        // Сортируем по времени (новые сначала)
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(backups)
    }
    
    /// Генерирует ID для нового бэкапа
    pub fn generate_id(&self, backup_type: BackupType, timestamp: DateTime<Utc>) -> String {
        let date_str = timestamp.format("%Y%m%d-%H%M%S").to_string();
        match backup_type {
            BackupType::Full => format!("full-{}", date_str),
            BackupType::Snapshot => format!("snap-{}", date_str),
        }
    }
    
    /// Проверяет целостность бэкапа
    pub fn verify_backup(&self, id: &str) -> Result<bool> {
        let backup_path = self.backup_path(id);
        
        // Проверяем существование директории
        if !backup_path.exists() {
            return Ok(false);
        }
        
        // Проверяем наличие обязательных файлов
        let required_files = ["index-local.json", "data.tar.gz.enc", "manifest.json.enc"];
        for file in required_files {
            if !backup_path.join(file).exists() {
                return Ok(false);
            }
        }
        
        // Проверяем валидность индекса
        match self.read_local_index(id) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Возвращает статистику хранилища
    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let mut stats = StorageStats {
            total_backups: 0,
            full_backups: 0,
            snapshots: 0,
            total_size: 0,
            profiles: HashMap::new(),
        };
        
        // Считаем полные бэкапы
        if let Ok(full_backups) = self.list_full() {
            stats.full_backups = full_backups.len();
            for backup in full_backups {
                stats.total_size += backup.size_encrypted;
                *stats.profiles.entry(backup.profile).or_insert(0) += 1;
            }
        }
        
        // Считаем снепшоты
        if let Ok(all_chains) = self.list_all_chained() {
            for chain in all_chains.values() {
                for backup in chain.iter().skip(1) { // Пропускаем первый (full)
                    if backup.backup_type == BackupType::Snapshot {
                        stats.snapshots += 1;
                        stats.total_size += backup.size_encrypted;
                        *stats.profiles.entry(backup.profile.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
        
        stats.total_backups = stats.full_backups + stats.snapshots;
        
        Ok(stats)
    }
}

/// Статистика хранилища
#[derive(Debug)]
pub struct StorageStats {
    pub total_backups: usize,
    pub full_backups: usize,
    pub snapshots: usize,
    pub total_size: u64,
    pub profiles: HashMap<String, usize>,
}

impl StorageStats {
    pub fn display(&self) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("Total backups: {}\n", self.total_backups));
        output.push_str(&format!("  Full backups: {}\n", self.full_backups));
        output.push_str(&format!("  Snapshots: {}\n", self.snapshots));
        output.push_str(&format!("Total size: {}\n", bytes_to_human(self.total_size)));
        
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
fn human_to_bytes(human: &str) -> Option<u64> {  // Удален неиспользуемый параметр
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
    
    // Если не нашли единицы измерения, пробуем просто число
    human.parse::<u64>().ok()
}