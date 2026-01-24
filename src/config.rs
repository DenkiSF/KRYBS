// src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Расписание для конкретного профиля
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSchedule {
    /// Интервал полного бэкапа в днях
    #[serde(default = "default_full_days")]
    pub full_days: u32,

    /// Интервал снэпшотов в часах
    #[serde(default = "default_snapshot_hours")]
    pub snapshot_hours: u32,
}

fn default_full_days() -> u32 {
    30
}
fn default_snapshot_hours() -> u32 {
    6
}

/// Политика хранения для конкретного профиля
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRetention {
    /// Хранение полных бэкапов в днях
    #[serde(default = "default_retention_full")]
    pub full_days: u32,

    /// Хранение снэпшотов в днях
    #[serde(default = "default_retention_snapshot")]
    pub snapshot_days: u32,
}

fn default_retention_full() -> u32 {
    90
}
fn default_retention_snapshot() -> u32 {
    30
}

/// Профиль бэкапа - любой путь или сервис
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Имя профиля (может быть путем: "/home/docs" или именем сервиса: "postgres")
    pub name: String,

    /// Пути для бэкапа (файлы, директории)
    pub paths: Vec<PathBuf>,

    /// Паттерны исключения
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Расписание профиля (опционально)
    #[serde(default)]
    pub schedule: Option<ProfileSchedule>,

    /// Политика хранения профиля (опционально)
    #[serde(default)]
    pub retention: Option<ProfileRetention>,
}

impl Profile {
    /// Создает профиль для произвольного пути
    pub fn for_path(path: &Path) -> Self {
        let name = path.display().to_string().trim_end_matches('/').to_string();

        Self {
            name,
            paths: vec![path.to_path_buf()],
            exclude: Vec::new(),
            schedule: None,
            retention: None,
        }
    }

    /// Получает интервал полного бэкапа
    pub fn get_full_interval(&self, global_schedule: &GlobalSchedule) -> u32 {
        self.schedule
            .as_ref()
            .map(|s| s.full_days)
            .unwrap_or(global_schedule.full_interval_days)
    }

    /// Получает интервал снэпшотов
    pub fn get_snapshot_interval(&self, global_schedule: &GlobalSchedule) -> u32 {
        self.schedule
            .as_ref()
            .map(|s| s.snapshot_hours)
            .unwrap_or(global_schedule.snapshot_interval_hours)
    }

    /// Получает политику хранения полных бэкапов
    pub fn get_full_retention(&self, global_retention: &GlobalRetention) -> u32 {
        self.retention
            .as_ref()
            .map(|r| r.full_days)
            .unwrap_or(global_retention.full_days)
    }

    /// Получает политику хранения снэпшотов
    pub fn get_snapshot_retention(&self, global_retention: &GlobalRetention) -> u32 {
        self.retention
            .as_ref()
            .map(|r| r.snapshot_days)
            .unwrap_or(global_retention.snapshot_days)
    }
}

/// Глобальное расписание (значения по умолчанию)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSchedule {
    /// Глобальный интервал полного бэкапа в днях
    #[serde(default = "default_global_full_days")]
    pub full_interval_days: u32,

    /// Глобальный интервал снэпшотов в часах
    #[serde(default = "default_global_snapshot_hours")]
    pub snapshot_interval_hours: u32,
}

fn default_global_full_days() -> u32 {
    60
}
fn default_global_snapshot_hours() -> u32 {
    24
}

/// Глобальная политика хранения
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRetention {
    /// Глобальное хранение полных бэкапов в днях
    #[serde(default = "default_global_full_days")]
    pub full_days: u32,

    /// Глобальное хранение снэпшотов в днях
    #[serde(default = "default_global_snapshot_days")]
    pub snapshot_days: u32,
}

fn default_global_snapshot_days() -> u32 {
    180
}

/// Криптография (структура оставлена для совместимости, но не используется)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Путь к мастер-ключу
    #[serde(default = "default_master_key_path")]
    pub master_key_path: PathBuf,

    /// Удалять незашифрованные файлы после шифрования
    #[serde(default = "default_delete_plain")]
    pub delete_plain: bool,

    /// Размер чанка для потокового шифрования (байты)
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,

    /// Версия формата шифрования
    #[serde(default = "default_crypto_version")]
    pub version: u8,
}

fn default_master_key_path() -> PathBuf {
    PathBuf::from("/etc/krybs/master.key")
}

fn default_delete_plain() -> bool {
    true
}
fn default_chunk_size() -> usize {
    1024 * 1024
} // 1MB
fn default_crypto_version() -> u8 {
    1
}

/// Основная конфигурация
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Глобальные настройки
    #[serde(default)]
    pub core: CoreConfig,

    /// Глобальное расписание (значения по умолчанию для профилей)
    #[serde(default)]
    pub schedule: GlobalSchedule,

    /// Глобальная политика хранения (значения по умолчанию для профилей)
    #[serde(default)]
    pub retention: GlobalRetention,

    /// Криптография (структура оставлена для совместимости)
    #[serde(default)]
    pub crypto: CryptoConfig,

    /// Профили бэкапа
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

/// Глобальные настройки
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Директория для хранения бэкапов
    #[serde(default = "default_backup_dir")]
    pub backup_dir: PathBuf,
}

fn default_backup_dir() -> PathBuf {
    PathBuf::from("/backup")
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            backup_dir: default_backup_dir(),
        }
    }
}

impl Default for GlobalSchedule {
    fn default() -> Self {
        Self {
            full_interval_days: default_global_full_days(),
            snapshot_interval_hours: default_global_snapshot_hours(),
        }
    }
}

impl Default for GlobalRetention {
    fn default() -> Self {
        Self {
            full_days: default_global_full_days(),
            snapshot_days: default_global_snapshot_days(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            master_key_path: default_master_key_path(),
            delete_plain: default_delete_plain(),
            chunk_size: default_chunk_size(),
            version: default_crypto_version(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            schedule: GlobalSchedule::default(),
            retention: GlobalRetention::default(),
            crypto: CryptoConfig::default(),
            profiles: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound,
    Invalid(String),
    IoError(std::io::Error),
    ParseError(toml::de::Error),
    SerializeError(toml::ser::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound => write!(f, "Configuration file not found"),
            ConfigError::Invalid(msg) => write!(f, "Invalid configuration: {}", msg),
            ConfigError::IoError(e) => write!(f, "IO error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::SerializeError(e) => write!(f, "Serialize error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Загружает конфигурацию из стандартных путей или указанного файла
    pub fn load(config_path: Option<&Path>) -> Result<Self, ConfigError> {
        let paths = get_config_paths(config_path);

        for path in paths {
            if path.exists() {
                println!("Loading config from: {}", path.display());
                return Self::load_from_file(&path);
            }
        }

        Err(ConfigError::NotFound)
    }

    /// Загружает конфигурацию из конкретного файла
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(ConfigError::IoError)?;

        let config: Self = toml::from_str(&content).map_err(ConfigError::ParseError)?;

        config.validate()?;
        Ok(config)
    }

    /// Находит профиль по имени
    pub fn find_profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Находит профиль по пути
    pub fn find_profile_by_path(&self, path: &Path) -> Option<&Profile> {
        let path_str = path.display().to_string();
        self.profiles.iter().find(|p| {
            p.paths
                .iter()
                .any(|profile_path| profile_path.display().to_string() == path_str)
        })
    }

    /// Валидирует конфигурацию
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Проверка backup_dir
        if !self.core.backup_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "backup_dir must be absolute path: {}",
                self.core.backup_dir.display()
            )));
        }

        // Проверка интервалов глобального расписания
        if self.schedule.full_interval_days == 0 {
            return Err(ConfigError::Invalid(
                "full_interval_days must be greater than 0".to_string(),
            ));
        }

        if self.schedule.snapshot_interval_hours == 0 {
            return Err(ConfigError::Invalid(
                "snapshot_interval_hours must be greater than 0".to_string(),
            ));
        }

        // Проверка глобальной политики хранения
        if self.retention.full_days == 0 {
            return Err(ConfigError::Invalid(
                "full_days must be greater than 0".to_string(),
            ));
        }

        if self.retention.snapshot_days == 0 {
            return Err(ConfigError::Invalid(
                "snapshot_days must be greater than 0".to_string(),
            ));
        }

        // Проверка профилей
        for profile in &self.profiles {
            if profile.paths.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "Profile '{}' has no paths defined",
                    profile.name
                )));
            }

            // Проверяем расписание профиля, если указано
            if let Some(schedule) = &profile.schedule {
                if schedule.full_days == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "Profile '{}': full_days must be greater than 0",
                        profile.name
                    )));
                }

                if schedule.snapshot_hours == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "Profile '{}': snapshot_hours must be greater than 0",
                        profile.name
                    )));
                }
            }

            // Проверяем политику хранения профиля, если указано
            if let Some(retention) = &profile.retention {
                if retention.full_days == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "Profile '{}': full_days must be greater than 0",
                        profile.name
                    )));
                }

                if retention.snapshot_days == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "Profile '{}': snapshot_days must be greater than 0",
                        profile.name
                    )));
                }
            }
        }

        Ok(())
    }

    /// Сохраняет конфигурацию в файл
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        // Создаём директорию если её нет
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ConfigError::IoError)?;
        }

        let content = toml::to_string_pretty(self).map_err(ConfigError::SerializeError)?;

        fs::write(path, content).map_err(ConfigError::IoError)?;

        Ok(())
    }

    /// Возвращает информацию о конфигурации для команды status
    pub fn info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();

        info.insert(
            "backup_dir".to_string(),
            self.core.backup_dir.display().to_string(),
        );
        info.insert(
            "master_key_path".to_string(),
            self.crypto.master_key_path.display().to_string(),
        );
        info.insert(
            "global_full_interval".to_string(),
            self.schedule.full_interval_days.to_string(),
        );
        info.insert(
            "global_snapshot_interval".to_string(),
            self.schedule.snapshot_interval_hours.to_string(),
        );
        info.insert(
            "global_full_retention".to_string(),
            self.retention.full_days.to_string(),
        );
        info.insert(
            "global_snapshot_retention".to_string(),
            self.retention.snapshot_days.to_string(),
        );
        info.insert(
            "profiles_count".to_string(),
            self.profiles.len().to_string(),
        );

        if !self.profiles.is_empty() {
            let profile_names: Vec<String> = self.profiles.iter().map(|p| p.name.clone()).collect();
            info.insert("profiles".to_string(), profile_names.join(", "));
        }

        info
    }
}

/// Возвращает список путей для поиска конфигурации
fn get_config_paths(custom_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Пользовательский путь (если указан)
    if let Some(path) = custom_path {
        paths.push(path.to_path_buf());
    }

    // 2. /etc/krybs/config.toml
    paths.push(PathBuf::from("/etc/krybs/config.toml"));

    // 3. ~/.config/krybs/config.toml
    if let Some(home) = dirs::config_dir() {
        paths.push(home.join("krybs/config.toml"));
    }

    // 4. Текущая директория
    paths.push(PathBuf::from("config.toml"));

    paths
}

/// Инициализирует конфигурационный файл с примерами
pub fn init_config(output_path: Option<&Path>, interactive: bool, _defaults: bool) -> Result<()> {
    let mut config = Config::default();

    // Добавляем примеры профилей
    config.profiles = vec![
        Profile {
            name: "postgres".to_string(),
            paths: vec![
                PathBuf::from("/var/lib/postgresql"),
                PathBuf::from("/etc/postgresql"),
            ],
            exclude: vec!["*.wal".to_string()],
            schedule: Some(ProfileSchedule {
                full_days: 30,
                snapshot_hours: 6,
            }),
            retention: Some(ProfileRetention {
                full_days: 90,
                snapshot_days: 30,
            }),
        },
        Profile {
            name: "/home/docs".to_string(),
            paths: vec![PathBuf::from("/home/user/docs")],
            exclude: vec!["cache/".to_string()],
            schedule: None,
            retention: None,
        },
        Profile {
            name: "nginx-service".to_string(),
            paths: vec![PathBuf::from("/etc/nginx"), PathBuf::from("/var/log/nginx")],
            exclude: vec!["*.tmp".to_string(), "cache/".to_string()],
            schedule: Some(ProfileSchedule {
                full_days: 7,
                snapshot_hours: 12,
            }),
            retention: Some(ProfileRetention {
                full_days: 30,
                snapshot_days: 7,
            }),
        },
        Profile {
            name: "system-logs".to_string(),
            paths: vec![PathBuf::from("/var/log")],
            exclude: vec!["*.tmp".to_string(), "*.temp".to_string()],
            schedule: None,
            retention: None,
        },
    ];

    // Определяем путь для сохранения
    let save_path = match output_path {
        Some(path) => path.to_path_buf(),
        None => {
            // По умолчанию сохраняем в ~/.config/krybs/config.toml
            if let Some(config_dir) = dirs::config_dir() {
                config_dir.join("krybs/config.toml")
            } else {
                PathBuf::from("config.toml")
            }
        }
    };

    println!("Creating configuration file at: {}", save_path.display());
    println!("Configuration:");
    println!("  Backup directory: {}", config.core.backup_dir.display());
    println!(
        "  Master key path: {}",
        config.crypto.master_key_path.display()
    );
    println!("  Delete plaintext: {}", config.crypto.delete_plain);
    println!(
        "  Global full interval: {} days",
        config.schedule.full_interval_days
    );
    println!(
        "  Global snapshot interval: {} hours",
        config.schedule.snapshot_interval_hours
    );
    println!(
        "  Global full retention: {} days",
        config.retention.full_days
    );
    println!(
        "  Global snapshot retention: {} days",
        config.retention.snapshot_days
    );
    println!("  Example profiles ({}):", config.profiles.len());

    for profile in &config.profiles {
        println!("    - {} ({} paths)", profile.name, profile.paths.len());
        if let Some(schedule) = &profile.schedule {
            println!(
                "      Schedule: full every {} days, snapshot every {} hours",
                schedule.full_days, schedule.snapshot_hours
            );
        }
        if let Some(retention) = &profile.retention {
            println!(
                "      Retention: full {} days, snapshot {} days",
                retention.full_days, retention.snapshot_days
            );
        }
    }

    if interactive {
        use std::io::{self, Write};

        print!("Save configuration? [Y/n]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "n" {
            println!("Configuration cancelled");
            return Ok(());
        }
    }

    config
        .save(&save_path)
        .context("Failed to save configuration")?;

    println!("Configuration saved successfully!");
    println!("You can edit it manually at: {}", save_path.display());

    Ok(())
}