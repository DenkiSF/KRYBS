// src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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

    /// Использовать шифрование для этого профиля (по умолчанию true)
    #[serde(default = "default_encrypt")]
    pub encrypt: bool,

    /// Уровень сжатия (0-9, где 0 - нет сжатия, 9 - максимальное)
    #[serde(default = "default_compression")]
    pub compression: u8,
}

fn default_encrypt() -> bool {
    true
}

fn default_compression() -> u8 {
    6
}

impl Profile {
    /// Создает профиль для произвольного пути
    pub fn for_path(path: &Path) -> Self {
        let name = path.display().to_string().trim_end_matches('/').to_string();

        Self {
            name,
            paths: vec![path.to_path_buf()],
            exclude: Vec::new(),
            encrypt: true,
            compression: 6,
        }
    }
}

/// Конфигурация шифрования "Кузнечик"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Путь к мастер-ключу шифрования "Кузнечик" (256 бит)
    #[serde(default = "default_master_key_path")]
    pub master_key_path: PathBuf,

    /// Удалять незашифрованные файлы после шифрования
    #[serde(default = "default_delete_plain")]
    pub delete_plain: bool,

    /// Размер чанка для потокового шифрования (байты)
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,

    /// Режим шифрования (CBC, CTR, OFB, CFB)
    #[serde(default = "default_cipher_mode")]
    pub cipher_mode: String,

    /// Использовать KDF (Key Derivation Function) для усиления ключа
    #[serde(default = "default_use_kdf")]
    pub use_kdf: bool,

    /// Размер соли для KDF (байты)
    #[serde(default = "default_salt_size")]
    pub salt_size: usize,
}

fn default_master_key_path() -> PathBuf {
    PathBuf::from("/etc/krybs/master.key")
}

fn default_delete_plain() -> bool {
    true
}

fn default_chunk_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_cipher_mode() -> String {
    "CBC".to_string()
}

fn default_use_kdf() -> bool {
    true
}

fn default_salt_size() -> usize {
    32
}

/// Основная конфигурация
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Глобальные настройки
    #[serde(default)]
    pub core: CoreConfig,

    /// Криптография с алгоритмом "Кузнечик"
    #[serde(default)]
    pub crypto: CryptoConfig,

    /// Профили бэкапа
    #[serde(default)]
    pub profiles: Vec<Profile>,

    /// Настройки автоматического обслуживания
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
}

/// Настройки автоматического обслуживания
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    /// Автоматически удалять старые бэкапы (в днях)
    #[serde(default = "default_max_age_days")]
    pub max_age_days: i64,

    /// Хранить не более N бэкапов
    #[serde(default = "default_max_backups")]
    pub max_backups: usize,

    /// Проверять целостность бэкапов при запуске
    #[serde(default = "default_check_integrity")]
    pub check_integrity: bool,

    /// Сжимать старые бэкапы (уровень сжатия 0-9)
    #[serde(default = "default_compress_old")]
    pub compress_old: Option<u8>,
}

fn default_max_age_days() -> i64 {
    30
}

fn default_max_backups() -> usize {
    10
}

fn default_check_integrity() -> bool {
    true
}

fn default_compress_old() -> Option<u8> {
    Some(9)
}

/// Глобальные настройки
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Директория для хранения бэкапов
    #[serde(default = "default_backup_dir")]
    pub backup_dir: PathBuf,

    /// Включить логирование
    #[serde(default = "default_enable_logging")]
    pub enable_logging: bool,

    /// Уровень детализации логов (error, warn, info, debug, trace)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Максимальный размер лог-файла (в мегабайтах)
    #[serde(default = "default_max_log_size")]
    pub max_log_size: u64,

    /// Сохранять ли незашифрованные бэкапы при ошибке шифрования
    #[serde(default = "default_keep_failed")]
    pub keep_failed: bool,

    /// Путь для временных файлов
    #[serde(default = "default_temp_dir")]
    pub temp_dir: PathBuf,
}

fn default_backup_dir() -> PathBuf {
    PathBuf::from("/var/backups/krybs")
}

fn default_enable_logging() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_max_log_size() -> u64 {
    100 // 100MB
}

fn default_keep_failed() -> bool {
    false
}

fn default_temp_dir() -> PathBuf {
    PathBuf::from("/tmp/krybs")
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            backup_dir: default_backup_dir(),
            enable_logging: default_enable_logging(),
            log_level: default_log_level(),
            max_log_size: default_max_log_size(),
            keep_failed: default_keep_failed(),
            temp_dir: default_temp_dir(),
        }
    }
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            max_age_days: default_max_age_days(),
            max_backups: default_max_backups(),
            check_integrity: default_check_integrity(),
            compress_old: default_compress_old(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            master_key_path: default_master_key_path(),
            delete_plain: default_delete_plain(),
            chunk_size: default_chunk_size(),
            cipher_mode: default_cipher_mode(),
            use_kdf: default_use_kdf(),
            salt_size: default_salt_size(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            crypto: CryptoConfig::default(),
            profiles: Vec::new(),
            maintenance: MaintenanceConfig::default(),
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

        // Проверка temp_dir
        if !self.core.temp_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "temp_dir must be absolute path: {}",
                self.core.temp_dir.display()
            )));
        }

        // Проверка crypto.master_key_path
        if !self.crypto.master_key_path.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "master_key_path must be absolute path: {}",
                self.crypto.master_key_path.display()
            )));
        }

        // Проверка допустимого режима шифрования
        let valid_modes = ["CBC", "CTR", "OFB", "CFB"];
        if !valid_modes.contains(&self.crypto.cipher_mode.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "Invalid cipher mode: {}. Must be one of: {:?}",
                self.crypto.cipher_mode, valid_modes
            )));
        }

        // Проверка уровня сжатия профилей
        for profile in &self.profiles {
            if profile.compression > 9 {
                return Err(ConfigError::Invalid(format!(
                    "Profile '{}' compression level must be between 0-9",
                    profile.name
                )));
            }

            if profile.paths.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "Profile '{}' has no paths defined",
                    profile.name
                )));
            }
        }

        // Проверка настроек обслуживания
        if self.maintenance.max_age_days < 0 {
            return Err(ConfigError::Invalid(
                "max_age_days cannot be negative".to_string(),
            ));
        }

        if self.maintenance.max_backups == 0 {
            return Err(ConfigError::Invalid(
                "max_backups must be greater than 0".to_string(),
            ));
        }

        if let Some(compress) = self.maintenance.compress_old {
            if compress > 9 {
                return Err(ConfigError::Invalid(
                    "compress_old level must be between 0-9".to_string(),
                ));
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
            "cipher_mode".to_string(),
            self.crypto.cipher_mode.clone(),
        );
        info.insert(
            "use_kdf".to_string(),
            self.crypto.use_kdf.to_string(),
        );
        info.insert(
            "profiles_count".to_string(),
            self.profiles.len().to_string(),
        );
        info.insert(
            "max_age_days".to_string(),
            self.maintenance.max_age_days.to_string(),
        );
        info.insert(
            "max_backups".to_string(),
            self.maintenance.max_backups.to_string(),
        );

        if !self.profiles.is_empty() {
            let profile_names: Vec<String> = self.profiles.iter().map(|p| p.name.clone()).collect();
            info.insert("profiles".to_string(), profile_names.join(", "));
        }

        info
    }

    /// Проверяет, доступен ли ключ шифрования
    pub fn encryption_available(&self) -> bool {
        self.crypto.master_key_path.exists()
    }

    /// Возвращает путь к ключу шифрования
    pub fn get_key_path(&self) -> &Path {
        &self.crypto.master_key_path
    }

    /// Получает настройки шифрования для профиля
    pub fn get_profile_encryption_settings(&self, profile_name: &str) -> (bool, u8) {
        if let Some(profile) = self.find_profile(profile_name) {
            (profile.encrypt, profile.compression)
        } else {
            (true, 6) // Значения по умолчанию
        }
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
pub fn init_config(output_path: Option<&Path>, interactive: bool, defaults: bool) -> Result<()> {
    let mut config = Config::default();

    if defaults {
        // Используем только значения по умолчанию
        config.profiles = Vec::new();
    } else {
        // Добавляем примеры профилей
        config.profiles = vec![
            Profile {
                name: "postgres".to_string(),
                paths: vec![
                    PathBuf::from("/var/lib/postgresql"),
                    PathBuf::from("/etc/postgresql"),
                ],
                exclude: vec!["*.wal".to_string()],
                encrypt: true,
                compression: 6,
            },
            Profile {
                name: "/home/docs".to_string(),
                paths: vec![PathBuf::from("/home/user/docs")],
                exclude: vec!["cache/".to_string()],
                encrypt: true,
                compression: 7,
            },
            Profile {
                name: "nginx-service".to_string(),
                paths: vec![PathBuf::from("/etc/nginx"), PathBuf::from("/var/log/nginx")],
                exclude: vec!["*.tmp".to_string(), "cache/".to_string()],
                encrypt: true,
                compression: 5,
            },
            Profile {
                name: "system-logs".to_string(),
                paths: vec![PathBuf::from("/var/log")],
                exclude: vec!["*.tmp".to_string(), "*.temp".to_string()],
                encrypt: false, // Логи обычно не требуют шифрования
                compression: 9,
            },
        ];
    }

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
    println!("  Temp directory: {}", config.core.temp_dir.display());
    println!(
        "  Master key path: {}",
        config.crypto.master_key_path.display()
    );
    println!("  Delete plaintext: {}", config.crypto.delete_plain);
    println!("  Cipher mode: {}", config.crypto.cipher_mode);
    println!("  Use KDF: {}", config.crypto.use_kdf);
    println!("  Max age days: {}", config.maintenance.max_age_days);
    println!("  Max backups: {}", config.maintenance.max_backups);
    
    if !config.profiles.is_empty() {
        println!("  Example profiles ({}):", config.profiles.len());
        for profile in &config.profiles {
            println!("    - {} ({} paths, encrypt: {}, compression: {})", 
                profile.name, profile.paths.len(), profile.encrypt, profile.compression);
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

    // Создаем директории
    if let Some(parent) = save_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Создаем директорию для ключа если нужно
    if let Some(key_parent) = config.crypto.master_key_path.parent() {
        fs::create_dir_all(key_parent)?;
    }
    
    // Создаем директорию для бэкапов
    fs::create_dir_all(&config.core.backup_dir)?;
    
    // Создаем директорию для временных файлов
    fs::create_dir_all(&config.core.temp_dir)?;

    // Сохраняем конфигурацию
    config
        .save(&save_path)
        .context("Failed to save configuration")?;

    println!("\n[SUCCESS] Configuration saved successfully!");
    println!("  Config file: {}", save_path.display());
    println!("  Backup directory: {}", config.core.backup_dir.display());
    println!("  Temp directory: {}", config.core.temp_dir.display());
    println!("\n[IMPORTANT] Next steps:");
    println!("  1. Generate encryption key: krybs keygen --output {}", 
             config.crypto.master_key_path.display());
    println!("  2. Test backup: krybs backup --profile system-logs");
    println!("  3. Check status: krybs status");
    
    if !config.profiles.is_empty() {
        println!("\nAvailable profiles:");
        for profile in &config.profiles {
            println!("  - {}: {} paths", profile.name, profile.paths.len());
        }
    }

    Ok(())
}

/// Вспомогательная функция для получения значения по ключу
pub fn get_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Проверяет существование конфигурационного файла
pub fn config_exists(path: Option<&Path>) -> bool {
    let paths = get_config_paths(path);
    paths.iter().any(|p| p.exists())
}

/// Загружает конфигурацию или создает новую с настройками по умолчанию
pub fn load_or_create(config_path: Option<&Path>) -> Result<Config> {
    match Config::load(config_path) {
        Ok(config) => Ok(config),
        Err(ConfigError::NotFound) => {
            println!("Configuration file not found. Creating default configuration...");
            let config = Config::default();
            Ok(config)
        }
        Err(e) => Err(anyhow::anyhow!("Failed to load configuration: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.core.backup_dir, PathBuf::from("/var/backups/krybs"));
        assert_eq!(config.crypto.master_key_path, PathBuf::from("/etc/krybs/master.key"));
        assert_eq!(config.crypto.cipher_mode, "CBC");
        assert!(config.crypto.use_kdf);
    }

    #[test]
    fn test_profile_for_path() {
        let profile = Profile::for_path(&PathBuf::from("/home/user"));
        assert_eq!(profile.name, "/home/user");
        assert_eq!(profile.paths.len(), 1);
        assert!(profile.encrypt);
        assert_eq!(profile.compression, 6);
    }

    #[test]
    fn test_config_validation() -> Result<()> {
        let mut config = Config::default();
        
        // Должно пройти валидацию
        config.validate()?;
        
        // Неправильный режим шифрования
        config.crypto.cipher_mode = "INVALID".to_string();
        assert!(config.validate().is_err());
        
        Ok(())
    }

    #[test]
    fn test_save_and_load() -> Result<()> {
        let temp_dir = tempdir()?;
        let config_path = temp_dir.path().join("config.toml");
        
        let mut config = Config::default();
        config.core.backup_dir = temp_dir.path().join("backups").to_path_buf();
        
        config.save(&config_path)?;
        assert!(config_path.exists());
        
        let loaded = Config::load_from_file(&config_path)?;
        assert_eq!(loaded.core.backup_dir, config.core.backup_dir);
        
        Ok(())
    }

    #[test]
    fn test_find_profile() {
        let mut config = Config::default();
        
        let profile = Profile {
            name: "test".to_string(),
            paths: vec![PathBuf::from("/test")],
            exclude: vec![],
            encrypt: true,
            compression: 6,
        };
        
        config.profiles.push(profile);
        
        assert!(config.find_profile("test").is_some());
        assert!(config.find_profile("nonexistent").is_none());
    }

    #[test]
    fn test_config_info() {
        let config = Config::default();
        let info = config.info();
        
        assert!(info.contains_key("backup_dir"));
        assert!(info.contains_key("master_key_path"));
        assert!(info.contains_key("profiles_count"));
    }

    #[test]
    fn test_encryption_available() {
        let config = Config::default();
        
        // Ключа по умолчанию нет
        assert!(!config.encryption_available());
    }

    #[test]
    fn test_get_config_paths() {
        let paths = get_config_paths(None);
        assert!(paths.len() >= 3);
        
        let custom = PathBuf::from("/custom/config.toml");
        let paths_with_custom = get_config_paths(Some(&custom));
        assert_eq!(paths_with_custom[0], custom);
    }
}