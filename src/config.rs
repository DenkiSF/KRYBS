use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub full_interval_days: u32,
    pub snapshot_interval_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retention {
    pub full_days: u32,
    pub snapshot_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub master_key_path: PathBuf,
    pub recovery_key_bits: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub backup_dir: PathBuf,
    pub profiles: Vec<Profile>,
    pub schedule: Schedule,
    pub retention: Retention,
    pub crypto: Crypto,
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound,
    Invalid(String),
    IoError(std::io::Error),
    ParseError(toml::de::Error),
    SerializeError(toml::ser::Error),  // Добавлен новый вариант
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound => write!(f, "Configuration file not found"),
            ConfigError::Invalid(msg) => write!(f, "Invalid configuration: {}", msg),
            ConfigError::IoError(e) => write!(f, "IO error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::SerializeError(e) => write!(f, "Serialize error: {}", e),  // Добавлен
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
        let content = fs::read_to_string(path)
            .map_err(ConfigError::IoError)?;
        
        let config: Self = toml::from_str(&content)
            .map_err(ConfigError::ParseError)?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Создаёт дефолтную конфигурацию
    pub fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        Self {
            backup_dir: PathBuf::from("/backup"),
            profiles: vec![
                Profile {
                    name: "system".to_string(),
                    paths: vec![
                        PathBuf::from("/etc"),
                        PathBuf::from("/home"),
                    ],
                    exclude: vec![
                        "/tmp".to_string(),
                        "*.log".to_string(),
                        "*.tmp".to_string(),
                    ],
                },
                Profile {
                    name: "web".to_string(),
                    paths: vec![
                        PathBuf::from("/var/www"),
                    ],
                    exclude: vec![
                        "*.tmp".to_string(),
                        "cache/*".to_string(),
                    ],
                },
            ],
            schedule: Schedule {
                full_interval_days: 60,
                snapshot_interval_hours: 24,
            },
            retention: Retention {
                full_days: 365,
                snapshot_days: 180,
            },
            crypto: Crypto {
                master_key_path: home_dir.join(".krybs/master.key"),
                recovery_key_bits: 128,
            },
        }
    }
    
    /// Валидирует конфигурацию
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Проверка backup_dir
        if !self.backup_dir.is_absolute() {
            return Err(ConfigError::Invalid(
                format!("backup_dir must be absolute path: {}", self.backup_dir.display())
            ));
        }
        
        // Проверка интервалов
        if self.schedule.full_interval_days == 0 {
            return Err(ConfigError::Invalid(
                "full_interval_days must be greater than 0".to_string()
            ));
        }
        
        if self.schedule.snapshot_interval_hours == 0 {
            return Err(ConfigError::Invalid(
                "snapshot_interval_hours must be greater than 0".to_string()
            ));
        }
        
        // Проверка политик хранения
        if self.retention.full_days == 0 {
            return Err(ConfigError::Invalid(
                "full_days must be greater than 0".to_string()
            ));
        }
        
        if self.retention.snapshot_days == 0 {
            return Err(ConfigError::Invalid(
                "snapshot_days must be greater than 0".to_string()
            ));
        }
        
        // Проверка профилей
        if self.profiles.is_empty() {
            return Err(ConfigError::Invalid(
                "At least one profile must be defined".to_string()
            ));
        }
        
        for profile in &self.profiles {
            if profile.paths.is_empty() {
                return Err(ConfigError::Invalid(
                    format!("Profile '{}' has no paths defined", profile.name)
                ));
            }
            
            // Проверяем, что все пути абсолютные
            for path in &profile.paths {
                if !path.is_absolute() {
                    return Err(ConfigError::Invalid(
                        format!("Profile '{}': path '{}' must be absolute", 
                                profile.name, path.display())
                    ));
                }
            }
        }
        
        // Проверка crypto
        if self.crypto.recovery_key_bits != 128 && 
           self.crypto.recovery_key_bits != 192 && 
           self.crypto.recovery_key_bits != 256 {
            return Err(ConfigError::Invalid(
                format!("recovery_key_bits must be 128, 192, or 256, got {}", 
                        self.crypto.recovery_key_bits)
            ));
        }
        
        Ok(())
    }
    
    /// Сохраняет конфигурацию в файл
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        // Создаём директорию если её нет
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(ConfigError::IoError)?;
        }
        
        let content = toml::to_string_pretty(self)
            .map_err(ConfigError::SerializeError)?;
        
        fs::write(path, content)
            .map_err(ConfigError::IoError)?;
        
        Ok(())
    }
    
    /// Возвращает информацию о конфигурации для команды status
    pub fn info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        
        info.insert("backup_dir".to_string(), 
                   self.backup_dir.display().to_string());
        info.insert("profiles".to_string(), 
                   self.profiles.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", "));
        info.insert("full_interval_days".to_string(), 
                   self.schedule.full_interval_days.to_string());
        info.insert("snapshot_interval_hours".to_string(), 
                   self.schedule.snapshot_interval_hours.to_string());
        info.insert("full_retention_days".to_string(), 
                   self.retention.full_days.to_string());
        info.insert("snapshot_retention_days".to_string(), 
                   self.retention.snapshot_days.to_string());
        info.insert("master_key_path".to_string(), 
                   self.crypto.master_key_path.display().to_string());
        info.insert("recovery_key_bits".to_string(), 
                   self.crypto.recovery_key_bits.to_string());
        
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

/// Инициализирует конфигурационный файл
pub fn init_config(output_path: Option<&Path>, interactive: bool, _defaults: bool) -> Result<()> {
    let config = Config::default();
    
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
    println!("  Backup directory: {}", config.backup_dir.display());
    println!("  Profiles: {}", config.profiles.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", "));
    println!("  Full backup interval: {} days", config.schedule.full_interval_days);
    println!("  Snapshot interval: {} hours", config.schedule.snapshot_interval_hours);
    println!("  Full backup retention: {} days", config.retention.full_days);
    println!("  Snapshot retention: {} days", config.retention.snapshot_days);
    println!("  Master key path: {}", config.crypto.master_key_path.display());
    println!("  Recovery key bits: {}", config.crypto.recovery_key_bits);
    
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
    
    config.save(&save_path)
        .context("Failed to save configuration")?;
    
    println!("Configuration saved successfully!");
    println!("You can edit it manually at: {}", save_path.display());
    
    Ok(())
}