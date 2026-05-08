// src/config.rs
use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Профиль резервного копирования – любой путь или сервис
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Имя профиля (может быть путём, например "/home/docs", или названием сервиса, например "postgres")
    pub name: String,

    /// Пути для резервного копирования (файлы, каталоги)
    pub paths: Vec<PathBuf>,

    /// Шаблоны исключений
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Использовать ли шифрование для этого профиля (по умолчанию true)
    #[serde(default = "default_encrypt")]
    pub encrypt: bool,

    /// Уровень сжатия (0-9, где 0 – без сжатия, 9 – максимальное)
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
    /// Создаёт профиль для произвольного пути
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

/// Конфигурация шифрования «Кузнечик»
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Путь к мастер-ключу шифрования «Кузнечик» (256 бит)
    #[serde(default = "default_master_key_path")]
    pub master_key_path: PathBuf,

    /// Удалять незашифрованные файлы после шифрования
    #[serde(default = "default_delete_plain")]
    pub delete_plain: bool,
}

fn default_master_key_path() -> PathBuf {
    PathBuf::from("/etc/krybs/master.key")
}

fn default_delete_plain() -> bool {
    true
}

/// Основная конфигурация
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Глобальные настройки
    #[serde(default)]
    pub core: CoreConfig,

    /// Криптография с алгоритмом «Кузнечик»
    #[serde(default)]
    pub crypto: CryptoConfig,

    /// Профили резервного копирования
    #[serde(default)]
    pub profiles: Vec<Profile>,

    /// Настройки автоматического обслуживания
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
}

/// Настройки автоматического обслуживания
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    /// Автоматически удалять резервные копии старше указанного количества дней
    #[serde(default = "default_max_age_days")]
    pub max_age_days: i64,

    /// Хранить не более указанного количества резервных копий
    #[serde(default = "default_max_backups")]
    pub max_backups: usize,

    /// Проверять целостность резервных копий при запуске
    #[serde(default = "default_check_integrity")]
    pub check_integrity: bool,

    /// Сжимать старые резервные копии (уровень сжатия 0-9)
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
    /// Каталог для хранения резервных копий
    #[serde(default = "default_backup_dir")]
    pub backup_dir: PathBuf,

    /// Включить логирование
    #[serde(default = "default_enable_logging")]
    pub enable_logging: bool,

    /// Уровень детализации логов (error, warn, info, debug, trace)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Максимальное количество файлов лога при ротации
    #[serde(default = "default_max_log_files")]
    pub max_log_files: u32,

    /// Максимальный размер одного лог-файла (в мегабайтах)
    #[serde(default = "default_max_log_size")]
    pub max_log_size: u64,

    /// Сохранять ли незашифрованные резервные копии при ошибке шифрования
    #[serde(default = "default_keep_failed")]
    pub keep_failed: bool,

    /// Каталог для временных файлов
    #[serde(default = "default_temp_dir")]
    pub temp_dir: PathBuf,

    /// Путь к файлу лога
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/krybs.log")
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
    100 // 100 МБ
}

fn default_keep_failed() -> bool {
    false
}

fn default_temp_dir() -> PathBuf {
    PathBuf::from("/tmp/krybs")
}

fn default_max_log_files() -> u32 {
    5
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            backup_dir: default_backup_dir(),
            enable_logging: default_enable_logging(),
            log_level: default_log_level(),
            max_log_files: default_max_log_files(),
            max_log_size: default_max_log_size(),
            keep_failed: default_keep_failed(),
            temp_dir: default_temp_dir(),
            log_file: default_log_file(),
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

/// Ошибки, возникающие при работе с конфигурацией
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
            ConfigError::NotFound => write!(f, "Файл конфигурации не найден"),
            ConfigError::Invalid(msg) => write!(f, "Некорректная конфигурация: {}", msg),
            ConfigError::IoError(e) => write!(f, "Ошибка ввода-вывода: {}", e),
            ConfigError::ParseError(e) => write!(f, "Ошибка разбора: {}", e),
            ConfigError::SerializeError(e) => write!(f, "Ошибка сериализации: {}", e),
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
                info!("Загрузка конфигурации из: {}", path.display());
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

    /// Выполняет проверку корректности конфигурации
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Проверка backup_dir
        if !self.core.backup_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "backup_dir должен быть абсолютным путём: {}",
                self.core.backup_dir.display()
            )));
        }

        // Проверка temp_dir
        if !self.core.temp_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "temp_dir должен быть абсолютным путём: {}",
                self.core.temp_dir.display()
            )));
        }

        // Проверка crypto.master_key_path
        if !self.crypto.master_key_path.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "master_key_path должен быть абсолютным путём: {}",
                self.crypto.master_key_path.display()
            )));
        }

        // Проверка уровня сжатия профилей
        for profile in &self.profiles {
            if profile.compression > 9 {
                return Err(ConfigError::Invalid(format!(
                    "Уровень сжатия в профиле '{}' должен быть от 0 до 9",
                    profile.name
                )));
            }

            if profile.paths.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "В профиле '{}' не указаны пути",
                    profile.name
                )));
            }
        }

        // Проверка настроек обслуживания
        if self.maintenance.max_age_days < 0 {
            return Err(ConfigError::Invalid(
                "max_age_days не может быть отрицательным".to_string(),
            ));
        }

        if self.maintenance.max_backups == 0 {
            return Err(ConfigError::Invalid(
                "max_backups должен быть больше 0".to_string(),
            ));
        }

        if let Some(compress) = self.maintenance.compress_old {
            if compress > 9 {
                return Err(ConfigError::Invalid(
                    "Уровень сжатия compress_old должен быть от 0 до 9".to_string(),
                ));
            }
        }

        if self.core.max_log_files == 0 {
            return Err(ConfigError::Invalid(
                "max_log_files должен быть больше 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Сохраняет конфигурацию в файл
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        // Создаём директорию, если её нет
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ConfigError::IoError)?;
        }

        let content = toml::to_string_pretty(self).map_err(ConfigError::SerializeError)?;

        fs::write(path, content).map_err(ConfigError::IoError)?;

        Ok(())
    }

    /// Возвращает сводку основных параметров конфигурации для команды status
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

    /// Получает настройки шифрования для указанного профиля
    pub fn get_profile_encryption_settings(&self, profile_name: &str) -> (bool, u8) {
        if let Some(profile) = self.find_profile(profile_name) {
            (profile.encrypt, profile.compression)
        } else {
            (true, 6) // значения по умолчанию
        }
    }
}

/// Возвращает список путей для поиска конфигурационного файла
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

    // 4. Текущий каталог
    paths.push(PathBuf::from("config.toml"));

    paths
}

/// Инициализирует конфигурационный файл с настройками по умолчанию или примерами
pub fn init_config(
    output_path: Option<&Path>,
    interactive: bool,
    defaults: bool,
    examples: bool,
) -> Result<()> {
    let mut config = Config::default();

    if examples && !defaults {
        // Добавляем примеры профилей только если явно запрошено и не режим defaults
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

    println!("Создание файла конфигурации: {}", save_path.display());
    println!("Параметры конфигурации:");
    println!(
        "  Каталог резервных копий: {}",
        config.core.backup_dir.display()
    );
    println!(
        "  Временный каталог:       {}",
        config.core.temp_dir.display()
    );
    println!(
        "  Путь к мастер-ключу:     {}",
        config.crypto.master_key_path.display()
    );
    println!("  Удалять открытые копии:  {}", config.crypto.delete_plain);
    println!(
        "  Макс. возраст копий:     {} дн.",
        config.maintenance.max_age_days
    );
    println!(
        "  Макс. количество копий:  {}",
        config.maintenance.max_backups
    );

    if !config.profiles.is_empty() {
        println!("  Примеры профилей ({}):", config.profiles.len());
        for profile in &config.profiles {
            println!(
                "    - {} ({} путей, шифрование: {}, сжатие: {})",
                profile.name,
                profile.paths.len(),
                profile.encrypt,
                profile.compression
            );
        }
    }

    if interactive {
        use std::io::{self, Write};

        print!("Сохранить конфигурацию? [Y/n]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "n" {
            println!("Создание конфигурации отменено");
            return Ok(());
        }
    }

    // Создаем необходимые директории
    if let Some(parent) = save_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Some(key_parent) = config.crypto.master_key_path.parent() {
        fs::create_dir_all(key_parent)?;
    }

    fs::create_dir_all(&config.core.backup_dir)?;
    fs::create_dir_all(&config.core.temp_dir)?;

    // Сохраняем конфигурацию
    config
        .save(&save_path)
        .context("Не удалось сохранить конфигурацию")?;

    println!("\n[УСПЕХ] Конфигурация успешно сохранена!");
    println!("  Файл конфигурации:          {}", save_path.display());
    println!(
        "  Каталог резервных копий:    {}",
        config.core.backup_dir.display()
    );
    println!(
        "  Временный каталог:          {}",
        config.core.temp_dir.display()
    );
    println!("\n[ВАЖНО] Дальнейшие шаги:");
    println!(
        "  1. Сгенерируйте ключ шифрования: krybs keygen --output {}",
        config.crypto.master_key_path.display()
    );
    println!("  2. Протестируйте резервное копирование: krybs backup --profile system-logs");
    println!("  3. Проверьте состояние: krybs status");

    if !config.profiles.is_empty() {
        println!("\nДоступные профили:");
        for profile in &config.profiles {
            println!("  - {}: {} путей", profile.name, profile.paths.len());
        }
    }

    Ok(())
}

/// Вспомогательная функция для получения значения переменной окружения или значения по умолчанию
pub fn get_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Проверяет существование конфигурационного файла
pub fn config_exists(path: Option<&Path>) -> bool {
    let paths = get_config_paths(path);
    paths.iter().any(|p| p.exists())
}

/// Загружает конфигурацию или создаёт новую с настройками по умолчанию
pub fn load_or_create(config_path: Option<&Path>) -> Result<Config> {
    match Config::load(config_path) {
        Ok(config) => Ok(config),
        Err(ConfigError::NotFound) => {
            println!("Файл конфигурации не найден. Используются настройки по умолчанию.");
            let config = Config::default();
            Ok(config)
        }
        Err(e) => Err(anyhow::anyhow!("Не удалось загрузить конфигурацию: {}", e)),
    }
}
