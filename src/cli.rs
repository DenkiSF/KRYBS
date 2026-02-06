// src/cli.rs
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "krybs",
    about = "KRYBS v0.1.0",
    long_about = "KRYBS v0.1.0\nAutomated backup system",
    version = "v0.1.0"
)]
pub struct Cli {
    /// Path to configuration file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Backup directory path
    #[arg(long = "backup-dir", global = true)]
    pub backup_dir: Option<PathBuf>,

    /// Profile name
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// JSON output format
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create backup of any paths
    ///
    /// Examples:
    ///   krybs backup /etc/nginx /var/log/nginx
    ///   krybs backup /home/user --exclude "*.tmp"
    ///   krybs backup --profile postgres  # Использовать профиль из конфига
    #[command(name = "backup")]
    Backup {
        /// Source paths to backup (optional if profile specified)
        #[arg(required_unless_present = "profile")]
        sources: Vec<PathBuf>,

        /// Exclude patterns
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Compression level (0-9)
        #[arg(short = 'c', long, default_value = "6")]
        compression: u8,

        /// Skip verification after backup
        #[arg(long)]
        no_verify: bool,
    },

    /// Restore backup to destination
    ///
    /// Example: krybs restore 2024-01-15 /home/user --verify
    #[command(name = "restore")]
    Restore {
        /// Backup identifier or date
        #[arg(required = true)]
        backup_id: String,

        /// Destination path
        #[arg(required = true)]
        destination: PathBuf,

        /// Verify restored files
        #[arg(long)]
        verify: bool,

        /// Restore specific path from backup
        #[arg(long)]
        path: Option<PathBuf>,

        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,

        /// Show progress bar
        #[arg(long)]
        progress: bool,
    },

    /// List available backups
    ///
    /// Example: krybs list --details --limit 10
    #[command(name = "list")]
    List {
        /// Show detailed information
        #[arg(long)]
        details: bool,

        /// Limit number of backups shown
        #[arg(short, long)]
        limit: Option<usize>,

        /// Filter by profile
        #[arg(long)]
        profile_filter: Option<String>,

        /// Sort by date (asc/desc)
        #[arg(long, value_parser = ["asc", "desc"], default_value = "desc")]
        sort: String,
    },

    /// Show backup system status
    ///
    /// Example: krybs status --check-integrity
    #[command(name = "status")]
    Status {
        /// Check backup integrity
        #[arg(long)]
        check_integrity: bool,

        /// Show storage usage
        #[arg(long)]
        storage: bool,

        /// Show recent backup history
        #[arg(short = 'H', long)]
        history: bool,

        /// Show only summary
        #[arg(short, long)]
        summary: bool,
    },

    /// Verify backup integrity
    ///
    /// Example: krybs verify 2024-01-15 --quick
    #[command(name = "verify")]
    Verify {
        /// Specific backup to verify (omit for all)
        backup_id: Option<String>,

        /// Quick verification (checksum only)
        #[arg(short, long)]
        quick: bool,

        /// Repair corrupted files if possible
        #[arg(long)]
        repair: bool,

        /// Verify specific profile only
        #[arg(long)]
        profile_filter: Option<String>,

        /// Show verification progress
        #[arg(long)]
        progress: bool,
    },

    /// Cleanup old backups
    ///
    /// Example: krybs cleanup --keep-last 7 --max-age 30d
    #[command(name = "cleanup")]
    Cleanup {
        /// Keep last N backups
        #[arg(long)]
        keep_last: Option<usize>,

        /// Maximum backup age (e.g., 7d, 30d, 1y)
        #[arg(long)]
        max_age: Option<String>,

        /// Dry run mode
        #[arg(long)]
        dry_run: bool,

        /// Cleanup specific profile only
        #[arg(long)]
        profile_filter: Option<String>,

        /// Remove corrupted backups
        #[arg(long)]
        remove_corrupted: bool,

        /// Force removal without confirmation
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Generate new encryption key for Kuznechik cipher
    ///
    /// Example: krybs keygen --output /etc/krybs/master.key
    #[command(name = "keygen")]
    Keygen {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force overwrite existing key
        #[arg(long)]
        force: bool,

        /// Generate recovery key
        #[arg(long)]
        recovery: bool,

        /// Key comment/description
        #[arg(long)]
        comment: Option<String>,
    },

    /// Initialize configuration file
    ///
    /// Example: krybs init-config --interactive --output /etc/krybs/config.toml
    #[command(name = "init-config")]
    InitConfig {
        /// Interactive mode
        #[arg(short, long)]
        interactive: bool,

        /// Output configuration file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Override default values
        #[arg(long)]
        defaults: bool,

        /// Generate example profiles
        #[arg(long)]
        examples: bool,

        /// Set backup directory in generated config
        #[arg(long)]
        set_backup_dir: Option<PathBuf>,
    },
}

impl Cli {
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Backup {
                sources,
                exclude,
                compression: _compression,
                no_verify: _no_verify,
            } => {
                println!("KRYBS {} command 'backup' called", crate::VERSION);

                // Загружаем конфигурацию
                let config =
                    crate::config::Config::load(self.config.as_deref()).unwrap_or_default();

                // Определяем директорию для бэкапа (CLI имеет приоритет)
                let backup_dir = self
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // Создаем хранилище
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

                // Инициализируем хранилище если нужно
                if !backup_dir.exists() {
                    storage.init()?;
                    println!("Created backup directory: {}", backup_dir.display());
                }

                // Создаем движок бэкапа
                let engine = crate::backup::BackupEngine::new(storage, config)?;

                // Выводим статус шифрования
                println!("[INFO] Encryption: {}", engine.encryption_status());

                // Если указан профиль, используем пути из конфига
                let paths_to_backup = if let Some(profile_name) = &self.profile {
                    // Находим профиль в конфиге
                    let config = crate::config::Config::load(self.config.as_deref())?;
                    if let Some(profile) = config.find_profile(profile_name) {
                        println!(
                            "Using profile '{}' with {} paths",
                            profile.name,
                            profile.paths.len()
                        );
                        profile.paths.clone()
                    } else {
                        eprintln!("Profile '{}' not found in config", profile_name);
                        sources.clone()
                    }
                } else {
                    // Используем пути из CLI
                    sources.clone()
                };

                // Проверяем, что есть пути для бэкапа
                if paths_to_backup.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No paths specified for backup. Use --profile or specify paths"
                    ));
                }

                // Выполняем бэкап
                let result = tokio::runtime::Runtime::new()?.block_on(engine.create_backup(
                    paths_to_backup,
                    exclude.clone(),
                    self.profile.as_deref(),
                    self.verbose,
                ))?;

                println!("\n[SUCCESS] Backup created successfully!");
                println!("  Backup ID: {}", result.id);
                println!("  Profile: {}", result.profile);
                println!("  Files: {}", result.file_count);
                println!("  Size: {} → {}", 
                    crate::storage::bytes_to_human(result.size_bytes),
                    crate::storage::bytes_to_human(result.archive_size)
                );
                println!("  Encryption: {}", if result.encrypted { "✓ (Kuznechik GOST R 34.12-2015)" } else { "✗" });
                println!("  Duration: {:.1}s", result.duration_secs);
                
                // Получаем путь к бэкапу через хранилище
                let storage = self.storage()?;
                println!("  Location: {}", storage.backup_path(&result.id).display());

                Ok(())
            }

            Commands::Restore {
                backup_id,
                destination,
                verify,
                path,
                force,
                progress,
            } => {
                println!("KRYBS {} command 'restore' called", crate::VERSION);
                println!(
                    "Restoring backup '{}' to '{}'",
                    backup_id,
                    destination.display()
                );

                if *verify {
                    println!("Verification enabled");
                }
                if let Some(path) = path {
                    println!("Restoring specific path: {}", path.display());
                }
                if *force {
                    println!("Force overwrite enabled");
                }
                if *progress {
                    println!("Progress display enabled");
                }

                // Загружаем конфигурацию
                let config =
                    crate::config::Config::load(self.config.as_deref()).unwrap_or_default();

                // Определяем директорию для бэкапа
                let backup_dir = self
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // Создаем хранилище и движок бэкапа
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
                let engine = crate::backup::BackupEngine::new(storage, config)?;

                // Выводим статус шифрования
                println!("[INFO] Encryption: {}", engine.encryption_status());

                // Выполняем восстановление
                tokio::runtime::Runtime::new()?.block_on(engine.restore_backup(
                    backup_id,
                    destination,
                    path.as_deref(),
                    *force,
                    *progress,
                ))?;

                // Проверяем восстановленные файлы если нужно
                if *verify {
                    println!("Verification of restored files not yet implemented");
                }

                Ok(())
            }

            Commands::List {
                details,
                limit,
                profile_filter,
                sort: _,
            } => {
                println!("KRYBS {} command 'list' called", crate::VERSION);

                // Загружаем конфигурацию (если есть)
                let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
                
                // Определяем директорию для бэкапа (CLI имеет приоритет)
                let backup_dir = self
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                println!("Using backup directory: {}", backup_dir.display());

                // Создаем хранилище
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

                // Проверяем существование директории
                if !backup_dir.exists() {
                    println!("Backup directory does not exist: {}", backup_dir.display());
                    return Ok(());
                }

                // Все бэкапы
                match storage.list_all() {
                    Ok(backups) => {
                        println!("Backups ({}):", backups.len());
                        
                        // Сортируем по времени (новые сначала)
                        let mut sorted_backups = backups;
                        sorted_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                        
                        for (i, backup) in sorted_backups.iter().enumerate() {
                            if let Some(limit) = limit {
                                if i >= *limit {
                                    break;
                                }
                            }

                            if let Some(filter_profile) = profile_filter {
                                if &backup.profile != filter_profile {
                                    continue;
                                }
                            }

                            self.display_backup(backup, *details);
                        }
                    }
                    Err(e) => println!("Error listing backups: {}", e),
                }

                Ok(())
            }
                
            Commands::Status {
                check_integrity,
                storage: show_storage,
                history,
                summary,
            } => {
                println!("KRYBS {} command 'status' called", crate::VERSION);

                // Загружаем конфигурацию
                match crate::config::Config::load(self.config.as_deref()) {
                    Ok(config) => {
                        if !*summary {
                            println!("Configuration:");
                            println!("  Backup directory: {}", config.core.backup_dir.display());
                            
                            // Проверяем наличие ключа шифрования
                            let key_exists = config.crypto.master_key_path.exists();
                            println!("  Encryption: {}", 
                                if key_exists { 
                                    format!("✓ (Kuznechik GOST R 34.12-2015)\n  Key: {}", config.crypto.master_key_path.display())
                                } else { 
                                    "✗".to_string() 
                                }
                            );
                            println!("  Profiles configured: {}", config.profiles.len());
                        }

                        // Информация о хранилище
                        if *show_storage || !*summary {
                            let storage = crate::storage::BackupStorage::new(
                                &config.core.backup_dir.display().to_string(),
                            );

                            match storage.get_storage_stats() {
                                Ok(stats) => {
                                    println!("\nStorage status:");
                                    print!("{}", stats.display());

                                    if *check_integrity && !*summary {
                                        println!("\nChecking backup integrity...");
                                        self.check_storage_integrity(&storage, &config)?;
                                    }
                                }
                                Err(e) => println!("Could not get storage stats: {}", e),
                            }
                        }

                        if *history && !*summary {
                            println!("\nRecent backup history:");
                            self.show_recent_history(&config)?;
                        }
                        
                        if *summary {
                            // Краткая сводка
                            let storage = crate::storage::BackupStorage::new(
                                &config.core.backup_dir.display().to_string(),
                            );
                            if let Ok(stats) = storage.get_storage_stats() {
                                println!("Backups: {}, Size: {}", 
                                    stats.total_backups, 
                                    crate::storage::bytes_to_human(stats.total_size)
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("Warning: Could not load configuration: {}", e);
                    }
                }

                Ok(())
            }

            Commands::Verify {
                backup_id,
                quick: _,
                repair: _,
                profile_filter: _,
                progress: _,
            } => {
                println!("KRYBS {} command 'verify' called", crate::VERSION);

                // Загружаем конфигурацию
                let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
                let backup_dir = self
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // Создаем хранилище и движок
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
                let engine = crate::backup::BackupEngine::new(storage, config)?;

                // Если указан конкретный бэкап, проверяем только его
                if let Some(backup_id) = backup_id {
                    println!("Verifying backup: {}", backup_id);
                    match tokio::runtime::Runtime::new()?.block_on(engine.verify_backup(backup_id)) {
                        Ok(true) => {
                            println!("[SUCCESS] Backup verification passed");
                            Ok(())
                        }
                        Ok(false) => {
                            println!("[ERROR] Backup verification failed");
                            Err(anyhow::anyhow!("Backup verification failed"))
                        }
                        Err(e) => {
                            println!("[ERROR] Verification error: {}", e);
                            Err(e)
                        }
                    }
                } else {
                    // Проверяем все бэкапы
                    println!("Verifying all backups...");
                    
                    let storage = self.storage()?;
                    let backups = storage.list_all()?;
                    let mut ok_count = 0;
                    let mut error_count = 0;
                    
                    for backup in backups {
                        print!("  {}... ", backup.id);
                        match tokio::runtime::Runtime::new()?.block_on(engine.verify_backup(&backup.id)) {
                            Ok(true) => {
                                println!("OK");
                                ok_count += 1;
                            }
                            Ok(false) => {
                                println!("FAILED");
                                error_count += 1;
                            }
                            Err(e) => {
                                println!("ERROR: {}", e);
                                error_count += 1;
                            }
                        }
                    }
                    
                    println!("\nVerification complete:");
                    println!("  Total: {}", ok_count + error_count);
                    println!("  OK: {}", ok_count);
                    println!("  Failed: {}", error_count);
                    
                    if error_count > 0 {
                        Err(anyhow::anyhow!("Some backups failed verification"))
                    } else {
                        Ok(())
                    }
                }
            }

            Commands::Cleanup {
                keep_last,
                max_age,
                dry_run,
                profile_filter,
                remove_corrupted,
                force,
            } => {
                println!("KRYBS {} command 'cleanup' called", crate::VERSION);

                if let Some(keep_last) = keep_last {
                    println!("Keep last {} backups", keep_last);
                }
                if let Some(max_age) = max_age {
                    println!("Maximum age: {}", max_age);
                }
                if *dry_run {
                    println!("DRY RUN - no backups will be deleted");
                }
                if let Some(profile_filter) = profile_filter {
                    println!("Profile filter: {}", profile_filter);
                }
                if *remove_corrupted {
                    println!("Will remove corrupted backups");
                }
                if *force {
                    println!("Force mode - no confirmation");
                }

                // TODO: Реализовать логику очистки
                println!("Cleanup functionality not yet implemented");
                Ok(())
            }

            Commands::Keygen {
                output,
                force,
                recovery,
                comment,
            } => {
                println!("KRYBS {} command 'keygen' called", crate::VERSION);
                
                // Генерируем ключ "Кузнечик" (256 бит = 32 байта)
                let key = crate::crypto::KuznechikCipher::generate_key();
                
                // Сохраняем в файл
                let default_key_path = PathBuf::from("/etc/krybs/master.key");
                let output_path = output.as_deref()
                    .unwrap_or(&default_key_path);
                
                if output_path.exists() && !force {
                    return Err(anyhow::anyhow!(
                        "Key file already exists: {}. Use --force to overwrite",
                        output_path.display()
                    ));
                }
                
                // Создаем директорию если нужно
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                // Сохраняем ключ
                crate::crypto::Crypto::save_key(&key, output_path)?;
                
                println!("[SUCCESS] Generated Kuznechik encryption key (256-bit)");
                println!("  Key file: {}", output_path.display());
                println!("  Key size: {} bytes (256 bits)", key.len());
                println!("  Algorithm: GOST R 34.12-2015 (Kuznechik)");
                
                if let Some(comment) = comment {
                    println!("  Comment: {}", comment);
                }
                
                if *recovery {
                    println!("\n[IMPORTANT] Generate recovery key:");
                    let recovery_key = crate::crypto::KuznechikCipher::generate_key();
                    let recovery_path = output_path.with_extension("recovery.key");
                    crate::crypto::Crypto::save_key(&recovery_key, &recovery_path)?;
                    println!("  Recovery key: {}", recovery_path.display());
                    println!("  [WARNING] Store recovery key in a secure location!");
                }
                
                Ok(())
            }

            Commands::InitConfig {
                interactive,
                output,
                defaults,
                examples,
                set_backup_dir,
            } => {
                println!("KRYBS {} command 'init-config' called", crate::VERSION);

                if *interactive {
                    println!("Interactive mode enabled");
                }
                if let Some(backup_dir) = set_backup_dir {
                    println!("Set backup directory to: {}", backup_dir.display());
                }
                if *examples {
                    println!("Will generate example profiles");
                }

                crate::config::init_config(output.as_deref(), *interactive, *defaults)?;
                Ok(())
            }
        }
    }

    /// Хелпер-метод для получения хранилища
    fn storage(&self) -> Result<crate::storage::BackupStorage> {
        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);
        
        Ok(crate::storage::BackupStorage::new(&backup_dir.display().to_string()))
    }

    /// Отображает информацию о бэкапе
    fn display_backup(&self, backup: &crate::storage::BackupInfo, details: bool) {
        let encryption_status = if backup.encrypted.unwrap_or(false) {
            "🔒"
        } else {
            "🔓"
        };

        if details {
            println!(
                "  {} [{}] {} - {} ({} files, {})",
                encryption_status,
                backup.backup_type,
                backup.id,
                backup.timestamp.format("%Y-%m-%d %H:%M:%S"),
                backup.file_count,
                crate::storage::bytes_to_human(backup.size_encrypted)
            );
            println!("    Profile: {}", backup.profile);
            if let Some(checksum) = &backup.checksum {
                println!("    Checksum: {}...", &checksum[0..16]);
            }
        } else {
            println!(
                "  {} {} {} {} ({})",
                encryption_status,
                backup.backup_type,
                backup.id,
                backup.timestamp.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
                crate::storage::bytes_to_human(backup.size_encrypted)
            );
        }
    }

    /// Проверяет целостность хранилища
    fn check_storage_integrity(
        &self,
        storage: &crate::storage::BackupStorage,
        config: &crate::config::Config,
    ) -> Result<()> {
        let backups = storage.list_all()?;
        let mut ok_count = 0;
        let mut error_count = 0;

        // Создаем движок для проверки целостности
        let engine = crate::backup::BackupEngine::new(
            storage.clone(),
            config.clone(),
        )?;

        for backup in backups {
            print!("  Checking {}... ", backup.id);
            
            let result = tokio::runtime::Runtime::new()?.block_on(engine.verify_backup(&backup.id))?;
            if result {
                println!("OK");
                ok_count += 1;
            } else {
                println!("CORRUPT");
                error_count += 1;
            }
        }

        println!(
            "\nIntegrity check complete: {} OK, {} ERROR",
            ok_count, error_count
        );
        
        if error_count > 0 {
            println!("[WARNING] Some backups are corrupted!");
        }
        
        Ok(())
    }

    /// Показывает историю бэкапов
    fn show_recent_history(&self, config: &crate::config::Config) -> Result<()> {
        let storage =
            crate::storage::BackupStorage::new(&config.core.backup_dir.display().to_string());

        let backups = storage.list_all()?;
        let mut all_backups = Vec::new();

        for backup in backups {
            all_backups.push(backup);
        }

        // Сортируем по времени (новые сначала)
        all_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Показываем последние 10
        let limit = 10.min(all_backups.len());
        for backup in all_backups.iter().take(limit) {
            let encryption_status = if backup.encrypted.unwrap_or(false) {
                "🔒"
            } else {
                "🔓"
            };

            println!(
                "  {} {} [{}] {} ({})",
                backup.timestamp.format("%Y-%m-%d %H:%M"),
                encryption_status,
                backup.backup_type,
                backup.profile,
                crate::storage::bytes_to_human(backup.size_encrypted)
            );
        }

        Ok(())
    }
}