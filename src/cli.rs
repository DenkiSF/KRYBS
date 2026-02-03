// src/cli.rs
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "krybs",
    about = "KRYBS v0.1.0",
    long_about = "KRYBS v0.1.0\nAutomated backup system",
    version = "v0.1.0"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args)]
pub struct GlobalArgs {
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
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create snapshot (incremental backup) from parent
    ///
    /// Examples:
    ///   krybs snapshot --parent full-20260115-154500
    ///   krybs snapshot --profile system --auto
    #[command(name = "snapshot")]
    Snapshot {
        #[command(flatten)]
        global: GlobalArgs,

        /// Parent backup ID
        #[arg(short, long)]
        parent: Option<String>,

        /// Auto-determine parent from last full backup
        #[arg(short, long)]
        auto: bool,

        /// Dry run mode
        #[arg(long)]
        dry_run: bool,

        /// Paths to backup (optional, uses profile paths if not specified)
        #[arg(required_unless_present_all = ["profile", "parent"])]
        sources: Vec<PathBuf>,

        /// Exclude patterns
        #[arg(short, long)]
        exclude: Vec<String>,
    },

    /// Automatic mode: full or snapshot based on schedule
    ///
    /// Examples:
    ///   krybs auto                    # Все профили из конфига
    ///   krybs auto --path /my/dir     # Произвольный путь
    ///   krybs auto --profile postgres # Конкретный профиль
    #[command(name = "auto")]
    Auto {
        #[command(flatten)]
        global: GlobalArgs,

        /// Path to backup (instead of profile)
        #[arg(long)]
        path: Option<PathBuf>,

        /// Skip full backup, only snapshots
        #[arg(long)]
        snapshot_only: bool,

        /// Force full backup
        #[arg(long)]
        force_full: bool,

        /// Run cleanup after backup
        #[arg(long)]
        cleanup: bool,
    },

    /// Create manual backup of any paths
    ///
    /// Examples:
    ///   krybs backup /etc/nginx /var/log/nginx
    ///   krybs backup /home/user --exclude "*.tmp"
    ///   krybs backup --profile postgres  # Использовать профиль из конфига
    #[command(name = "backup")]
    Backup {
        #[command(flatten)]
        global: GlobalArgs,

        /// Source paths to backup (optional if profile specified)
        #[arg(required_unless_present = "profile")]
        sources: Vec<PathBuf>,

        /// Exclude patterns
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Force full backup
        #[arg(long)]
        full: bool,

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
        #[command(flatten)]
        global: GlobalArgs,

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

    /// Rollback to previous backup version
    ///
    /// Example: krybs rollback 2024-01-14 --dry-run
    #[command(name = "rollback")]
    Rollback {
        #[command(flatten)]
        global: GlobalArgs,

        /// Target backup version
        #[arg(required = true)]
        target: String,

        /// Dry run without actual changes
        #[arg(long)]
        dry_run: bool,

        /// Create backup before rollback
        #[arg(long)]
        create_backup: bool,

        /// Rollback specific profile only
        #[arg(long)]
        profile_filter: Option<String>,
    },

    /// List available backups
    ///
    /// Example: krybs list --details --limit 10
    #[command(name = "list")]
    List {
        #[command(flatten)]
        global: GlobalArgs,

        /// Show detailed information
        #[arg(long)]
        details: bool,

        /// Limit number of backups shown
        #[arg(short, long)]
        limit: Option<usize>,

        /// Filter by profile
        #[arg(long)]
        profile_filter: Option<String>,

        /// Show only full backups
        #[arg(long)]
        full_only: bool,

        /// Show only snapshots
        #[arg(long)]
        snapshots_only: bool,

        /// Sort by date (asc/desc)
        #[arg(long, value_parser = ["asc", "desc"], default_value = "desc")]
        sort: String,
    },

    /// Show backup system status
    ///
    /// Example: krybs status --check-integrity
    #[command(name = "status")]
    Status {
        #[command(flatten)]
        global: GlobalArgs,

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
        #[command(flatten)]
        global: GlobalArgs,

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
        #[command(flatten)]
        global: GlobalArgs,

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

    /// Generate new encryption key (TEMPORARILY DISABLED)
    ///
    /// Example: krybs keygen --strength 256 --output /etc/krybs/key.key
    #[command(name = "keygen")]
    Keygen {
        #[command(flatten)]
        global: GlobalArgs,

        /// Key strength (128, 192, 256) bits for Kuznechik
        #[arg(long, default_value = "256", value_parser = ["128", "192", "256"])]
        strength: u16,

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

    /// Rotate encryption keys (TEMPORARILY DISABLED)
    ///
    /// Example: krybs key-rotate --old-key old.key --new-key new.key
    #[command(name = "key-rotate")]
    KeyRotate {
        #[command(flatten)]
        global: GlobalArgs,

        /// Path to old key file
        #[arg(long)]
        old_key: PathBuf,

        /// Path to new key file
        #[arg(long)]
        new_key: PathBuf,

        /// Re-encrypt existing backups
        #[arg(long)]
        reencrypt: bool,

        /// Keep old key for restore
        #[arg(long)]
        keep_old: bool,

        /// Rotate specific profile only
        #[arg(long)]
        profile_filter: Option<String>,

        /// Dry run mode
        #[arg(long)]
        dry_run: bool,
    },

    /// Initialize configuration file
    ///
    /// Example: krybs init-config --interactive --output /etc/krybs/config.toml
    #[command(name = "init-config")]
    InitConfig {
        #[command(flatten)]
        global: GlobalArgs,

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

    /// Decrypt encrypted backup file (TEMPORARILY DISABLED)
    #[command(name = "backup-decrypt")]
    BackupDecrypt {
        #[command(flatten)]
        global: GlobalArgs,

        /// Input encrypted file
        #[arg(required = true)]
        input: PathBuf,

        /// Output decrypted file
        #[arg(required = true)]
        output: PathBuf,

        /// Key file path (default: from config)
        #[arg(short, long)]
        key: Option<PathBuf>,
    },

    /// Verify encrypted file integrity (TEMPORARILY DISABLED)
    #[command(name = "backup-verify")]
    BackupVerify {
        #[command(flatten)]
        global: GlobalArgs,

        /// Encrypted file to verify
        #[arg(required = true)]
        file: PathBuf,

        /// Key file path (default: from config)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Verify without decryption (MAC only)
        #[arg(long)]
        mac_only: bool,
    },

    /// Encrypt file with GOST Kuznechik CTR mode (TEMPORARILY DISABLED)
    ///
    /// Example: krybs encrypt secret.txt secret.enc --key-file master.key
    #[command(name = "encrypt")]
    Encrypt {
        #[command(flatten)]
        global: GlobalArgs,

        /// Input file to encrypt
        #[arg(required = true)]
        input: PathBuf,

        /// Output encrypted file
        #[arg(required = true)]
        output: PathBuf,

        /// Key file path (default: from config)
        #[arg(long)]
        key_file: Option<PathBuf>,
    },

    /// Decrypt file with GOST Kuznechik CTR mode (TEMPORARILY DISABLED)
    ///
    /// Example: krybs decrypt secret.enc secret-decrypt.txt --key-file master.key
    #[command(name = "decrypt")]
    Decrypt {
        #[command(flatten)]
        global: GlobalArgs,

        /// Input encrypted file
        #[arg(required = true)]
        input: PathBuf,

        /// Output decrypted file
        #[arg(required = true)]
        output: PathBuf,

        /// Key file path (default: from config)
        #[arg(long)]
        key_file: Option<PathBuf>,
    },

    /// Verify encrypted file integrity (TEMPORARILY DISABLED)
    ///
    /// Example: krybs verify secret.enc --key-file master.key
    #[command(name = "verify-file")]
    VerifyFile {
        #[command(flatten)]
        global: GlobalArgs,

        /// Encrypted file to verify
        #[arg(required = true)]
        file: PathBuf,

        /// Key file path (default: from config)
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

impl Cli {
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Auto {
                global,
                path,
                snapshot_only,
                force_full,
                cleanup: _,
            } => {
                println!("KRYBS {} command 'auto' called", super::VERSION);

                // Загружаем конфигурацию
                let config =
                    crate::config::Config::load(global.config.as_deref()).unwrap_or_default();

                // Определяем директорию для бэкапа
                let backup_dir = global
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // ЗАКОММЕНТИРОВАНО: временно отключаем проверку мастер-ключа
                println!("[INFO] Encryption is temporarily disabled for testing");

                // Создаем хранилище и движок снепшотов
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
                let engine = crate::snapshot::SnapshotEngine::new(storage, config.clone());

                // Определяем профиль и пути
                if let Some(profile_name) = &global.profile {
                    // Используем профиль из конфига
                    if let Some(profile) = config.find_profile(profile_name) {
                        println!("[INFO] Auto backup for profile: {}", profile.name);

                        let result =
                            tokio::runtime::Runtime::new()?.block_on(engine.auto_backup(
                                profile,
                                profile.paths.clone(),
                                profile.exclude.clone(),
                                *force_full,
                                *snapshot_only,
                                global.verbose,
                            ))?;

                        println!("Auto backup completed: {}", result.id);
                    } else {
                        return Err(anyhow::anyhow!("Profile '{}' not found", profile_name));
                    }
                } else if let Some(path) = path {
                    // Используем указанный путь
                    println!("[INFO] Auto backup for path: {}", path.display());

                    // Создаем временный профиль
                    let temp_profile = crate::config::Profile::for_path(path);

                    let result = tokio::runtime::Runtime::new()?.block_on(engine.auto_backup(
                        &temp_profile,
                        vec![path.clone()],
                        Vec::new(),
                        *force_full,
                        *snapshot_only,
                        global.verbose,
                    ))?;

                    println!("Auto backup completed: {}", result.id);
                } else {
                    // Автоматический бэкап всех профилей
                    println!("[INFO] Auto backup for all profiles");

                    for profile in &config.profiles {
                        println!("\n--- Processing profile: {} ---", profile.name);

                        match tokio::runtime::Runtime::new()?.block_on(engine.auto_backup(
                            profile,
                            profile.paths.clone(),
                            profile.exclude.clone(),
                            *force_full,
                            *snapshot_only,
                            global.verbose,
                        )) {
                            Ok(result) => println!("  Created: {}", result.id),
                            Err(e) => println!("  Error: {}", e),
                        }
                    }

                    println!("\nAll profiles processed.");
                }

                Ok(())
            }

            Commands::Backup {
                global,
                sources,
                exclude,
                full: force_full,
                compression: _compression,
                no_verify: _no_verify,
            } => {
                println!("KRYBS {} command 'backup' called", super::VERSION);

                // Загружаем конфигурацию
                let config =
                    crate::config::Config::load(global.config.as_deref()).unwrap_or_default();

                println!("[INFO] Encryption is temporarily disabled for testing");

                // Определяем директорию для бэкапа (CLI имеет приоритет)
                let backup_dir = global
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
                let engine = crate::backup::BackupEngine::new(storage, config);

                // Если указан профиль, используем пути из конфига
                let paths_to_backup = if let Some(profile_name) = &global.profile {
                    // Находим профиль в конфиге
                    let config = crate::config::Config::load(global.config.as_deref())?;
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
                let result = tokio::runtime::Runtime::new()?.block_on(engine.create_full(
                    paths_to_backup,
                    exclude.clone(),
                    global.profile.as_deref(),
                    false, // TODO: добавить dry-run флаг
                    global.verbose,
                ))?;

                println!("Backup completed successfully!");
                println!("Backup ID: {}", result.id);

                // Проверяем целостность если не отключено
                if *force_full && !global.verbose {
                    println!("Verifying backup integrity...");
                    match tokio::runtime::Runtime::new()?.block_on(engine.verify_backup(&result.id))
                    {
                        Ok(valid) => {
                            if valid {
                                println!("✓ Backup integrity verified");
                            } else {
                                println!("⚠ Backup verification failed");
                            }
                        }
                        Err(e) => println!("⚠ Verification error: {}", e),
                    }
                }

                Ok(())
            }

            Commands::Restore {
                global,
                backup_id,
                destination,
                verify,
                path,
                force,
                progress,
            } => {
                println!("KRYBS {} command 'restore' called", super::VERSION);
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
                    crate::config::Config::load(global.config.as_deref()).unwrap_or_default();

                // Определяем директорию для бэкапа
                let backup_dir = global
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // Создаем хранилище и движок бэкапа
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
                let engine = crate::backup::BackupEngine::new(storage, config);

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

            Commands::Rollback {
                global: _,
                target,
                dry_run,
                create_backup,
                profile_filter,
            } => {
                println!("KRYBS {} command 'rollback' called", super::VERSION);
                println!("Rolling back to version: {}", target);

                if *dry_run {
                    println!("DRY RUN - no changes will be made");
                }
                if *create_backup {
                    println!("Creating backup before rollback");
                }
                if let Some(profile_filter) = profile_filter {
                    println!("Profile filter: {}", profile_filter);
                }

                Ok(())
            }

            Commands::List {
                global,
                details,
                limit,
                profile_filter,
                full_only,
                snapshots_only,
                sort: _,
            } => {
                println!("KRYBS {} command 'list' called", super::VERSION);

                // Загружаем конфигурацию (если есть)
                let config = crate::config::Config::load(global.config.as_deref()).unwrap_or_default();
                
                // ✅ ИСПРАВЛЕНО: Определяем директорию для бэкапа (CLI имеет приоритет)
                let backup_dir = global
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

                if *full_only {
                    // Только полные бэкапы
                    match storage.list_full() {
                        Ok(full_backups) => {
                            println!("Full backups ({}):", full_backups.len());
                            for (i, backup) in full_backups.iter().enumerate() {
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
                        Err(e) => println!("Error listing full backups: {}", e),
                    }
                } else if *snapshots_only {
                    // Только снепшоты
                    println!("Snapshots:");
                    match storage.list_all_chained() {
                        Ok(chains) => {
                            let mut all_snapshots = Vec::new();
                            for chain in chains.values() {
                                for backup in chain.iter().skip(1) { // Пропускаем первый (full)
                                    if let Some(filter_profile) = profile_filter {
                                        if &backup.profile != filter_profile {
                                            continue;
                                        }
                                    }
                                    all_snapshots.push(backup.clone());
                                }
                            }

                            all_snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

                            for (i, backup) in all_snapshots.iter().enumerate() {
                                if let Some(limit) = limit {
                                    if i >= *limit {
                                        break;
                                    }
                                }
                                self.display_backup(backup, *details);
                            }
                        }
                        Err(e) => println!("Error listing snapshots: {}", e),
                    }
                } else {
                    // Все бэкапы по цепочкам
                    match storage.list_all_chained() {
                        Ok(chains) => {
                            println!("Backup chains ({}):", chains.len());
                            for (chain_id, chain) in chains {
                                println!("\nChain: {}", chain_id);
                                for backup in chain {
                                    if let Some(filter_profile) = profile_filter {
                                        if &backup.profile != filter_profile {
                                            continue;
                                        }
                                    }
                                    self.display_backup(&backup, *details);
                                }
                            }
                        }
                        Err(e) => println!("Error listing backups: {}", e),
                    }
                }

                Ok(())
            }
                
            Commands::Status {
                global,
                check_integrity,
                storage: show_storage,
                history,
                summary,
            } => {
                println!("KRYBS {} command 'status' called", super::VERSION);

                // Загружаем конфигурацию
                match crate::config::Config::load(global.config.as_deref()) {
                    Ok(config) => {
                        if !*summary {
                            println!("Configuration:");
                            println!("  Backup directory: {}", config.core.backup_dir.display());
                            println!("  Encryption: ✗ (temporarily disabled for testing)");
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
                    }
                    Err(e) => {
                        println!("Warning: Could not load configuration: {}", e);
                    }
                }

                Ok(())
            }
            Commands::Snapshot {
                global,
                parent,
                auto,
                dry_run,
                sources,
                exclude,
            } => {
                println!("KRYBS {} command 'snapshot' called", super::VERSION);

                // Загружаем конфигурацию
                let config =
                    crate::config::Config::load(global.config.as_deref()).unwrap_or_default();

                println!("[INFO] Encryption is temporarily disabled for testing");

                // Определяем директорию для бэкапа
                let backup_dir = global
                    .backup_dir
                    .as_deref()
                    .unwrap_or(&config.core.backup_dir);

                // Создаем хранилище и движок снепшотов
                let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
                let engine = crate::snapshot::SnapshotEngine::new(storage, config);

                // Определяем родительский бэкап
                let parent_id = if let Some(parent) = parent {
                    parent.clone()
                } else if *auto {
                    // Автоматический поиск последнего полного бэкапа
                    if let Some(profile_name) = &global.profile {
                        let last_full = tokio::runtime::Runtime::new()?
                            .block_on(engine.get_last_full_backup(profile_name))?;

                        if let Some(last_full) = last_full {
                            println!("[INFO] Auto-selected parent: {}", last_full.id);
                            last_full.id
                        } else {
                            return Err(anyhow::anyhow!(
                                "No full backup found for profile '{}'. Create one first.",
                                profile_name
                            ));
                        }
                    } else {
                        return Err(anyhow::anyhow!(
                            "Profile required for auto mode. Use --profile or specify --parent"
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Parent backup ID required. Use --parent or --auto"
                    ));
                };

                // Определяем пути для бэкапа
                let paths_to_backup = if !sources.is_empty() {
                    sources.clone()
                } else if let Some(profile_name) = &global.profile {
                    // Используем пути из профиля
                    let config = crate::config::Config::load(global.config.as_deref())?;
                    if let Some(profile) = config.find_profile(profile_name) {
                        println!("[INFO] Using profile '{}' paths", profile.name);
                        profile.paths.clone()
                    } else {
                        return Err(anyhow::anyhow!("Profile '{}' not found", profile_name));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "No paths specified. Use --profile or specify paths"
                    ));
                };

                // Создаем снепшот
                let result = tokio::runtime::Runtime::new()?.block_on(engine.create_snapshot(
                    &parent_id,
                    paths_to_backup,
                    exclude.clone(),
                    global.profile.as_deref(),
                    *dry_run,
                    global.verbose,
                ))?;

                if result.file_count > 0 {
                    println!("Snapshot created successfully!");
                } else {
                    println!("No changes detected, snapshot skipped.");
                }

                Ok(())
            }

            Commands::Verify {
                global: _,
                backup_id,
                quick,
                repair,
                profile_filter,
                progress,
            } => {
                println!("KRYBS {} command 'verify' called", super::VERSION);

                if let Some(backup_id) = backup_id {
                    println!("Verifying backup: {}", backup_id);
                } else {
                    println!("Verifying all backups");
                }

                if *quick {
                    println!("Quick verification mode");
                }
                if *repair {
                    println!("Repair mode enabled");
                }
                if let Some(profile_filter) = profile_filter {
                    println!("Profile filter: {}", profile_filter);
                }
                if *progress {
                    println!("Progress display enabled");
                }

                Ok(())
            }

            Commands::Cleanup {
                global: _,
                keep_last,
                max_age,
                dry_run,
                profile_filter,
                remove_corrupted,
                force,
            } => {
                println!("KRYBS {} command 'cleanup' called", super::VERSION);

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

                Ok(())
            }

            Commands::Keygen {
                global: _,
                strength: _,
                output: _,
                force: _,
                recovery: _,
                comment: _,
            } => {
                println!("KRYBS {} command 'keygen' called", super::VERSION);
                println!("Key generation is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::KeyRotate {
                global: _,
                old_key: _,
                new_key: _,
                reencrypt: _,
                keep_old: _,
                profile_filter: _,
                dry_run: _,
            } => {
                println!("KRYBS {} command 'key-rotate' called", super::VERSION);
                println!("Key rotation is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::InitConfig {
                global: _,
                interactive,
                output,
                defaults,
                examples,
                set_backup_dir,
            } => {
                println!("KRYBS {} command 'init-config' called", super::VERSION);

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

            Commands::BackupDecrypt {
                global: _,
                input: _,
                output: _,
                key: _,
            } => {
                println!("KRYBS {} command 'backup-decrypt' called", super::VERSION);
                println!("Backup decryption is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::BackupVerify {
                global: _,
                file: _,
                key: _,
                mac_only: _,
            } => {
                println!("KRYBS {} command 'backup-verify' called", super::VERSION);
                println!("Backup verification is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::Encrypt {
                global: _,
                input: _,
                output: _,
                key_file: _,
            } => {
                println!("KRYBS {} command 'encrypt' called", super::VERSION);
                println!("File encryption is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::Decrypt {
                global: _,
                input: _,
                output: _,
                key_file: _,
            } => {
                println!("KRYBS {} command 'decrypt' called", super::VERSION);
                println!("File decryption is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }

            Commands::VerifyFile {
                global: _,
                file: _,
                key_file: _,
            } => {
                println!("KRYBS {} command 'verify-file' called", super::VERSION);
                println!("File verification is temporarily disabled for testing.");
                println!("Encryption features will be available in a future release.");
                Ok(())
            }
        }
    }

    /// Отображает информацию о бэкапе
    fn display_backup(&self, backup: &crate::storage::BackupInfo, details: bool) {
        let parent_info = backup.parent_id.as_deref().unwrap_or("none");

        let encryption_status = "🔓"; // Все бэкапы незашифрованы при тестировании

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
            println!("    Profile: {}, Parent: {}", backup.profile, parent_info);
        } else {
            println!(
                "  {} {} {} {} ({}) [parent: {}]",
                encryption_status,
                backup.backup_type,
                backup.id,
                backup.timestamp.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S"),
                crate::storage::bytes_to_human(backup.size_encrypted),
                parent_info
            );
        }
    }

    /// Проверяет целостность хранилища
    fn check_storage_integrity(
        &self,
        storage: &crate::storage::BackupStorage,
        _config: &crate::config::Config,
    ) -> Result<()> {
        let chains = storage.list_all_chained()?;
        let mut ok_count = 0;
        let mut error_count = 0;

        for (chain_id, chain) in chains {
            print!("  Checking chain {}... ", chain_id);
            let mut chain_ok = true;

            for backup in chain {
                let backup_path = storage.backup_path(&backup.id);

                if backup_path.join("data.tar.gz").exists() {
                    // Незашифрованный бэкап
                    if !storage.verify_backup(&backup.id)? {
                        print!("CORRUPT ");
                        chain_ok = false;
                    }
                } else {
                    print!("MISSING ");
                    chain_ok = false;
                }
            }

            if chain_ok {
                println!("OK");
                ok_count += 1;
            } else {
                println!("ERROR");
                error_count += 1;
            }
        }

        println!(
            "Integrity check complete: {} OK, {} ERROR",
            ok_count, error_count
        );
        Ok(())
    }

    /// Показывает историю бэкапов
    fn show_recent_history(&self, config: &crate::config::Config) -> Result<()> {
        let storage =
            crate::storage::BackupStorage::new(&config.core.backup_dir.display().to_string());

        let chains = storage.list_all_chained()?;
        let mut all_backups = Vec::new();

        for chain in chains.values() {
            all_backups.extend(chain.clone());
        }

        // Сортируем по времени (новые сначала)
        all_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Показываем последние 10
        let limit = 10.min(all_backups.len());
        for backup in all_backups.iter().take(limit) {
            let encryption_status = "🔓";

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