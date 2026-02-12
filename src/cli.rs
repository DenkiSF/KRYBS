// src/cli.rs
use anyhow::{anyhow, Result};
use chrono::Duration;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "krybs",
    about = "KRYBS v0.1.0",
    long_about = "KRYBS v0.1.0\nAutomated backup system with Kuznechik encryption",
    version = "v0.1.0"
)]
pub struct Cli {
    /// Path to configuration file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Backup directory path (overrides config)
    #[arg(long = "backup-dir", global = true)]
    pub backup_dir: Option<PathBuf>,

    /// Profile name (for backup/restore)
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// JSON output format (not yet implemented)
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create backup of specified paths or profile
    ///
    /// Examples:
    ///   krybs backup /etc/nginx /var/log/nginx
    ///   krybs backup /home/user --exclude "*.tmp"
    ///   krybs backup --profile postgres --min-interval 24h
    #[command(name = "backup")]
    Backup {
        /// Source paths to backup (optional if --profile is used)
        #[arg(required_unless_present = "profile")]
        sources: Vec<PathBuf>,

        /// Exclude patterns (glob syntax)
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Compression level (0-9)
        #[arg(short = 'c', long, default_value = "6")]
        compression: u8,

        /// Skip verification after backup
        #[arg(long)]
        no_verify: bool,

        /// Minimum interval between backups for the same profile (e.g. 24h, 7d)
        #[arg(long)]
        min_interval: Option<String>,

        /// Force backup even if min-interval is not satisfied
        #[arg(short, long)]
        force: bool,
    },

    /// Restore backup to destination
    ///
    /// Example: krybs restore full-20260211-123456 /tmp/restore --progress
    #[command(name = "restore")]
    Restore {
        /// Backup identifier (e.g. full-20260211-123456)
        #[arg(required = true)]
        backup_id: String,

        /// Destination path where to restore files
        #[arg(required = true)]
        destination: PathBuf,

        /// Verify restored files (not yet implemented)
        #[arg(long)]
        verify: bool,

        /// Restore only specific path from backup
        #[arg(long)]
        path: Option<PathBuf>,

        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,

        /// Show progress bar during extraction
        #[arg(long)]
        progress: bool,
    },

    /// List available backups
    ///
    /// Example: krybs list --details --limit 10
    #[command(name = "list")]
    List {
        /// Show detailed information (checksum, profile, etc.)
        #[arg(long)]
        details: bool,

        /// Limit number of backups shown
        #[arg(short, long)]
        limit: Option<usize>,

        /// Filter backups by profile name
        #[arg(long)]
        profile_filter: Option<String>,

        /// Sort order: asc or desc (default: desc)
        #[arg(long, value_parser = ["asc", "desc"], default_value = "desc")]
        sort: String,
    },

    /// Show system status and storage information
    ///
    /// Example: krybs status --check-integrity
    #[command(name = "status")]
    Status {
        /// Check integrity of all backups (full verification)
        #[arg(long)]
        check_integrity: bool,

        /// Show detailed storage usage
        #[arg(long)]
        storage: bool,

        /// Show recent backup history
        #[arg(short = 'H', long)]
        history: bool,

        /// Show only summary (compact output)
        #[arg(short, long)]
        summary: bool,
    },

    /// Verify backup integrity
    ///
    /// Examples:
    ///   krybs verify full-20260211-123456 --quick
    ///   krybs verify --all --progress
    #[command(name = "verify")]
    Verify {
        /// Specific backup ID to verify (omit to verify all)
        backup_id: Option<String>,

        /// Quick verification (archive integrity and decryption only)
        #[arg(short, long)]
        quick: bool,

        /// Attempt to repair corrupted backups (not yet implemented)
        #[arg(long)]
        repair: bool,

        /// Verify only backups of specified profile
        #[arg(long)]
        profile_filter: Option<String>,

        /// Show progress bar during full verification
        #[arg(long)]
        progress: bool,
    },

    /// Cleanup old or corrupted backups
    ///
    /// Examples:
    ///   krybs cleanup --keep-last 7 --max-age 30d --dry-run
    ///   krybs cleanup --remove-corrupted --force
    #[command(name = "cleanup")]
    Cleanup {
        /// Keep only last N backups per profile
        #[arg(long)]
        keep_last: Option<usize>,

        /// Maximum age (e.g. 7d, 30d, 1y) – only 'd' (days) supported currently
        #[arg(long)]
        max_age: Option<String>,

        /// Dry run – show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,

        /// Cleanup only backups of specified profile
        #[arg(long)]
        profile_filter: Option<String>,

        /// Remove corrupted backups (requires verification)
        #[arg(long)]
        remove_corrupted: bool,

        /// Actually perform deletion (required for real cleanup)
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Generate new Kuznechik encryption key
    ///
    /// Example: krybs keygen --output /etc/krybs/master.key --recovery
    #[command(name = "keygen")]
    Keygen {
        /// Output file path (default: /etc/krybs/master.key)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force overwrite existing key
        #[arg(long)]
        force: bool,

        /// Also generate a recovery key (stored separately)
        #[arg(long)]
        recovery: bool,

        /// Optional comment to embed in key file
        #[arg(long)]
        comment: Option<String>,
    },

    /// Initialize configuration file with defaults or examples
    ///
    /// Example: krybs init-config --output ~/.config/krybs/config.toml --examples
    #[command(name = "init-config")]
    InitConfig {
        /// Interactive mode (ask for settings)
        #[arg(short, long)]
        interactive: bool,

        /// Output configuration file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use default values only (no example profiles)
        #[arg(long)]
        defaults: bool,

        /// Generate example profiles in config
        #[arg(long)]
        examples: bool,

        /// Explicitly set backup directory in generated config
        #[arg(long)]
        set_backup_dir: Option<PathBuf>,
    },
}

impl Cli {
    /// Main entry point: dispatch to subcommand
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Backup {
                sources,
                exclude,
                compression: _compression,
                no_verify,
                min_interval,
                force,
            } => self.cmd_backup(sources, exclude, *no_verify, min_interval, *force),

            Commands::Restore {
                backup_id,
                destination,
                verify,
                path,
                force,
                progress,
            } => self.cmd_restore(backup_id, destination, *verify, path.as_deref(), *force, *progress),

            Commands::List {
                details,
                limit,
                profile_filter,
                sort,
            } => self.cmd_list(*details, *limit, profile_filter.as_deref(), sort),

            Commands::Status {
                check_integrity,
                storage,
                history,
                summary,
            } => self.cmd_status(*check_integrity, *storage, *history, *summary),

            Commands::Verify {
                backup_id,
                quick,
                repair,
                profile_filter,
                progress,
            } => self.cmd_verify(backup_id.as_deref(), *quick, *repair, profile_filter.as_deref(), *progress),

            Commands::Cleanup {
                keep_last,
                max_age,
                dry_run,
                profile_filter,
                remove_corrupted,
                force,
            } => self.cmd_cleanup(
                *keep_last,
                max_age.as_deref(),
                *dry_run,
                profile_filter.as_deref(),
                *remove_corrupted,
                *force,
            ),

            Commands::Keygen {
                output,
                force,
                recovery,
                comment,
            } => self.cmd_keygen(output.as_deref(), *force, *recovery, comment.as_deref()),

            Commands::InitConfig {
                interactive,
                output,
                defaults,
                examples,
                set_backup_dir,
            } => self.cmd_init_config(*interactive, output.as_deref(), *defaults, *examples, set_backup_dir.as_deref()),
        }
    }

    // ------------------------------------------------------------------------
    // Command implementations
    // ------------------------------------------------------------------------

    fn cmd_backup(
        &self,
        sources: &[PathBuf],
        exclude: &[String],
        no_verify: bool,
        min_interval: &Option<String>,
        force: bool,
    ) -> Result<()> {
        println!("KRYBS {} command 'backup' called", crate::VERSION);

        // Load configuration (or defaults)
        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();

        // Determine backup directory (CLI overrides config)
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);

        // Create storage and ensure it exists
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        if !backup_dir.exists() {
            storage.init()?;
            println!("Created backup directory: {}", backup_dir.display());
        }

        // Create backup engine
        let engine = crate::backup::BackupEngine::new(storage, config)?;
        println!("[INFO] Encryption: {}", engine.encryption_status());

        // Determine paths to back up
        let paths_to_backup = if let Some(profile_name) = &self.profile {
            // Profile specified: load config again to get paths
            let config = crate::config::Config::load(self.config.as_deref())?;
            if let Some(profile) = config.find_profile(profile_name) {
                println!(
                    "Using profile '{}' with {} path(s)",
                    profile.name,
                    profile.paths.len()
                );
                profile.paths.clone()
            } else {
                eprintln!("Profile '{}' not found in config", profile_name);
                sources.to_vec()
            }
        } else {
            sources.to_vec()
        };

        if paths_to_backup.is_empty() {
            return Err(anyhow!(
                "No paths specified for backup. Use --profile or provide source paths."
            ));
        }

        // --- Backup interval check ---
        if let (Some(profile_name), Some(interval_str)) = (&self.profile, min_interval) {
            let interval = parse_duration(interval_str)
                .map_err(|_| anyhow!("Invalid duration format. Use e.g. '24h', '7d', '30m'"))?;

            match engine.check_backup_interval(profile_name, interval)? {
                Some(time_left) => {
                    let hours = time_left.num_hours();
                    let minutes = time_left.num_minutes() % 60;

                    println!(
                        "⚠️  Last backup for profile '{}' is too recent.",
                        profile_name
                    );
                    println!(
                        "   Next backup allowed in {}h {}m (minimum interval: {})",
                        hours, minutes, interval_str
                    );

                    if !force {
                        println!("   Use --force to override or wait.");
                        return Ok(());
                    } else {
                        println!("   --force detected, proceeding anyway.");
                    }
                }
                None => {
                    // Interval satisfied or no previous backup
                }
            }
        }

        // Perform the backup
        let result = tokio::runtime::Runtime::new()?.block_on(engine.create_backup(
            paths_to_backup,
            exclude.to_vec(),
            self.profile.as_deref(),
            self.verbose,
        ))?;

        println!("\n[SUCCESS] Backup created successfully!");
        println!("  Backup ID: {}", result.id);
        println!("  Profile: {}", result.profile);
        println!("  Files: {}", result.file_count);
        println!(
            "  Size: {} → {}",
            crate::storage::bytes_to_human(result.size_bytes),
            crate::storage::bytes_to_human(result.archive_size)
        );

        if result.size_bytes > 0 {
            let ratio = result.archive_size as f64 / result.size_bytes as f64;
            if result.archive_size < result.size_bytes {
                let compression = (1.0 - ratio) * 100.0;
                println!("  Compression:  +{:.1}%", compression);
            } else if result.archive_size > result.size_bytes {
                let increase = (ratio - 1.0) * 100.0;
                if result.encrypted {
                    println!("  Overhead:     {:.1}% (metadata + encryption)", increase);
                } else {
                    println!("  Overhead:     {:.1}% (metadata)", increase);
                }
            } else {
                println!("  Compression:  0.0%");
            }
        }

        println!(
            "  Encryption: {}",
            if result.encrypted {
                "✓ (Kuznechik GOST R 34.12-2015)"
            } else {
                "✗"
            }
        );
        println!("  Duration: {:.1}s", result.duration_secs);

        // Show backup location
        let storage = self.storage()?;
        println!("  Location: {}", storage.backup_path(&result.id).display());

        // Optional verification after backup (unless disabled)
        if !no_verify {
            println!("\n[INFO] Running quick verification of created backup...");
            let verify_result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(&result.id, true, false), // quick=true, progress=false
            )?;
            if verify_result.is_ok() {
                println!("[OK] Backup verified successfully.");
            } else {
                eprintln!("[WARN] Backup verification reported issues.");
            }
        }

        Ok(())
    }

    fn cmd_restore(
        &self,
        backup_id: &str,
        destination: &PathBuf,
        _verify: bool,
        path: Option<&Path>,
        force: bool,
        progress: bool,
    ) -> Result<()> {
        println!("KRYBS {} command 'restore' called", crate::VERSION);
        println!(
            "Restoring backup '{}' to '{}'",
            backup_id,
            destination.display()
        );

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        let engine = crate::backup::BackupEngine::new(storage, config)?;

        println!("[INFO] Encryption: {}", engine.encryption_status());

        tokio::runtime::Runtime::new()?.block_on(engine.restore_backup(
            backup_id,
            destination,
            path,
            force,
            progress,
        ))?;

        // Verification after restore is not yet implemented (--verify flag ignored)
        println!("[SUCCESS] Restore completed to {}", destination.display());
        Ok(())
    }

    fn cmd_list(
        &self,
        details: bool,
        limit: Option<usize>,
        profile_filter: Option<&str>,
        _sort: &str,
    ) -> Result<()> {
        println!("KRYBS {} command 'list' called", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);

        println!("Using backup directory: {}", backup_dir.display());

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        if !backup_dir.exists() {
            println!("Backup directory does not exist: {}", backup_dir.display());
            return Ok(());
        }

        match storage.list_all() {
            Ok(backups) => {
                println!("Backups ({}):", backups.len());

                let mut sorted_backups = backups;
                sorted_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

                for (i, backup) in sorted_backups.iter().enumerate() {
                    if let Some(limit) = limit {
                        if i >= limit {
                            break;
                        }
                    }

                    if let Some(filter) = profile_filter {
                        if backup.profile != filter {
                            continue;
                        }
                    }

                    self.display_backup(backup, details);
                }
            }
            Err(e) => println!("Error listing backups: {}", e),
        }

        Ok(())
    }

    fn cmd_status(
        &self,
        check_integrity: bool,
        show_storage: bool,
        history: bool,
        summary: bool,
    ) -> Result<()> {
        println!("KRYBS {} command 'status' called", crate::VERSION);

        match crate::config::Config::load(self.config.as_deref()) {
            Ok(config) => {
                if !summary {
                    println!("Configuration:");
                    println!("  Backup directory: {}", config.core.backup_dir.display());

                    let key_exists = config.crypto.master_key_path.exists();
                    println!(
                        "  Encryption: {}",
                        if key_exists {
                            format!(
                                "✓ (Kuznechik GOST R 34.12-2015)\n  Key: {}",
                                config.crypto.master_key_path.display()
                            )
                        } else {
                            "✗".to_string()
                        }
                    );
                    println!("  Profiles configured: {}", config.profiles.len());
                }

                let storage = crate::storage::BackupStorage::new(
                    &config.core.backup_dir.display().to_string(),
                );

                if show_storage || !summary {
                    match storage.get_storage_stats() {
                        Ok(stats) => {
                            println!("\nStorage status:");
                            print!("{}", stats.display());

                            if check_integrity && !summary {
                                println!("\nChecking backup integrity...");
                                self.check_storage_integrity(&storage, &config)?;
                            }
                        }
                        Err(e) => println!("Could not get storage stats: {}", e),
                    }
                }

                if history && !summary {
                    println!("\nRecent backup history:");
                    self.show_recent_history(&config)?;
                }

                if summary {
                    if let Ok(stats) = storage.get_storage_stats() {
                        println!(
                            "Backups: {}, Size: {}",
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

    fn cmd_verify(
        &self,
        backup_id: Option<&str>,
        quick: bool,
        _repair: bool,
        _profile_filter: Option<&str>,
        progress: bool,
    ) -> Result<()> {
        println!("KRYBS {} command 'verify' called", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        let engine = crate::backup::BackupEngine::new(storage.clone(), config)?;

        if let Some(id) = backup_id {
            // Verify single backup
            println!("Verifying backup: {} (quick={})", id, quick);

            let result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(id, quick, progress)
            )?;

            if result.is_ok() {
                println!("\n✅ [SUCCESS] Backup verification passed");
                if !quick {
                    println!(
                        "   Files checked: {}/{}",
                        result.files_matched, result.files_checked
                    );
                    if !result.files_missing.is_empty() {
                        println!("   ⚠️  Missing files: {}", result.files_missing.len());
                    }
                    if !result.files_corrupted.is_empty() {
                        println!("   ❌ Corrupted files: {}", result.files_corrupted.len());
                    }
                }
                Ok(())
            } else {
                println!("\n❌ [ERROR] Backup verification failed");
                for err in &result.errors {
                    println!("   - {}", err);
                }
                if !result.files_missing.is_empty() {
                    println!("\n   Missing files:");
                    for f in result.files_missing.iter().take(5) {
                        println!("     - {}", f);
                    }
                    if result.files_missing.len() > 5 {
                        println!("     ... and {} more", result.files_missing.len() - 5);
                    }
                }
                if !result.files_corrupted.is_empty() {
                    println!("\n   Corrupted files:");
                    for f in result.files_corrupted.iter().take(5) {
                        println!("     - {}", f);
                    }
                    if result.files_corrupted.len() > 5 {
                        println!("     ... and {} more", result.files_corrupted.len() - 5);
                    }
                }
                Err(anyhow!("Backup verification failed"))
            }
        } else {
            // Verify all backups
            println!("Verifying all backups...");

            let storage = self.storage()?;
            let backups = storage.list_all()?;
            let mut ok_count = 0;
            let mut error_count = 0;

            for backup in backups {
                print!("  {}... ", backup.id);
                let verify_result = tokio::runtime::Runtime::new()?.block_on(
                    engine.verify_backup(&backup.id, quick, progress)
                )?;
                if verify_result.is_ok() {
                    println!("OK");
                    ok_count += 1;
                } else {
                    println!("FAILED");
                    error_count += 1;
                }
            }

            println!("\nVerification complete:");
            println!("  Total: {}", ok_count + error_count);
            println!("  OK: {}", ok_count);
            println!("  Failed: {}", error_count);

            if error_count > 0 {
                Err(anyhow!("Some backups failed verification"))
            } else {
                Ok(())
            }
        }
    }

    fn cmd_cleanup(
        &self,
        keep_last: Option<usize>,
        max_age: Option<&str>,
        dry_run: bool,
        profile_filter: Option<&str>,
        remove_corrupted: bool,
        force: bool,
    ) -> Result<()> {
        println!("KRYBS {} command 'cleanup' called", crate::VERSION);

        if let Some(keep) = keep_last {
            println!("Keep last {} backups", keep);
        }
        if let Some(age) = max_age {
            println!("Maximum age: {}", age);
        }
        if dry_run {
            println!("[DRY RUN] No changes will be made");
        }
        if let Some(filter) = profile_filter {
            println!("Profile filter: {}", filter);
        }
        if remove_corrupted {
            println!("Will remove corrupted backups");
        }
        if force {
            println!("Force mode - no confirmation");
        }

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        let mut backups = storage.list_all()?;
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        println!("Found {} backups", backups.len());

        let mut to_keep = Vec::new();
        let mut to_delete = Vec::new();

        let filtered_backups: Vec<_> = if let Some(filter) = profile_filter {
            backups
                .into_iter()
                .filter(|b| b.profile == filter)
                .collect()
        } else {
            backups
        };
        println!("After profile filter: {} backups", filtered_backups.len());

        // Keep last N
        if let Some(keep) = keep_last {
            for (i, backup) in filtered_backups.iter().enumerate() {
                if i < keep {
                    to_keep.push(backup);
                } else {
                    to_delete.push(backup);
                }
            }
        } else {
            to_keep = filtered_backups.iter().collect();
        }

        // Max age filter
        if let Some(age_str) = max_age {
            if age_str.ends_with('d') {
                if let Ok(days) = age_str.trim_end_matches('d').parse::<i64>() {
                    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
                    for backup in &filtered_backups {
                        if backup.timestamp < cutoff {
                            if !to_delete.iter().any(|b| b.id == backup.id) {
                                to_delete.push(backup);
                            }
                        } else if !to_keep.iter().any(|b| b.id == backup.id) {
                            to_keep.push(backup);
                        }
                    }
                    println!(
                        "Max age filter: {} days (cutoff: {})",
                        days,
                        cutoff.format("%Y-%m-%d")
                    );
                }
            } else {
                println!("Warning: max-age format not supported, use '7d', '30d', etc.");
            }
        }

        // Remove corrupted backups
        if remove_corrupted {
            println!("Checking for corrupted backups...");
            let engine = crate::backup::BackupEngine::new(storage.clone(), config.clone())?;

            for backup in &filtered_backups {
                let verify_result = tokio::runtime::Runtime::new()?.block_on(
                    engine.verify_backup(&backup.id, true, false) // quick=true, progress=false
                )?;
                if !verify_result.is_ok() {
                    println!("  Backup {} is corrupted", backup.id);
                    if !to_delete.iter().any(|b| b.id == backup.id) {
                        to_delete.push(backup);
                    }
                }
            }
        }

        // Remove duplicates (a backup can't be both kept and deleted)
        to_delete.retain(|backup| !to_keep.iter().any(|b| b.id == backup.id));

        println!("\nSummary:");
        println!("  To keep: {} backups", to_keep.len());
        println!("  To delete: {} backups", to_delete.len());

        if !to_delete.is_empty() {
            if dry_run {
                println!("\n[DRY RUN] Would delete:");
                for backup in &to_delete {
                    println!(
                        "  - {} (profile: {}, date: {})",
                        backup.id,
                        backup.profile,
                        backup.timestamp.format("%Y-%m-%d")
                    );
                }
                println!(
                    "\nTotal space to free: {}",
                    crate::storage::bytes_to_human(to_delete.iter().map(|b| b.size_encrypted).sum())
                );
            } else if force {
                println!("\nDeleting backups (force mode)...");
                let mut freed_space = 0;
                for backup in &to_delete {
                    let backup_path = storage.backup_path(&backup.id);
                    if backup_path.exists() {
                        println!("  Deleting: {} (profile: {})", backup.id, backup.profile);
                        freed_space += backup.size_encrypted;
                        std::fs::remove_dir_all(&backup_path)?;
                    }
                }
                println!("\n[SUCCESS] Cleanup completed");
                println!(
                    "  Freed space: {}",
                    crate::storage::bytes_to_human(freed_space)
                );
                println!("  Remaining backups: {}", to_keep.len());
            } else {
                println!("\nBackups marked for deletion (use --force to actually delete):");
                for backup in &to_delete {
                    println!(
                        "  - {} (profile: {}, date: {}, size: {})",
                        backup.id,
                        backup.profile,
                        backup.timestamp.format("%Y-%m-%d"),
                        crate::storage::bytes_to_human(backup.size_encrypted)
                    );
                }
                println!(
                    "\nTotal space to free: {}",
                    crate::storage::bytes_to_human(to_delete.iter().map(|b| b.size_encrypted).sum())
                );
                println!("\nRun with --force to delete these backups");
            }
        } else {
            println!("\nNo backups to delete.");
        }

        Ok(())
    }

    fn cmd_keygen(
        &self,
        output: Option<&Path>,
        force: bool,
        recovery: bool,
        comment: Option<&str>,
    ) -> Result<()> {
        println!("KRYBS {} command 'keygen' called", crate::VERSION);

        let key = crate::crypto::KuznechikCipher::generate_key();

        let default_key_path = PathBuf::from("/etc/krybs/master.key");
        let output_path = output.unwrap_or(&default_key_path);

        if output_path.exists() && !force {
            return Err(anyhow!(
                "Key file already exists: {}. Use --force to overwrite",
                output_path.display()
            ));
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        crate::crypto::Crypto::save_key(&key, output_path)?;

        println!("[SUCCESS] Generated Kuznechik encryption key (256-bit)");
        println!("  Key file: {}", output_path.display());
        println!("  Key size: {} bytes (256 bits)", key.len());
        println!("  Algorithm: GOST R 34.12-2015 (Kuznechik)");

        if let Some(comment) = comment {
            println!("  Comment: {}", comment);
        }

        if recovery {
            println!("\n[IMPORTANT] Generate recovery key:");
            let recovery_key = crate::crypto::KuznechikCipher::generate_key();
            let recovery_path = output_path.with_extension("recovery.key");
            crate::crypto::Crypto::save_key(&recovery_key, &recovery_path)?;
            println!("  Recovery key: {}", recovery_path.display());
            println!("  [WARNING] Store recovery key in a secure location!");
        }

        Ok(())
    }

    fn cmd_init_config(
        &self,
        interactive: bool,
        output: Option<&Path>,
        defaults: bool,
        examples: bool,
        set_backup_dir: Option<&Path>,
    ) -> Result<()> {
        println!("KRYBS {} command 'init-config' called", crate::VERSION);

        if interactive {
            println!("Interactive mode enabled");
        }
        if let Some(dir) = set_backup_dir {
            println!("Set backup directory to: {}", dir.display());
        }
        if examples {
            println!("Will generate example profiles");
        }

        // Delegate to config module
        crate::config::init_config(output, interactive, defaults)?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Helper methods
    // ------------------------------------------------------------------------

    /// Helper to get a BackupStorage instance using current CLI/config settings
    fn storage(&self) -> Result<crate::storage::BackupStorage> {
        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self
            .backup_dir
            .as_deref()
            .unwrap_or(&config.core.backup_dir);
        Ok(crate::storage::BackupStorage::new(
            &backup_dir.display().to_string(),
        ))
    }

    /// Display a single backup entry (used by `list`)
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
                backup
                    .timestamp
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M"),
                crate::storage::bytes_to_human(backup.size_encrypted)
            );
        }
    }

    /// Check integrity of all backups (used by `status --check-integrity`)
    fn check_storage_integrity(
        &self,
        storage: &crate::storage::BackupStorage,
        config: &crate::config::Config,
    ) -> Result<()> {
        let backups = storage.list_all()?;
        let mut ok_count = 0;
        let mut error_count = 0;

        let engine = crate::backup::BackupEngine::new(storage.clone(), config.clone())?;

        for backup in backups {
            print!("  Checking {}... ", backup.id);
            let verify_result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(&backup.id, false, false) // quick=false, progress=false
            )?;
            if verify_result.is_ok() {
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

    /// Show recent backup history (used by `status --history`)
    fn show_recent_history(&self, config: &crate::config::Config) -> Result<()> {
        let storage =
            crate::storage::BackupStorage::new(&config.core.backup_dir.display().to_string());

        let backups = storage.list_all()?;
        let mut all_backups = backups;
        all_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

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

/// Parse duration string like "24h", "7d", "30m" into chrono::Duration
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(num_str) = s.strip_suffix('h') {
        let hours = num_str.parse::<i64>()?;
        Ok(Duration::hours(hours))
    } else if let Some(num_str) = s.strip_suffix('d') {
        let days = num_str.parse::<i64>()?;
        Ok(Duration::days(days))
    } else if let Some(num_str) = s.strip_suffix('m') {
        let minutes = num_str.parse::<i64>()?;
        Ok(Duration::minutes(minutes))
    } else {
        // Default to hours if no suffix
        let hours = s.parse::<i64>()?;
        Ok(Duration::hours(hours))
    }
}