use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "krybs",
    about = "KRYBS v0.1.0",
    long_about = "KRYBS v0.1.0\nAutomated backup system with GOST encryption",
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
    /// Automatic mode: full or snapshot based on schedule
    ///
    /// Example: krybs auto --profile daily --backup-dir /backups
    #[command(name = "auto")]
    Auto {
        #[command(flatten)]
        global: GlobalArgs,
    },

    /// Create manual backup
    ///
    /// Example: krybs backup /home/user/docs --exclude "*.tmp"
    #[command(name = "backup")]
    Backup {
        #[command(flatten)]
        global: GlobalArgs,
        
        /// Source paths to backup
        #[arg(required = true)]
        sources: Vec<PathBuf>,
        
        /// Exclude patterns
        #[arg(short, long)]
        exclude: Vec<String>,
        
        /// Force full backup
        #[arg(long)]
        full: bool,
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
    },

    /// Generate new encryption key
    ///
    /// Example: krybs keygen --strength 256 --output /etc/krybs/key.key
    #[command(name = "keygen")]
    Keygen {
        #[command(flatten)]
        global: GlobalArgs,
        
        /// Key strength (128, 192, 256)
        #[arg(long, default_value = "256")]
        strength: u16,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Force overwrite existing key
        #[arg(long)]
        force: bool,
    },

    /// Rotate encryption keys
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
    },
}

impl Cli {
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Auto { global: _ } => {
                println!("KRYBS {} command 'auto' called", super::VERSION);
                Ok(())
            }
            Commands::Backup { global: _, .. } => {
                println!("KRYBS {} command 'backup' called", super::VERSION);
                Ok(())
            }
            Commands::Restore { global: _, .. } => {
                println!("KRYBS {} command 'restore' called", super::VERSION);
                Ok(())
            }
            Commands::Rollback { global: _, .. } => {
                println!("KRYBS {} command 'rollback' called", super::VERSION);
                Ok(())
            }
            Commands::List { global: _, .. } => {
                println!("KRYBS {} command 'list' called", super::VERSION);
                Ok(())
            }
            Commands::Status { global, check_integrity: _ } => {
                println!("KRYBS {} command 'status' called", super::VERSION);
                
                // Пробуем загрузить конфигурацию
                match crate::config::Config::load(global.config.as_deref()) {
                    Ok(config) => {
                        if global.json {
                            // Временно закомментируем JSON вывод
                            // println!("{}", serde_json::to_string_pretty(&config.info())?);
                            println!("{{}}");  // Заглушка
                        } else {
                            println!("Configuration loaded successfully!");
                            for (key, value) in config.info() {
                                println!("  {}: {}", key, value);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Warning: Could not load configuration: {}", e);
                        println!("Using command line arguments and defaults");
                    }
                }
                
                Ok(())
            }
            Commands::Verify { global: _, .. } => {
                println!("KRYBS {} command 'verify' called", super::VERSION);
                Ok(())
            }
            Commands::Cleanup { global: _, .. } => {
                println!("KRYBS {} command 'cleanup' called", super::VERSION);
                Ok(())
            }
            Commands::Keygen { global: _, .. } => {
                println!("KRYBS {} command 'keygen' called", super::VERSION);
                Ok(())
            }
            Commands::KeyRotate { global: _, .. } => {
                println!("KRYBS {} command 'key-rotate' called", super::VERSION);
                Ok(())
            }
            Commands::InitConfig { global: _, interactive, output, defaults } => {
                println!("KRYBS {} command 'init-config' called", super::VERSION);
                crate::config::init_config(output.as_deref(), *interactive, *defaults)?;
                Ok(())
            }
        }
    }
}