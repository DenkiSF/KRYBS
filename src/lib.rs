// src/lib.rs
pub mod backup;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod logging;
pub mod storage;
pub mod source;
pub mod utils;

use anyhow::Result;
use clap::Parser;

const VERSION: &str = "v0.1.0";

/// Запускает приложение с аргументами командной строки, полученными из std::env.
pub fn run() -> Result<()> {
    let cli = cli::Cli::parse();
    run_with_cli(cli)
}

/// Запускает приложение с переданным экземпляром Cli (полезно для тестов).
pub fn run_with_cli(cli: cli::Cli) -> Result<()> {
    // Загружаем конфигурацию
    let config = config::Config::load(cli.config.as_deref()).unwrap_or_default();

    // Инициализируем логирование на основе конфигурации
    logging::init_logging(&config.core)?;

    log::info!("KRYBS {} started", VERSION);
    log::info!("Command: {:?}", cli.command);

    let result = cli.execute();

    match &result {
        Ok(_) => log::info!("Command finished successfully"),
        Err(e) => log::error!("Command failed: {}", e),
    }

    result
}