// src/logging.rs

use anyhow::{Context, Result};
use log::LevelFilter;
use log4rs::{
    append::rolling_file::{
        RollingFileAppender,
        policy::compound::{
            CompoundPolicy,
            trigger::size::SizeTrigger,
            roll::fixed_window::FixedWindowRoller,
        },
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use std::path::Path;

use crate::config::CoreConfig;

/// Инициализирует глобальный логгер с ротацией на основе конфигурации.
pub fn init_logging(config: &CoreConfig) -> Result<()> {
    if !config.enable_logging {
        return Ok(());
    }

    // Определяем уровень логирования из строки
    let level = match config.log_level.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    // Создаём директорию для логов, если её нет
    if let Some(parent) = Path::new(&config.log_file).parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create log directory")?;
    }

    // Настройка ротации: триггер по размеру, roller с фиксированным окном
    let size_trigger = SizeTrigger::new(config.max_log_size * 1024 * 1024); // переводим MB в байты
    let roller = FixedWindowRoller::builder()
        .base(1)
        .build(
            &format!("{}.{{}}.gz", config.log_file.display()),
            config.max_log_files,
        )
        .context("Failed to build log roller")?;

    let policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(roller));

    let appender = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S%.3f)} [{l}] {t}: {m}{n}",
        )))
        .build(&config.log_file, Box::new(policy))
        .context("Failed to build log appender")?;

    let log_config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(appender)))
        .build(Root::builder().appender("file").build(level))
        .context("Failed to build log config")?;

    log4rs::init_config(log_config).context("Failed to initialize logger")?;

    Ok(())
}