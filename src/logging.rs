// src/logging.rs

use anyhow::Result;
use log::LevelFilter;
use log4rs::{
    append::rolling_file::{
        RollingFileAppender,
        policy::compound::{CompoundPolicy, roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger},
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
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("Предупреждение: не удалось создать каталог логов: {}. Логирование отключено.", e);
            return Ok(());
        }
    }

    // Настройка ротации: триггер по размеру, roller с фиксированным окном
    let size_trigger = SizeTrigger::new(config.max_log_size * 1024 * 1024); // переводим МБ в байты
    let roller = match FixedWindowRoller::builder()
        .base(1)
        .build(&format!("{}.{{}}.gz", config.log_file.display()), config.max_log_files)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Предупреждение: не удалось настроить ротацию логов: {}. Логирование отключено.", e);
            return Ok(());
        }
    };

    let policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(roller));

    let appender = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S%.3f)} [{l}] {t}: {m}{n}")))
        .build(&config.log_file, Box::new(policy));

    let appender = match appender {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Предупреждение: не удалось инициализировать файл лога: {}. Логирование отключено.", e);
            return Ok(());
        }
    };

    let log_config = match Config::builder()
        .appender(Appender::builder().build("file", Box::new(appender)))
        .build(Root::builder().appender("file").build(level))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Предупреждение: не удалось построить конфигурацию логгера: {}. Логирование отключено.", e);
            return Ok(());
        }
    };

    if let Err(e) = log4rs::init_config(log_config) {
        eprintln!("Предупреждение: не удалось инициализировать логгер: {}. Логирование отключено.", e);
    }

    Ok(())
}
