// src/source/mod.rs

use anyhow::Result;
use serde_json::Value;
use std::io::Read;

pub mod file;
pub mod postgres;

/// Общий интерфейс для источника данных резервного копирования.
pub trait BackupSource: Send + Sync {
    /// Имя источника (для отображения в логах и метаданных).
    fn name(&self) -> &str;

    /// Оценочный размер данных в байтах (если известен).
    fn size_hint(&self) -> Option<u64>;

    /// Создаёт поток для чтения данных источника.
    /// Вызывается один раз за бэкап.
    fn read(&mut self) -> Result<Box<dyn Read + Send + '_>>;

    /// Метаданные, которые будут сохранены в манифесте.
    fn metadata(&self) -> Value;

    /// Возвращает true, если источник не содержит данных (пустой).
    fn is_empty(&self) -> bool {
        self.size_hint().unwrap_or(0) == 0
    }
}