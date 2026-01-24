// src/lib.rs
pub mod backup;
pub mod cli;
pub mod config;
pub mod crypto;  // Модуль оставлен, но содержит заглушки
pub mod snapshot;
pub mod storage;

use anyhow::Result;
use clap::Parser;

const VERSION: &str = "v0.1.0";

pub fn run() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.execute()
}