pub mod cli;
pub mod config;
pub mod storage;
pub mod backup;
pub mod snapshot;
// pub mod logger;

use anyhow::Result;
use clap::Parser;

const VERSION: &str = "v0.1.0";

pub fn run() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.execute()
}