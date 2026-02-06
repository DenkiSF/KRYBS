// tests/integration.rs
#![allow(deprecated)]

use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn test_cli_help() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.arg("--help");
    cmd.assert().success();
    Ok(())
}

#[test]
fn test_cli_version() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.arg("--version");
    cmd.assert().success().stdout(predicates::str::contains("v0.1.0"));
    Ok(())
}

#[test]
fn test_cli_list_no_backups() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let backup_dir = temp_dir.child("backups");

    let config_content = format!(
        r#"
        [core]
        backup_dir = "{}"
        "#,
        backup_dir.path().display()
    );

    let config_file = temp_dir.child("config.toml");
    config_file.write_str(&config_content)?;

    let mut cmd = Command::cargo_bin("krybs")?;
    // --config должен идти ПЕРЕД командой list
    cmd.args(&[
        "--config",
        config_file.path().to_str().unwrap(),
        "list",
    ]);
    cmd.assert().success().stdout(predicates::str::contains("Backup directory does not exist"));
    Ok(())
}

#[test]
fn test_cli_backup_without_config() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = assert_fs::TempDir::new()?;
    let source_dir = temp_dir.child("source");
    source_dir.child("test.txt").write_str("test content")?;

    let mut cmd = Command::cargo_bin("krybs")?;
    // Здесь нет --config, только команда backup
    cmd.args(&[
        "backup",
        "--backup-dir",
        temp_dir.path().to_str().unwrap(),
        source_dir.path().to_str().unwrap(),
    ]);
    
    // Бэкап должен создать директорию и выполниться успешно
    cmd.assert().success().stdout(predicates::str::contains("Backup completed successfully"));
    
    // Проверяем, что бэкап создан
    let entries: Vec<_> = std::fs::read_dir(temp_dir.path())?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
                && entry.file_name().to_string_lossy().starts_with("full-")
        })
        .collect();
    
    assert_eq!(entries.len(), 1, "Должен быть создан один бэкап");
    
    Ok(())
}