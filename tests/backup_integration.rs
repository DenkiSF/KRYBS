// tests/backup_integration.rs
#![allow(deprecated)]
#![allow(unused_imports)]

use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn test_backup_and_list_integration() -> Result<(), Box<dyn std::error::Error>> {
    // Создаем временную директорию
    let temp_dir = assert_fs::TempDir::new()?;
    let backup_dir = temp_dir.child("backups");
    let source_dir = temp_dir.child("source");

    // Создаем исходные файлы
    source_dir.child("file1.txt").write_str("Hello, world!")?;
    source_dir.child("file2.txt").write_str("Another file")?;

    // Создаем конфиг
    let config_content = format!(
        r#"
        [core]
        backup_dir = "{}"

        [[profiles]]
        name = "test-profile"
        paths = ["{}"]
        "#,
        backup_dir.path().display(),
        source_dir.path().display()
    );

    let config_file = temp_dir.child("config.toml");
    config_file.write_str(&config_content)?;

    // Запускаем команду backup с --config ПЕРЕД командой
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args(&[
        "--config",
        config_file.path().to_str().unwrap(),
        "backup",
        "--profile",
        "test-profile",
    ]);
    cmd.assert().success();

    // Проверяем, что бэкап создан
    let backup_path = backup_dir.path();
    let entries: Vec<_> = std::fs::read_dir(backup_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
                && entry.file_name().to_string_lossy().starts_with("full-")
        })
        .collect();
    assert_eq!(entries.len(), 1, "Должен быть создан один бэкап");

    // Запускаем команду list с --config ПЕРЕД командой
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args(&[
        "--config",
        config_file.path().to_str().unwrap(),
        "list",
    ]);
    let assert = cmd.assert();
    assert.success().stdout(predicates::str::contains("full-"));

    Ok(())
}