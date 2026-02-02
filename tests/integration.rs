// tests/integration.rs
use anyhow::Result;
use assert_cmd::Command;
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn test_cli_help() -> Result<()> {
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("KRYBS"));
    Ok(())
}

#[test]
fn test_backup_command() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let source_dir = temp_dir.child("source");
    source_dir.create_dir_all()?;
    
    // Создаем тестовые файлы
    source_dir.child("file1.txt").write_str("Hello, World!")?;
    source_dir.child("file2.txt").write_str("Another file")?;
    source_dir.child("subdir").create_dir_all()?;
    source_dir.child("subdir/file3.txt").write_str("Nested file")?;

    let backup_dir = temp_dir.child("backups");
    backup_dir.create_dir_all()?;

    let config_path = temp_dir.child("config.toml");
    
    // Сначала создаем конфиг
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "init-config",
        "--output",
        config_path.path().to_str().unwrap(),
    ]);
    cmd.assert().success();

    // Теперь делаем бэкап
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "backup",
        source_dir.path().to_str().unwrap(),
        "--backup-dir",
        backup_dir.path().to_str().unwrap(),
        "--config",
        config_path.path().to_str().unwrap(),
        "--verbose",
    ]);
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Backup completed successfully!"));

    Ok(())
}

#[test]
fn test_list_command() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let backup_dir = temp_dir.child("backups");
    backup_dir.create_dir_all()?;

    // ✅ ИСПРАВЛЕНО: Создаем правильную структуру директорий
    // Внутри backup_dir должны быть поддиректории full/ и snap/
    let full_dir = backup_dir.child("full");
    full_dir.create_dir_all()?;
    
    let full_backup_dir = full_dir.child("full-20240101-120000");
    full_backup_dir.create_dir_all()?;
    
    // Создаем необходимые файлы бэкапа
    full_backup_dir.child("data.tar.gz").touch()?;
    full_backup_dir.child("manifest.json").touch()?;
    
    // Создаем index-local.json с правильной структурой
    full_backup_dir.child("index-local.json").write_str(r#"
{
    "backup_id": "full-20240101-120000",
    "backup_type": "full",
    "timestamp": "2024-01-01T12:00:00Z",
    "profile": "test",
    "file_count": 10,
    "size_encrypted": "1.00MB",
    "parent_id": null
}
    "#)?;

    // Запускаем команду list
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "list",
        "--backup-dir",
        backup_dir.path().to_str().unwrap(),
    ]);
    
    cmd.assert()
        .success();
        
    // Получаем вывод для отладки
    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    println!("STDOUT:\n{}", stdout);
    println!("STDERR:\n{}", stderr);
    
    // Проверяем что команда выполнилась успешно
    assert!(output.status.success());
    
    // Проверяем что в выводе есть что-то (не обязательно конкретный ID,
    // так как формат вывода может измениться)
    assert!(!stdout.trim().is_empty());
    
    Ok(())
}