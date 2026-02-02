// tests/backup_integration.rs (новый файл)
use anyhow::Result;
use assert_cmd::Command;
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn test_backup_and_list_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // 1. Создаем тестовые данные
    let source_dir = temp_dir.child("source");
    source_dir.create_dir_all()?;
    source_dir.child("test1.txt").write_str("File 1 content")?;
    source_dir.child("test2.txt").write_str("File 2 content")?;
    
    let backup_dir = temp_dir.child("backups");
    backup_dir.create_dir_all()?;
    
    let config_path = temp_dir.child("config.toml");
    
    // 2. Создаем конфигурацию
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "init-config",
        "--output",
        config_path.path().to_str().unwrap(),
    ]);
    cmd.assert().success();
    
    // 3. Модифицируем конфигурацию чтобы использовать наш backup_dir
    let config_content = format!(
        r#"
[core]
backup_dir = "{}"

[schedule]
full_interval_days = 30
snapshot_interval_hours = 24

[retention]
full_days = 90
snapshot_days = 30

[crypto]
master_key_path = "/tmp/test.key"
delete_plain = true
chunk_size = 1048576
version = 1

[[profiles]]
name = "test-profile"
paths = ["{}"]
exclude = ["*.tmp"]
"#,
        backup_dir.path().display(),
        source_dir.path().display()
    );
    
    std::fs::write(config_path.path(), config_content)?;
    
    // 4. Выполняем бэкап
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "backup",
        source_dir.path().to_str().unwrap(),
        "--backup-dir",
        backup_dir.path().to_str().unwrap(),
        "--config",
        config_path.path().to_str().unwrap(),
        "--profile",
        "test-profile",
    ]);
    
    let output = cmd.output()?;
    println!("Backup STDOUT:\n{}", String::from_utf8_lossy(&output.stdout));
    println!("Backup STDERR:\n{}", String::from_utf8_lossy(&output.stderr));
    
    // Проверяем что бэкап выполнился
    assert!(output.status.success());
    
    // 5. Проверяем что появились файлы бэкапа
    let full_backups_dir = backup_dir.child("full");
    assert!(full_backups_dir.path().exists());
    
    // 6. Запускаем команду list
    let mut cmd = Command::cargo_bin("krybs")?;
    cmd.args([
        "list",
        "--backup-dir",
        backup_dir.path().to_str().unwrap(),
        "--config",
        config_path.path().to_str().unwrap(),
    ]);
    
    let output = cmd.output()?;
    println!("List STDOUT:\n{}", String::from_utf8_lossy(&output.stdout));
    println!("List STDERR:\n{}", String::from_utf8_lossy(&output.stderr));
    
    assert!(output.status.success());
    
    // Проверяем что в выводе есть информация о бэкапе
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Backup chains") || stdout.contains("full-"));
    
    Ok(())
}