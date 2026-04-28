// src/source/postgres.rs

use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Read;
use std::process::{Command, Stdio};

use crate::source::BackupSource;

/// Источник данных для резервного копирования базы данных PostgreSQL
pub struct PostgresSource {
    name: String,
    dbname: String,
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
}

impl PostgresSource {
    /// Создаёт новый источник PostgreSQL
    pub fn new(
        dbname: String,
        host: String,
        port: u16,
        user: String,
        password: Option<String>,
    ) -> Self {
        let name = format!("postgres-{}", dbname);
        Self {
            name,
            dbname,
            host,
            port,
            user,
            password,
        }
    }

    /// Формирует аргументы командной строки для утилиты pg_dump
    fn build_pg_dump_args(&self) -> Vec<String> {
        let mut args = vec![
            "-h".to_string(),
            self.host.clone(),
            "-p".to_string(),
            self.port.to_string(),
            "-U".to_string(),
            self.user.clone(),
            "-d".to_string(),
            self.dbname.clone(),
            "--clean".to_string(),        // добавить команды DROP
            "--if-exists".to_string(),    // использовать IF EXISTS для DROP
            "--create".to_string(),       // включить CREATE DATABASE
        ];

        // Формат вывода: plain text (SQL)
        args.push("-Fp".to_string());

        args
    }
}

impl BackupSource for PostgresSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn size_hint(&self) -> Option<u64> {
        None // размер заранее не известен
    }

    fn read(&mut self) -> Result<Box<dyn Read + Send + '_>> {
        let mut cmd = Command::new("pg_dump");
        cmd.args(self.build_pg_dump_args())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Если задан пароль, передаём его через переменную окружения
        if let Some(ref pass) = self.password {
            cmd.env("PGPASSWORD", pass);
        }

        let mut child = cmd.spawn()
            .context("Не удалось запустить pg_dump")?;

        let stdout = child.stdout.take()
            .context("Не удалось получить stdout от pg_dump")?;

        // Читаем весь вывод (для простоты – полностью в память)
        let mut output = Vec::new();
        let mut reader = std::io::BufReader::new(stdout);
        reader.read_to_end(&mut output)?;

        let status = child.wait()?;
        if !status.success() {
            // Собираем stderr для диагностики
            let mut stderr = Vec::new();
            if let Some(mut err) = child.stderr {
                err.read_to_end(&mut stderr)?;
            }
            let error_msg = String::from_utf8_lossy(&stderr);
            anyhow::bail!("pg_dump завершился с ошибкой (код {}): {}", status, error_msg);
        }

        Ok(Box::new(std::io::Cursor::new(output)))
    }

    fn metadata(&self) -> Value {
        serde_json::json!({
            "type": "postgresql",
            "dbname": self.dbname,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "file_count": 1,
            "files": []
        })
    }
}