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
    pub fn new(dbname: String, host: String, port: u16, user: String, password: Option<String>) -> Self {
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
            "--clean".to_string(),     // добавить команды DROP
            "--if-exists".to_string(), // использовать IF EXISTS для DROP
            "--create".to_string(),    // включить CREATE DATABASE
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
        cmd.args(self.build_pg_dump_args()).stdout(Stdio::piped()).stderr(Stdio::piped());

        // Если задан пароль, передаём его через переменную окружения
        if let Some(ref pass) = self.password {
            cmd.env("PGPASSWORD", pass);
        }

        let child = cmd.spawn().context("Не удалось запустить pg_dump")?;

        // wait_with_output читает stdout и stderr одновременно через внутренние треды,
        // исключая дедлок при переполнении буфера stderr (~64 КБ).
        let result = child.wait_with_output().context("Не удалось дождаться завершения pg_dump")?;

        if !result.status.success() {
            let error_msg = String::from_utf8_lossy(&result.stderr);
            anyhow::bail!("pg_dump завершился с ошибкой (код {}): {}", result.status, error_msg);
        }

        Ok(Box::new(std::io::Cursor::new(result.stdout)))
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
