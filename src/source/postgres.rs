// src/source/postgres.rs

use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Read;
use std::process::{Command, Stdio};

use crate::source::BackupSource;

pub struct PostgresSource {
    name: String,
    dbname: String,
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    // можем сохранить размер, если запросим отдельно
}

impl PostgresSource {
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

    /// Формирует аргументы для pg_dump
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

        // Формат: plain text (SQL)
        args.push("-Fp".to_string());

        args
    }
}

impl BackupSource for PostgresSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn size_hint(&self) -> Option<u64> {
        None // можно было бы запросить у PostgreSQL, но пока не будем
    }

    fn read(&mut self) -> Result<Box<dyn Read + Send + '_>> {
        let mut cmd = Command::new("pg_dump");
        cmd.args(self.build_pg_dump_args())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Если передан пароль, устанавливаем переменную окружения PGPASSWORD
        if let Some(ref pass) = self.password {
            cmd.env("PGPASSWORD", pass);
        }

        let mut child = cmd.spawn()
            .context("Failed to spawn pg_dump")?;

        let stdout = child.stdout.take()
            .context("Failed to get pg_dump stdout")?;

        // Нам нужно вернуть Read, но также нужно следить за завершением процесса.
        // Создадим обёртку, которая при чтении будет также проверять статус процесса.
        // Для простоты пока прочитаем всё в память (неэффективно для больших баз).
        // В реальном проекте лучше использовать каналы и потоковую передачу.
        // Временно сделаем через чтение в буфер.

        let mut output = Vec::new();
        let mut reader = std::io::BufReader::new(stdout);
        reader.read_to_end(&mut output)?;

        let status = child.wait()?;
        if !status.success() {
            // Прочитаем stderr для диагностики
            let mut stderr = Vec::new();
            if let Some(mut err) = child.stderr {
                err.read_to_end(&mut stderr)?;
            }
            let error_msg = String::from_utf8_lossy(&stderr);
            anyhow::bail!("pg_dump failed with exit code {}: {}", status, error_msg);
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