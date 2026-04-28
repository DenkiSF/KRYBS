// src/cli.rs

use anyhow::{anyhow, Result};
use chrono::Duration;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use serde::Serialize;
use serde_json::json;
use crate::backup::BackupResult;
use crate::storage::BackupInfo;
use crate::source::BackupSource;

use log::{info, warn, error};

/// Точка входа для разбора аргументов командной строки.
#[derive(Parser)]
#[command(
    name = "krybs",
    about = "KRYBS v0.1.0 – автоматизированное резервное копирование с шифрованием Кузнечик",
    long_about = "Автоматизированная система резервного копирования с шифрованием по ГОСТ 34.12-2018 (Кузнечик) и контролем целостности на основе Стрибог (ГОСТ 34.11-2018).",
    version = "v0.1.0"
)]
pub struct Cli {
    /// Путь к файлу конфигурации
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Каталог для хранения резервных копий (переопределяет настройки конфигурации)
    #[arg(long = "backup-dir", global = true)]
    pub backup_dir: Option<PathBuf>,

    /// Имя профиля (для команд резервного копирования и восстановления)
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Подробный вывод
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Вывод в формате JSON
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Создать резервную копию указанных путей или профиля
    ///
    /// Примеры:
    ///   krybs backup /etc/nginx /var/log/nginx
    ///   krybs backup /home/user --exclude "*.tmp"
    ///   krybs backup --profile postgres --min-interval 24h
    #[command(name = "backup")]
    Backup {
        /// Исходные пути для резервного копирования (необязательно, если указан --profile)
        #[arg(required_unless_present = "profile")]
        sources: Vec<PathBuf>,

        /// Шаблоны исключений (glob)
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Уровень сжатия (0-9)
        #[arg(short = 'c', long, default_value = "6")]
        compression: u8,

        /// Пропустить проверку после создания копии
        #[arg(long)]
        no_verify: bool,

        /// Минимальный интервал между резервными копиями для одного профиля (например, 24h, 7d)
        #[arg(long)]
        min_interval: Option<String>,

        /// Принудительно выполнить, даже если интервал не выдержан
        #[arg(short, long)]
        force: bool,
    },

    /// Восстановить резервную копию в указанный каталог
    ///
    /// Пример: krybs restore full-20260211-123456 /tmp/restore --progress
    #[command(name = "restore")]
    Restore {
        /// Идентификатор резервной копии (например, full-20260211-123456)
        #[arg(required = true)]
        backup_id: String,

        /// Каталог, куда будет выполнено восстановление
        #[arg(required = true)]
        destination: PathBuf,

        /// Проверить восстановленные файлы по манифесту
        #[arg(long)]
        verify: bool,

        /// Восстановить только указанный относительный путь из резервной копии
        #[arg(long)]
        path: Option<PathBuf>,

        /// Перезаписывать существующие файлы
        #[arg(short, long)]
        force: bool,

        /// Показывать индикатор выполнения при распаковке
        #[arg(long)]
        progress: bool,

        /// Пропустить проверку целостности перед восстановлением
        #[arg(long)]
        skip_verify: bool,
    },

    /// Показать список доступных резервных копий
    ///
    /// Пример: krybs list --details --limit 10
    #[command(name = "list")]
    List {
        /// Показать подробную информацию (контрольная сумма, профиль и т.д.)
        #[arg(long)]
        details: bool,

        /// Ограничить количество выводимых записей
        #[arg(short, long)]
        limit: Option<usize>,

        /// Отфильтровать копии по имени профиля
        #[arg(long)]
        profile_filter: Option<String>,

        /// Порядок сортировки: asc (по возрастанию даты) или desc (по убыванию, по умолчанию)
        #[arg(long, value_parser = ["asc", "desc"], default_value = "desc")]
        sort: String,
    },

    /// Показать состояние системы и хранилища
    ///
    /// Пример: krybs status --check-integrity
    #[command(name = "status")]
    Status {
        /// Проверить целостность всех резервных копий (быстрая проверка)
        #[arg(long)]
        check_integrity: bool,

        /// Показать подробную информацию об использовании хранилища
        #[arg(long)]
        storage: bool,

        /// Показать историю последних операций
        #[arg(short = 'H', long)]
        history: bool,

        /// Вывести только сводку (компактный вывод)
        #[arg(short, long)]
        summary: bool,
    },

    /// Проверить целостность резервных копий
    ///
    /// Примеры:
    ///   krybs verify full-20260211-123456 --quick
    ///   krybs verify --all --progress
    #[command(name = "verify")]
    Verify {
        /// Идентификатор конкретной копии (если не указан, проверяются все)
        backup_id: Option<String>,

        /// Быстрая проверка (только структура архива и расшифровка)
        #[arg(short, long)]
        quick: bool,

        /// Попытаться восстановить повреждённые копии (пока не реализовано)
        #[arg(long)]
        repair: bool,

        /// Проверять только копии указанного профиля
        #[arg(long)]
        profile_filter: Option<String>,

        /// Показывать индикатор выполнения при полной проверке
        #[arg(long)]
        progress: bool,
    },

    /// Очистить устаревшие или повреждённые резервные копии
    ///
    /// Примеры:
    ///   krybs cleanup --keep-last 7 --max-age 30d --dry-run
    ///   krybs cleanup --remove-corrupted --force
    #[command(name = "cleanup")]
    Cleanup {
        /// Оставить только последние N копий для каждого профиля
        #[arg(long)]
        keep_last: Option<usize>,

        /// Максимальный возраст копий (например, 7d, 30d) – поддерживаются дни (d)
        #[arg(long)]
        max_age: Option<String>,

        /// Пробный прогон – показать, что будет удалено, без фактического удаления
        #[arg(long)]
        dry_run: bool,

        /// Очищать только копии указанного профиля
        #[arg(long)]
        profile_filter: Option<String>,

        /// Удалить повреждённые копии (требуется проверка целостности)
        #[arg(long)]
        remove_corrupted: bool,

        /// Фактически выполнить удаление (обязательный флаг для реальной очистки)
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Сгенерировать новый ключ шифрования Кузнечик (256 бит)
    ///
    /// Пример: krybs keygen --output /etc/krybs/master.key --recovery
    #[command(name = "keygen")]
    Keygen {
        /// Путь для сохранения ключа (по умолчанию /etc/krybs/master.key)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Перезаписать существующий ключ
        #[arg(long)]
        force: bool,

        /// Также сгенерировать ключ восстановления (сохраняется отдельно)
        #[arg(long)]
        recovery: bool,

        /// Комментарий для встраивания в ключевой файл
        #[arg(long)]
        comment: Option<String>,
    },

    /// Инициализировать конфигурационный файл с настройками по умолчанию или примерами
    ///
    /// Пример: krybs init-config --output ~/.config/krybs/config.toml --examples
    #[command(name = "init-config")]
    InitConfig {
        /// Интерактивный режим (запрос параметров)
        #[arg(short, long)]
        interactive: bool,

        /// Путь для сохранения файла конфигурации
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Использовать только значения по умолчанию (без примеров профилей)
        #[arg(long)]
        defaults: bool,

        /// Добавить примеры профилей в конфигурацию
        #[arg(long)]
        examples: bool,

        /// Явно задать каталог резервных копий в генерируемой конфигурации
        #[arg(long)]
        set_backup_dir: Option<PathBuf>,
    },

    /// Создать резервную копию базы данных PostgreSQL
    ///
    /// Пример: krybs backup-postgres --dbname mydb --user postgres
    #[command(name = "backup-postgres")]
    BackupPostgres {
        /// Имя базы данных
        #[arg(short, long)]
        dbname: String,

        /// Хост PostgreSQL (по умолчанию localhost)
        #[arg(long, default_value = "localhost")]
        host: String,

        /// Порт PostgreSQL (по умолчанию 5432)
        #[arg(long, default_value = "5432")]
        port: u16,

        /// Пользователь PostgreSQL
        #[arg(short, long)]
        user: String,

        /// Пароль (если не указан, будет использован .pgpass или переменная окружения)
        #[arg(short, long)]
        password: Option<String>,

        /// Каталог для резервной копии (переопределяет настройки конфигурации)
        #[arg(long)]
        backup_dir: Option<PathBuf>,

        /// Имя профиля для метаданных
        #[arg(long)]
        profile: Option<String>,

        /// Пропустить проверку после создания копии
        #[arg(long)]
        no_verify: bool,
    },

    /// Создать резервную копию и загрузить в S3-совместимое хранилище
    #[command(name = "backup-s3")]
    BackupS3 {
        /// Исходные пути
        sources: Vec<PathBuf>,

        /// Шаблоны исключений
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Имя бакета S3
        #[arg(long)]
        bucket: String,

        /// Регион S3 (по умолчанию us-east-1)
        #[arg(long, default_value = "us-east-1")]
        region: String,

        /// URL конечной точки (для совместимых сервисов)
        #[arg(long)]
        endpoint: Option<String>,

        /// Префикс для объектов в бакете
        #[arg(long, default_value = "")]
        prefix: String,

        /// Имя профиля
        #[arg(long)]
        profile: Option<String>,

        /// Пропустить проверку после загрузки
        #[arg(long)]
        no_verify: bool,
    },

    /// Перешифровать ключ данных (DEK) существующих копий новым мастер-ключом
    ///
    /// Пример: krybs rekey --old-key /path/to/old.key --new-key /path/to/new.key --backup-id full-20260211-123456
    #[command(name = "rekey")]
    Rekey {
        /// Путь к старому мастер-ключу
        #[arg(long)]
        old_key: PathBuf,

        /// Путь к новому мастер-ключу
        #[arg(long)]
        new_key: PathBuf,

        /// Идентификатор конкретной копии (если не указан, обрабатываются все)
        #[arg(long)]
        backup_id: Option<String>,

        /// Обрабатывать только копии указанного профиля
        #[arg(long)]
        profile: Option<String>,

        /// Пробный прогон – показать, что будет сделано, без изменений
        #[arg(long)]
        dry_run: bool,
    },
}

// ------------------------------------------------------------------------
// Исполнение команд
// ------------------------------------------------------------------------

impl Cli {
    /// Точка входа диспетчеризации подкоманд.
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Backup {
                sources,
                exclude,
                compression: _compression,
                no_verify,
                min_interval,
                force,
            } => self.cmd_backup(sources, exclude, *no_verify, min_interval, *force),

            Commands::Restore {
                backup_id,
                destination,
                verify,
                path,
                force,
                progress,
                skip_verify,
            } => self.cmd_restore(backup_id, destination, *verify, path.as_deref(), *force, *progress, *skip_verify),

            Commands::List {
                details,
                limit,
                profile_filter,
                sort,
            } => self.cmd_list(*details, *limit, profile_filter.as_deref(), sort),

            Commands::Status {
                check_integrity,
                storage,
                history,
                summary,
            } => self.cmd_status(*check_integrity, *storage, *history, *summary),

            Commands::Verify {
                backup_id,
                quick,
                repair,
                profile_filter,
                progress,
            } => self.cmd_verify(backup_id.as_deref(), *quick, *repair, profile_filter.as_deref(), *progress),

            Commands::Cleanup {
                keep_last,
                max_age,
                dry_run,
                profile_filter,
                remove_corrupted,
                force,
            } => self.cmd_cleanup(
                *keep_last,
                max_age.as_deref(),
                *dry_run,
                profile_filter.as_deref(),
                *remove_corrupted,
                *force,
            ),

            Commands::Keygen {
                output,
                force,
                recovery,
                comment,
            } => self.cmd_keygen(output.as_deref(), *force, *recovery, comment.as_deref()),

            Commands::InitConfig {
                interactive,
                output,
                defaults,
                examples,
                set_backup_dir,
            } => self.cmd_init_config(*interactive, output.as_deref(), *defaults, *examples, set_backup_dir.as_deref()),

            Commands::BackupPostgres {
                dbname,
                host,
                port,
                user,
                password,
                backup_dir,
                profile,
                no_verify,
            } => self.cmd_backup_postgres(
                dbname,
                host,
                *port,
                user,
                password.as_deref(),
                backup_dir.as_deref(),
                profile.as_deref(),
                *no_verify,
            ),

            Commands::BackupS3 {
                sources,
                exclude,
                bucket,
                region,
                endpoint,
                prefix,
                profile,
                no_verify,
            } => self.cmd_backup_s3(
                sources,
                exclude,
                bucket,
                region,
                endpoint.as_deref(),
                prefix,
                profile.as_deref(),
                *no_verify,
            ),

            Commands::Rekey {
                old_key,
                new_key,
                backup_id,
                profile,
                dry_run,
            } => self.cmd_rekey(old_key, new_key, backup_id.as_deref(), profile.as_deref(), *dry_run),
        }
    }

    // ------------------------------------------------------------------------
    // Реализации команд
    // ------------------------------------------------------------------------

    fn cmd_backup(
        &self,
        sources: &[PathBuf],
        exclude: &[String],
        no_verify: bool,
        min_interval: &Option<String>,
        force: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'backup' вызвана", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        if !backup_dir.exists() {
            storage.init()?;
            info!("Создан каталог резервных копий: {}", backup_dir.display());
        }

        let engine = crate::backup::BackupEngine::new(storage, config)?;
        info!("Шифрование: {}", engine.encryption_status());

        // Определяем список путей для копирования
        let paths_to_backup = if let Some(profile_name) = &self.profile {
            let config = crate::config::Config::load(self.config.as_deref())?;
            if let Some(profile) = config.find_profile(profile_name) {
                info!("Использую профиль '{}' с {} путями", profile.name, profile.paths.len());
                profile.paths.clone()
            } else {
                warn!("Профиль '{}' не найден в конфигурации", profile_name);
                sources.to_vec()
            }
        } else {
            sources.to_vec()
        };

        if paths_to_backup.is_empty() {
            return Err(anyhow!(
                "Не указаны пути для резервного копирования. Используйте --profile или укажите исходные пути."
            ));
        }

        // --- Проверка интервала ---
        if let (Some(profile_name), Some(interval_str)) = (&self.profile, min_interval) {
            let interval = parse_duration(interval_str)
                .map_err(|_| anyhow!("Некорректный формат длительности. Используйте, например, '24h', '7d', '30m'"))?;

            match engine.check_backup_interval(profile_name, interval)? {
                Some(time_left) => {
                    let hours = time_left.num_hours();
                    let minutes = time_left.num_minutes() % 60;
                    let msg = format!(
                        "Последняя копия профиля '{}' создана слишком недавно. Следующая будет доступна через {} ч. {} мин. (минимальный интервал: {})",
                        profile_name, hours, minutes, interval_str
                    );

                    if !force {
                        if self.json {
                            let err_json = json!({
                                "status": "error",
                                "error": "interval_check_failed",
                                "message": msg,
                                "time_left_hours": hours as f64 + minutes as f64 / 60.0,
                            });
                            println!("{}", serde_json::to_string_pretty(&err_json)?);
                        } else {
                            println!("⚠️  {}", msg);
                            println!("   Используйте --force для принудительного запуска или дождитесь интервала.");
                        }
                        return Ok(());
                    } else {
                        if !self.json {
                            println!("   Обнаружен --force, продолжаем несмотря на интервал.");
                        }
                        info!("Принудительный запуск резервного копирования, несмотря на проверку интервала.");
                    }
                }
                None => { /* интервал соблюдён */ }
            }
        }

        // Создание источника и резервной копии
        let source = match crate::source::file::FileSource::new(paths_to_backup, exclude.to_vec()) {
            Ok(src) => src,
            Err(e) => {
                error!("Не удалось создать файловый источник: {}", e);
                return Err(e);
            }
        };
        let sources_list: Vec<Box<dyn BackupSource>> = vec![Box::new(source)];

        let result = tokio::runtime::Runtime::new()?.block_on(
            engine.create_backup_from_sources(sources_list, self.profile.as_deref(), self.verbose)
        )?;

        // Вычисляем степень сжатия/накладных расходов
        let ratio = if result.size_bytes > 0 {
            result.archive_size as f64 / result.size_bytes as f64
        } else {
            0.0
        };

        // JSON-вывод
        if self.json {
            #[derive(Serialize)]
            struct BackupResponse {
                status: String,
                backup: BackupResult,
                compression_ratio: f64,
                message: String,
            }
            let response = BackupResponse {
                status: "success".to_string(),
                backup: result.clone(),
                compression_ratio: ratio,
                message: "Резервная копия успешно создана".to_string(),
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        // Человекочитаемый вывод
        println!("\n[УСПЕХ] Резервная копия создана успешно!");
        println!("  Идентификатор:       {}", result.id);
        println!("  Профиль:              {}", result.profile);
        println!("  Количество файлов:    {}", result.file_count);
        println!(
            "  Исходный размер:      {} → архив: {}",
            crate::utils::bytes_to_human(result.size_bytes),
            crate::utils::bytes_to_human(result.archive_size)
        );

        if result.size_bytes > 0 {
            if result.archive_size < result.size_bytes {
                let saved = (1.0 - ratio) * 100.0;
                println!("  Сжатие сэкономило:    {:.1}%", saved);
            } else if result.archive_size > result.size_bytes {
                let overhead = (ratio - 1.0) * 100.0;
                println!("  Накладные расходы:    {:.1}%", overhead);
            } else {
                println!("  Коэффициент сжатия:   1.0");
            }
        }

        println!(
            "  Шифрование:           {}",
            if result.encrypted { "✓ (Кузнечик ГОСТ 34.12-2018)" } else { "✗" }
        );
        println!("  Длительность:         {:.1} с", result.duration_secs);

        let storage = self.storage()?;
        println!("  Размещение:           {}", storage.backup_path(&result.id).display());

        // Дополнительная верификация после создания (если не отключена)
        if !no_verify {
            println!("\n[ИНФО] Выполняю быструю проверку созданной резервной копии...");
            info!("Проверка копии {} после создания", result.id);
            let verify_result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(&result.id, true, false),
            )?;
            if verify_result.is_ok() {
                println!("[OK] Резервная копия успешно проверена.");
                info!("Копия {} успешно проверена", result.id);
            } else {
                warn!("Проверка резервной копии выявила проблемы.");
                eprintln!("[ПРЕДУПРЕЖДЕНИЕ] Проверка копии завершилась с ошибками.");
            }
        }

        Ok(())
    }

    fn cmd_rekey(
        &self,
        old_key_path: &Path,
        new_key_path: &Path,
        backup_id: Option<&str>,
        profile: Option<&str>,
        dry_run: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'rekey' вызвана", crate::VERSION);

        let old_key = *crate::crypto::Crypto::load_key(old_key_path)?;
        let new_key = *crate::crypto::Crypto::load_key(new_key_path)?;

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        let backups = if let Some(id) = backup_id {
            let info = storage.read_backup_info(id)?;
            vec![info]
        } else {
            let mut all = storage.list_all()?;
            if let Some(prof) = profile {
                all.retain(|b| b.profile == prof);
            }
            all
        };

        if backups.is_empty() {
            println!("Нет резервных копий для обработки.");
            return Ok(());
        }

        println!("Найдено копий для обработки: {}.", backups.len());
        let mut ok_count = 0;
        let mut skipped_count = 0;
        let mut error_count = 0;

        for backup in backups {
            let backup_path = storage.backup_path(&backup.id);
            let encrypted_archive = backup_path.join("data.tar.gz.enc");
            if !encrypted_archive.exists() {
                println!("  Копия {}: зашифрованный архив не найден (возможно, не шифрована), пропускаю.", backup.id);
                skipped_count += 1;
                continue;
            }

            let is_wrapped = match crate::crypto::WrappedKuznechik::is_wrapped(&encrypted_archive) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("  Копия {}: ошибка определения формата - {}", backup.id, e);
                    error_count += 1;
                    continue;
                }
            };

            if !is_wrapped {
                println!("  Копия {}: старый формат (прямое шифрование), пропускаю. Пересоздайте копию для конвертации.", backup.id);
                skipped_count += 1;
                continue;
            }

            if dry_run {
                println!("  [ПРОБНЫЙ ПРОГОН] Будет перешифрована копия: {}", backup.id);
                ok_count += 1;
                continue;
            }

            println!("  Перешифровываю копию: {} ...", backup.id);
            match crate::crypto::Crypto::rekey_backup(&encrypted_archive, &old_key, &new_key) {
                Ok(()) => {
                    println!("    ✓ Успешно");
                    ok_count += 1;
                }
                Err(e) => {
                    eprintln!("    ✗ Ошибка: {}", e);
                    error_count += 1;
                }
            }
        }

        println!("\nИтого:");
        println!("  Успешно перешифровано: {}", ok_count);
        println!("  Пропущено:             {}", skipped_count);
        println!("  Ошибок:                {}", error_count);

        if error_count > 0 {
            Err(anyhow::anyhow!("Перешифрование завершено с ошибками"))
        } else {
            Ok(())
        }
    }

    fn cmd_backup_postgres(
        &self,
        dbname: &str,
        host: &str,
        port: u16,
        user: &str,
        password: Option<&str>,
        backup_dir: Option<&Path>,
        profile_name: Option<&str>,
        no_verify: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'backup-postgres' вызвана", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = backup_dir
            .or(self.backup_dir.as_deref())
            .unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        if !backup_dir.exists() {
            storage.init()?;
            info!("Создан каталог резервных копий: {}", backup_dir.display());
        }

        let engine = crate::backup::BackupEngine::new(storage, config)?;
        info!("Шифрование: {}", engine.encryption_status());

        let source = crate::source::postgres::PostgresSource::new(
            dbname.to_string(),
            host.to_string(),
            port,
            user.to_string(),
            password.map(|s| s.to_string()),
        );
        let sources: Vec<Box<dyn BackupSource>> = vec![Box::new(source)];

        let result = tokio::runtime::Runtime::new()?.block_on(
            engine.create_backup_from_sources(sources, profile_name, self.verbose)
        )?;

        println!("\n[УСПЕХ] Резервная копия PostgreSQL создана успешно!");
        println!("  Идентификатор: {}", result.id);
        println!("  База данных:   {}", dbname);
        println!("  Профиль:       {}", result.profile);
        println!("  Размер:        {}", crate::utils::bytes_to_human(result.archive_size));

        if !no_verify {
            println!("\n[ИНФО] Выполняю быструю проверку созданной копии...");
            info!("Проверка копии {} после создания", result.id);
            let verify_result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(&result.id, true, false)
            )?;
            if verify_result.is_ok() {
                println!("[OK] Резервная копия успешно проверена.");
            } else {
                warn!("Проверка резервной копии выявила проблемы.");
                eprintln!("[ПРЕДУПРЕЖДЕНИЕ] Проверка завершилась с ошибками.");
            }
        }

        Ok(())
    }

    fn cmd_backup_s3(
        &self,
        sources: &[PathBuf],
        exclude: &[String],
        bucket: &str,
        region: &str,
        endpoint: Option<&str>,
        prefix: &str,
        profile_name: Option<&str>,
        _no_verify: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'backup-s3' вызвана", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();

        let temp_dir = tempfile::tempdir()?;
        let temp_backup_dir = temp_dir.path().join("backup");
        std::fs::create_dir_all(&temp_backup_dir)?;

        let storage = crate::storage::BackupStorage::new(temp_backup_dir.to_str().unwrap());
        storage.init()?;

        let engine = crate::backup::BackupEngine::new(storage, config)?;

        let file_source = crate::source::file::FileSource::new(sources.to_vec(), exclude.to_vec())?;
        let all_sources: Vec<Box<dyn BackupSource>> = vec![Box::new(file_source)];

        let result = tokio::runtime::Runtime::new()?.block_on(
            engine.create_backup_from_sources(all_sources, profile_name, self.verbose)
        )?;

        let backup_path = temp_backup_dir.join(&result.id);

        println!("Подключение к S3...");
        let uploader = tokio::runtime::Runtime::new()?.block_on(
            crate::storage::s3_uploader::S3Uploader::new(bucket, region, endpoint)
        )?;

        println!("Загрузка резервной копии в s3://{}/{}{}", bucket, prefix, result.id);
        uploader.upload_backup(&result.id, &backup_path, prefix)?;

        if self.json {
            let response = serde_json::json!({
                "status": "success",
                "backup_id": result.id,
                "profile": result.profile,
                "files": result.file_count,
                "size": result.archive_size,
                "size_human": crate::utils::bytes_to_human(result.archive_size),
                "s3_location": format!("s3://{}/{}{}/", bucket, prefix, result.id),
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
        } else {
            println!("\n[УСПЕХ] Резервная копия загружена в S3 успешно!");
            println!("  Идентификатор:        {}", result.id);
            println!("  Профиль:               {}", result.profile);
            println!("  Файлов:                {}", result.file_count);
            println!("  Размер:                {}", crate::utils::bytes_to_human(result.archive_size));
            println!("  Размещение S3:         s3://{}/{}{}/", bucket, prefix, result.id);
        }

        Ok(())
    }

    fn cmd_restore(
        &self,
        backup_id: &str,
        destination: &PathBuf,
        verify: bool,
        path: Option<&Path>,
        force: bool,
        progress: bool,
        skip_verify: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'restore' вызвана", crate::VERSION);
        println!("Восстановление копии '{}' в '{}'", backup_id, destination.display());

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);

        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        let engine = crate::backup::BackupEngine::new(storage, config)?;

        info!("Шифрование: {}", engine.encryption_status());

        // Проверка целостности перед восстановлением (если не отключена)
        if !skip_verify {
            println!("[ИНФО] Быстрая проверка целостности перед восстановлением...");
            info!("Проверка копии {} перед восстановлением", backup_id);

            let verify_result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(backup_id, true, false)
            )?;

            if !verify_result.is_ok() {
                error!("Проверка целостности не пройдена для {}", backup_id);
                eprintln!("[ОШИБКА] Проверка целостности не пройдена. Восстановление отменено.");
                for err in &verify_result.errors {
                    eprintln!("  - {}", err);
                }
                return Err(anyhow::anyhow!("Проверка резервной копии не пройдена"));
            }

            println!("[OK] Проверка целостности пройдена.");
            info!("Копия {} успешно проверена", backup_id);
        } else {
            println!("[ИНФО] Проверка целостности пропущена по запросу.");
            warn!("Проверка целостности пропущена пользователем для {}", backup_id);
        }

        // Выполнение восстановления
        tokio::runtime::Runtime::new()?.block_on(
            engine.restore_backup(backup_id, destination, path, force, progress)
        )?;

        println!("[УСПЕХ] Восстановление завершено в {}", destination.display());
        info!("Восстановление завершено для копии {}", backup_id);

        // Дополнительная верификация восстановленных файлов
        if verify {
            println!("\n[ИНФО] Проверка восстановленных файлов по манифесту...");
            match engine.verify_restored(backup_id, destination) {
                Ok(verify_result) => {
                    if verify_result.is_ok() {
                        println!("[OK] Все файлы успешно проверены ({} совпадений).", verify_result.files_matched);
                    } else {
                        println!("[ПРЕДУПРЕЖДЕНИЕ] Проверка выявила расхождения:");
                        if !verify_result.files_missing.is_empty() {
                            println!("  Отсутствует файлов: {}", verify_result.files_missing.len());
                            for f in verify_result.files_missing.iter().take(5) {
                                println!("    - {}", f);
                            }
                            if verify_result.files_missing.len() > 5 {
                                println!("    ... и ещё {}", verify_result.files_missing.len() - 5);
                            }
                        }
                        if !verify_result.files_corrupted.is_empty() {
                            println!("  Повреждённых файлов: {}", verify_result.files_corrupted.len());
                            for f in verify_result.files_corrupted.iter().take(5) {
                                println!("    - {}", f);
                            }
                            if verify_result.files_corrupted.len() > 5 {
                                println!("    ... и ещё {}", verify_result.files_corrupted.len() - 5);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ОШИБКА] Не удалось проверить восстановленные файлы: {}", e);
                    error!("Ошибка проверки восстановленных файлов: {}", e);
                }
            }
        }

        Ok(())
    }

    fn cmd_list(
        &self,
        details: bool,
        limit: Option<usize>,
        profile_filter: Option<&str>,
        sort: &str,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'list' вызвана", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        if !backup_dir.exists() {
            if self.json {
                let empty = json!({
                    "status": "success",
                    "backups": [],
                    "count": 0,
                    "message": "Каталог резервных копий не существует"
                });
                println!("{}", serde_json::to_string_pretty(&empty)?);
            } else {
                println!("Каталог резервных копий не существует: {}", backup_dir.display());
            }
            return Ok(());
        }

        let backups = match storage.list_all() {
            Ok(b) => b,
            Err(e) => {
                error!("Ошибка получения списка копий: {}", e);
                if self.json {
                    let err = json!({
                        "status": "error",
                        "error": "list_failed",
                        "message": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&err)?);
                } else {
                    println!("Ошибка получения списка резервных копий: {}", e);
                }
                return Ok(());
            }
        };

        // Сортировка (по умолчанию – от новых к старым)
        let mut sorted_backups = backups;
        if sort == "asc" {
            sorted_backups.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        } else {
            sorted_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        }

        // Применяем фильтр и лимит
        let mut filtered = Vec::new();
        for backup in sorted_backups {
            if let Some(filter) = profile_filter {
                if backup.profile != filter {
                    continue;
                }
            }
            filtered.push(backup);
            if let Some(limit) = limit {
                if filtered.len() >= limit {
                    break;
                }
            }
        }

        // JSON-вывод
        if self.json {
            #[derive(Serialize)]
            struct ListResponse {
                status: String,
                backups: Vec<BackupInfo>,
                count: usize,
            }
            let response = ListResponse {
                status: "success".to_string(),
                backups: filtered.clone(),
                count: filtered.len(),
            };
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        // Человекочитаемый вывод
        if filtered.is_empty() {
            println!("Резервные копии не найдены.");
            return Ok(());
        }

        println!("Резервные копии ({}):", filtered.len());
        for backup in filtered {
            self.display_backup(&backup, details);
        }

        Ok(())
    }

    fn cmd_status(
        &self,
        check_integrity: bool,
        show_storage: bool,
        history: bool,
        summary: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'status' вызвана", crate::VERSION);

        let config = match crate::config::Config::load(self.config.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                warn!("Не удалось загрузить конфигурацию: {}", e);
                if self.json {
                    let err = json!({
                        "status": "error",
                        "error": "config_load_failed",
                        "message": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&err)?);
                } else {
                    println!("Предупреждение: не удалось загрузить конфигурацию: {}", e);
                }
                crate::config::Config::default()
            }
        };

        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        // Статистика хранилища
        let stats = match storage.get_storage_stats() {
            Ok(s) => s,
            Err(e) => {
                error!("Не удалось получить статистику хранилища: {}", e);
                if self.json {
                    let err = json!({
                        "status": "error",
                        "error": "storage_stats_failed",
                        "message": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&err)?);
                } else {
                    println!("Не удалось получить статистику хранилища: {}", e);
                }
                return Ok(());
            }
        };

        // Сводка проверки целостности (если запрошена)
        let integrity_summary = if check_integrity {
            let (ok, corrupted) = self.check_storage_integrity_summary(&storage, &config)?;
            Some((ok, corrupted))
        } else {
            None
        };

        // JSON-вывод
        if self.json {
            #[derive(Serialize)]
            struct StatusResponse {
                status: String,
                config: serde_json::Value,
                storage: StorageStatsJson,
                integrity: Option<IntegrityJson>,
                recent_backups: Option<Vec<BackupInfo>>,
            }

            #[derive(Serialize)]
            struct StorageStatsJson {
                total_backups: usize,
                total_size: u64,
                total_size_human: String,
                profiles: Vec<ProfileCount>,
            }

            #[derive(Serialize)]
            struct ProfileCount {
                name: String,
                count: usize,
            }

            #[derive(Serialize)]
            struct IntegrityJson {
                ok: usize,
                corrupted: usize,
            }

            let config_json = json!({
                "backup_dir": config.core.backup_dir,
                "encryption_available": config.encryption_available(),
                "profiles_count": config.profiles.len(),
            });

            let profiles_vec: Vec<ProfileCount> = stats
                .profiles
                .iter()
                .map(|(name, &count)| ProfileCount { name: name.clone(), count })
                .collect();

            let recent = if history {
                let mut all = storage.list_all().unwrap_or_default();
                all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                Some(all.into_iter().take(10).collect())
            } else {
                None
            };

            let response = StatusResponse {
                status: "success".to_string(),
                config: config_json,
                storage: StorageStatsJson {
                    total_backups: stats.total_backups,
                    total_size: stats.total_size,
                    total_size_human: crate::utils::bytes_to_human(stats.total_size),
                    profiles: profiles_vec,
                },
                integrity: integrity_summary.map(|(ok, corrupted)| IntegrityJson { ok, corrupted }),
                recent_backups: recent,
            };

            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        // Человекочитаемый вывод
        if !summary {
            println!("Конфигурация:");
            println!("  Каталог резервных копий: {}", config.core.backup_dir.display());

            let key_exists = config.crypto.master_key_path.exists();
            println!(
                "  Шифрование: {}",
                if key_exists {
                    format!("✓ (Кузнечик ГОСТ 34.12-2018)\n  Ключ: {}", config.crypto.master_key_path.display())
                } else {
                    "✗".to_string()
                }
            );
            println!("  Профилей в конфигурации: {}", config.profiles.len());
        }

        if show_storage || !summary {
            println!("\nСостояние хранилища:");
            print!("{}", stats.display());
        }

        if let Some((ok, corrupted)) = integrity_summary {
            println!("\nСводка проверки целостности:");
            println!("  OK:          {}", ok);
            println!("  Повреждено:  {}", corrupted);
            if corrupted > 0 {
                println!("  [ВНИМАНИЕ] Обнаружены повреждённые резервные копии!");
            }
        }

        if history && !summary {
            println!("\nПоследние операции:");
            match storage.list_all() {
                Ok(backups) => {
                    let mut sorted = backups;
                    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    for backup in sorted.iter().take(10) {
                        let enc = if backup.encrypted.unwrap_or(false) { "🔒" } else { "🔓" };
                        println!(
                            "  {} {} [{}] {} ({})",
                            backup.timestamp.format("%Y-%m-%d %H:%M"),
                            enc,
                            backup.backup_type,
                            backup.profile,
                            crate::utils::bytes_to_human(backup.size_encrypted)
                        );
                    }
                }
                Err(e) => println!("  Не удалось получить список копий: {}", e),
            }
        }

        if summary {
            println!(
                "Копий: {}, Общий размер: {}",
                stats.total_backups,
                crate::utils::bytes_to_human(stats.total_size)
            );
        }

        Ok(())
    }

    fn cmd_verify(
        &self,
        backup_id: Option<&str>,
        quick: bool,
        _repair: bool,
        _profile_filter: Option<&str>,
        progress: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'verify' вызвана", crate::VERSION);

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());
        let engine = crate::backup::BackupEngine::new(storage.clone(), config)?;

        if let Some(id) = backup_id {
            println!("Проверка копии: {} (быстрая: {})", id, quick);
            info!("Проверка копии {}", id);

            let result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(id, quick, progress)
            )?;

            if result.is_ok() {
                println!("\n✅ [УСПЕХ] Проверка резервной копии пройдена");
                if !quick {
                    println!("   Проверено файлов: {}/{}", result.files_matched, result.files_checked);
                    if !result.files_missing.is_empty() {
                        println!("   ⚠️  Отсутствует файлов: {}", result.files_missing.len());
                    }
                    if !result.files_corrupted.is_empty() {
                        println!("   ❌ Повреждённых файлов: {}", result.files_corrupted.len());
                    }
                }
                info!("Копия {} успешно проверена", id);
                Ok(())
            } else {
                println!("\n❌ [ОШИБКА] Проверка не пройдена");
                for err in &result.errors {
                    println!("   - {}", err);
                }
                if !result.files_missing.is_empty() {
                    println!("\n   Отсутствующие файлы:");
                    for f in result.files_missing.iter().take(5) {
                        println!("     - {}", f);
                    }
                    if result.files_missing.len() > 5 {
                        println!("     ... и ещё {}", result.files_missing.len() - 5);
                    }
                }
                if !result.files_corrupted.is_empty() {
                    println!("\n   Повреждённые файлы:");
                    for f in result.files_corrupted.iter().take(5) {
                        println!("     - {}", f);
                    }
                    if result.files_corrupted.len() > 5 {
                        println!("     ... и ещё {}", result.files_corrupted.len() - 5);
                    }
                }
                error!("Проверка копии {} не пройдена", id);
                Err(anyhow!("Проверка резервной копии не пройдена"))
            }
        } else {
            println!("Проверка всех резервных копий...");
            info!("Проверка всех копий");

            let storage = self.storage()?;
            let backups = storage.list_all()?;
            let mut ok_count = 0;
            let mut error_count = 0;

            for backup in backups {
                print!("  {}... ", backup.id);
                let verify_result = tokio::runtime::Runtime::new()?.block_on(
                    engine.verify_backup(&backup.id, quick, progress)
                )?;
                if verify_result.is_ok() {
                    println!("OK");
                    ok_count += 1;
                } else {
                    println!("ОШИБКА");
                    error_count += 1;
                }
            }

            println!("\nПроверка завершена:");
            println!("  Всего:     {}", ok_count + error_count);
            println!("  Успешно:   {}", ok_count);
            println!("  Ошибок:    {}", error_count);

            if error_count > 0 {
                error!("Некоторые копии не прошли проверку");
                Err(anyhow!("Некоторые резервные копии не прошли проверку"))
            } else {
                info!("Все копии успешно проверены");
                Ok(())
            }
        }
    }

    fn cmd_cleanup(
        &self,
        keep_last: Option<usize>,
        max_age: Option<&str>,
        dry_run: bool,
        profile_filter: Option<&str>,
        remove_corrupted: bool,
        force: bool,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'cleanup' вызвана", crate::VERSION);

        if let Some(keep) = keep_last {
            println!("Сохранить последних копий: {}", keep);
        }
        if let Some(age) = max_age {
            println!("Максимальный возраст: {}", age);
        }
        if dry_run {
            println!("[ПРОБНЫЙ ПРОГОН] Изменения не будут применены");
        }
        if let Some(filter) = profile_filter {
            println!("Фильтр профиля: {}", filter);
        }
        if remove_corrupted {
            println!("Будут удалены повреждённые копии");
        }
        if force {
            println!("Принудительный режим – удаление без подтверждения");
        }

        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        let storage = crate::storage::BackupStorage::new(&backup_dir.display().to_string());

        let mut backups = storage.list_all()?;
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        println!("Найдено копий: {}", backups.len());

        let mut to_keep = Vec::new();
        let mut to_delete = Vec::new();

        let filtered_backups: Vec<_> = if let Some(filter) = profile_filter {
            backups.into_iter().filter(|b| b.profile == filter).collect()
        } else {
            backups
        };
        println!("После фильтрации профиля: {} копий", filtered_backups.len());

        // Оставить последние N
        if let Some(keep) = keep_last {
            for (i, backup) in filtered_backups.iter().enumerate() {
                if i < keep {
                    to_keep.push(backup);
                } else {
                    to_delete.push(backup);
                }
            }
        } else {
            to_keep = filtered_backups.iter().collect();
        }

        // Фильтр по возрасту
        if let Some(age_str) = max_age {
            if age_str.ends_with('d') {
                if let Ok(days) = age_str.trim_end_matches('d').parse::<i64>() {
                    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
                    for backup in &filtered_backups {
                        if backup.timestamp < cutoff {
                            if !to_delete.iter().any(|b| b.id == backup.id) {
                                to_delete.push(backup);
                            }
                        } else if !to_keep.iter().any(|b| b.id == backup.id) {
                            to_keep.push(backup);
                        }
                    }
                    println!("Максимальный возраст: {} дн. (дата отсечения: {})", days, cutoff.format("%Y-%m-%d"));
                }
            } else {
                warn!("Формат max-age не поддерживается, используйте '7d', '30d' и т.д.");
                println!("Предупреждение: формат max-age не поддерживается, используйте '7d', '30d'.");
            }
        }

        // Удаление повреждённых
        if remove_corrupted {
            println!("Проверка на повреждённые копии...");
            let engine = crate::backup::BackupEngine::new(storage.clone(), config.clone())?;

            for backup in &filtered_backups {
                let verify_result = tokio::runtime::Runtime::new()?.block_on(
                    engine.verify_backup(&backup.id, true, false)
                )?;
                if !verify_result.is_ok() {
                    println!("  Копия {} повреждена", backup.id);
                    if !to_delete.iter().any(|b| b.id == backup.id) {
                        to_delete.push(backup);
                    }
                }
            }
        }

        // Убираем дубли: нельзя одновременно оставить и удалить
        to_delete.retain(|backup| !to_keep.iter().any(|b| b.id == backup.id));

        println!("\nИтого:");
        println!("  Оставить:  {} копий", to_keep.len());
        println!("  Удалить:   {} копий", to_delete.len());

        if !to_delete.is_empty() {
            if dry_run {
                println!("\n[ПРОБНЫЙ ПРОГОН] Будет удалено:");
                for backup in &to_delete {
                    println!("  - {} (профиль: {}, дата: {})",
                        backup.id,
                        backup.profile,
                        backup.timestamp.format("%Y-%m-%d")
                    );
                }
                println!("\nОбщий объём к освобождению: {}",
                    crate::utils::bytes_to_human(to_delete.iter().map(|b| b.size_encrypted).sum())
                );
            } else if force {
                println!("\nУдаление копий (принудительный режим)...");
                let mut freed_space = 0;
                for backup in &to_delete {
                    let backup_path = storage.backup_path(&backup.id);
                    if backup_path.exists() {
                        println!("  Удаление: {} (профиль: {})", backup.id, backup.profile);
                        freed_space += backup.size_encrypted;
                        std::fs::remove_dir_all(&backup_path)?;
                    }
                }
                println!("\n[УСПЕХ] Очистка завершена");
                println!("  Освобождено:      {}", crate::utils::bytes_to_human(freed_space));
                println!("  Осталось копий:   {}", to_keep.len());
            } else {
                println!("\nКопии, отмеченные для удаления (используйте --force для фактического удаления):");
                for backup in &to_delete {
                    println!(
                        "  - {} (профиль: {}, дата: {}, размер: {})",
                        backup.id,
                        backup.profile,
                        backup.timestamp.format("%Y-%m-%d"),
                        crate::utils::bytes_to_human(backup.size_encrypted)
                    );
                }
                println!("\nОбщий объём к освобождению: {}",
                    crate::utils::bytes_to_human(to_delete.iter().map(|b| b.size_encrypted).sum())
                );
                println!("\nЗапустите с --force для подтверждения удаления.");
            }
        } else {
            println!("\nНет копий для удаления.");
        }

        Ok(())
    }

    fn cmd_keygen(
        &self,
        output: Option<&Path>,
        force: bool,
        recovery: bool,
        comment: Option<&str>,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'keygen' вызвана", crate::VERSION);

        let key = crate::crypto::KuznechikCipher::generate_key();

        let default_key_path = PathBuf::from("/etc/krybs/master.key");
        let output_path = output.unwrap_or(&default_key_path);

        if output_path.exists() && !force {
            return Err(anyhow!(
                "Файл ключа уже существует: {}. Используйте --force для перезаписи",
                output_path.display()
            ));
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        crate::crypto::Crypto::save_key(&key, output_path)?;

        println!("[УСПЕХ] Сгенерирован ключ шифрования Кузнечик (256 бит)");
        println!("  Файл ключа:     {}", output_path.display());
        println!("  Размер ключа:   {} байт (256 бит)", key.len());
        println!("  Алгоритм:       ГОСТ 34.12-2018 (Кузнечик)");

        if let Some(comment) = comment {
            println!("  Комментарий:    {}", comment);
        }

        if recovery {
            println!("\n[ВАЖНО] Генерация ключа восстановления:");
            let recovery_key = crate::crypto::KuznechikCipher::generate_key();
            let recovery_path = output_path.with_extension("recovery.key");
            crate::crypto::Crypto::save_key(&recovery_key, &recovery_path)?;
            println!("  Ключ восстановления: {}", recovery_path.display());
            println!("  [ПРЕДУПРЕЖДЕНИЕ] Храните ключ восстановления в надёжном месте!");
        }

        Ok(())
    }

    fn cmd_init_config(
        &self,
        interactive: bool,
        output: Option<&Path>,
        defaults: bool,
        examples: bool,
        set_backup_dir: Option<&Path>,
    ) -> Result<()> {
        info!("KRYBS {}: команда 'init-config' вызвана", crate::VERSION);

        if interactive {
            println!("Включён интерактивный режим");
        }
        if let Some(dir) = set_backup_dir {
            println!("Задан каталог резервных копий: {}", dir.display());
        }
        if examples {
            println!("Будут добавлены примеры профилей");
        }

        crate::config::init_config(output, interactive, defaults)?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Вспомогательные методы
    // ------------------------------------------------------------------------

    /// Возвращает экземпляр хранилища на основе текущих настроек CLI.
    fn storage(&self) -> Result<crate::storage::BackupStorage> {
        let config = crate::config::Config::load(self.config.as_deref()).unwrap_or_default();
        let backup_dir = self.backup_dir.as_deref().unwrap_or(&config.core.backup_dir);
        Ok(crate::storage::BackupStorage::new(&backup_dir.display().to_string()))
    }

    /// Отображает одну запись резервной копии (для команды list).
    fn display_backup(&self, backup: &BackupInfo, details: bool) {
        let enc_icon = if backup.encrypted.unwrap_or(false) { "🔒" } else { "🔓" };

        if details {
            println!(
                "  {} [{}] {} — {} ({} файлов, {})",
                enc_icon,
                backup.backup_type,
                backup.id,
                backup.timestamp.format("%Y-%m-%d %H:%M:%S"),
                backup.file_count,
                crate::utils::bytes_to_human(backup.size_encrypted)
            );
            println!("    Профиль: {}", backup.profile);
            if let Some(checksum) = &backup.checksum {
                println!("    Контрольная сумма: {}...", &checksum[0..16]);
            }
        } else {
            println!(
                "  {} {} {} {} ({})",
                enc_icon,
                backup.backup_type,
                backup.id,
                backup.timestamp.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
                crate::utils::bytes_to_human(backup.size_encrypted)
            );
        }
    }

    /// Сводная проверка целостности всех копий (возвращает число OK и повреждённых).
    fn check_storage_integrity_summary(
        &self,
        storage: &crate::storage::BackupStorage,
        config: &crate::config::Config,
    ) -> Result<(usize, usize)> {
        let backups = storage.list_all()?;
        let engine = crate::backup::BackupEngine::new(storage.clone(), config.clone())?;

        let mut ok = 0;
        let mut corrupted = 0;

        for backup in backups {
            let result = tokio::runtime::Runtime::new()?.block_on(
                engine.verify_backup(&backup.id, true, false)
            )?;
            if result.is_ok() {
                ok += 1;
            } else {
                corrupted += 1;
            }
        }

        Ok((ok, corrupted))
    }
}

/// Преобразует строку вида "24h", "7d", "30m" в chrono::Duration.
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(num_str) = s.strip_suffix('h') {
        let hours = num_str.parse::<i64>()?;
        Ok(Duration::hours(hours))
    } else if let Some(num_str) = s.strip_suffix('d') {
        let days = num_str.parse::<i64>()?;
        Ok(Duration::days(days))
    } else if let Some(num_str) = s.strip_suffix('m') {
        let minutes = num_str.parse::<i64>()?;
        Ok(Duration::minutes(minutes))
    } else {
        // По умолчанию считаем часы
        let hours = s.parse::<i64>()?;
        Ok(Duration::hours(hours))
    }
}