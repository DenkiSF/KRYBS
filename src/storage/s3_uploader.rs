// src/storage/s3_uploader.rs

use anyhow::{Context, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use std::path::Path;
use walkdir::WalkDir;

/// Клиент для загрузки резервных копий в S3-совместимое хранилище
pub struct S3Uploader {
    client: Client,
    bucket: String,
}

impl S3Uploader {
    /// Создаёт новый экземпляр, настраивая подключение к указанному бакету
    pub async fn new(bucket: &str, region: &str, endpoint: Option<&str>) -> Result<Self> {
        let region_provider = RegionProviderChain::first_try(
            aws_sdk_s3::config::Region::new(region.to_string())
        )
        .or_default_provider()
        .or_else(aws_sdk_s3::config::Region::new("us-east-1"));

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&config);
        if let Some(endpoint) = endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }
        let s3_config = s3_config_builder.build();

        let client = Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket: bucket.to_string(),
        })
    }

    /// Загружает резервную копию (все файлы из локального каталога) в S3
    pub fn upload_backup(&self, backup_id: &str, local_dir: &Path, prefix: &str) -> Result<()> {
        if !local_dir.exists() {
            anyhow::bail!("Локальный каталог резервной копии не существует: {}", local_dir.display());
        }

        let prefix = if prefix.is_empty() {
            format!("{}/", backup_id)
        } else {
            format!("{}/{}/", prefix.trim_end_matches('/'), backup_id)
        };

        for entry in WalkDir::new(local_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let local_path = entry.path();
            let relative = local_path.strip_prefix(local_dir)
                .expect("должен быть внутри корня");
            let object_key = format!("{}{}", prefix, relative.display());

            tokio::runtime::Runtime::new()?.block_on(
                self.upload_file(local_path, &object_key)
            )?;

            println!("  Загружен: {}", object_key);
        }

        Ok(())
    }

    /// Загружает отдельный файл в бакет
    async fn upload_file(&self, local_path: &Path, object_key: &str) -> Result<()> {
        let body = ByteStream::from_path(local_path)
            .await
            .with_context(|| format!("Не удалось прочитать файл: {}", local_path.display()))?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(object_key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("Не удалось загрузить {}", object_key))?;

        Ok(())
    }
}