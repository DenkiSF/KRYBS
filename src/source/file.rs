// src/source/file.rs

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use log::debug;
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Builder;
use tempfile::NamedTempFile;

use crate::source::BackupSource;
use crate::utils; // для build_globset, common_prefix, find_common_root, calculate_file_hash

/// Информация о файле, собираемая при сканировании
#[derive(Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: DateTime<Utc>,
    pub hash: String,
    pub mode: Option<u32>,
    #[cfg(unix)]
    pub uid: Option<u32>,
    #[cfg(unix)]
    pub gid: Option<u32>,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
}

/// Источник данных для резервного копирования файлов и каталогов
pub struct FileSource {
    name: String,
    paths: Vec<PathBuf>,
    exclude_patterns: Vec<String>,
    files: Vec<FileInfo>,
    total_size: u64,
    common_root: PathBuf,
    temp_archive: Option<NamedTempFile>, // временный архив, создаваемый при read()
}

impl FileSource {
    /// Создаёт новый файловый источник. Принимает список исходных путей и шаблоны исключений.
    pub fn new(paths: Vec<PathBuf>, exclude_patterns: Vec<String>) -> Result<Self> {
        let name = if paths.len() == 1 {
            paths[0].display().to_string()
        } else {
            format!("{} paths", paths.len())
        };

        let (files, total_size, common_root) = Self::scan_paths(&paths, &exclude_patterns)?;

        Ok(Self {
            name,
            paths,
            exclude_patterns,
            files,
            total_size,
            common_root,
            temp_archive: None,
        })
    }

    /// Рекурсивно сканирует указанные пути, собирает информацию о файлах (исключая те, что подпадают под шаблоны)
    fn scan_paths(
        paths: &[PathBuf],
        exclude_patterns: &[String],
    ) -> Result<(Vec<FileInfo>, u64, PathBuf)> {
        let mut files = Vec::new();
        let mut total_size = 0;

        let globset = utils::build_globset(exclude_patterns)?;

        for path in paths {
            if !path.exists() {
                eprintln!("[ПРЕДУПРЕЖДЕНИЕ] Путь не существует: {}", path.display());
                continue;
            }

            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();

                if entry_path.is_dir() {
                    continue;
                }

                if let Some(ref globset) = globset {
                    let path_str = entry_path.to_string_lossy();
                    if globset.is_match(path_str.as_ref()) {
                        continue;
                    }
                }

                let file_info = Self::get_file_info(entry_path)?;
                total_size += file_info.size;
                files.push(file_info);
            }
        }

        if files.is_empty() {
            anyhow::bail!("Не найдено ни одного файла для резервного копирования");
        }

        let paths_for_root: Vec<PathBuf> = files.iter().map(|f| f.path.clone()).collect();
        let common_root = utils::find_common_root(&paths_for_root)?;

        Ok((files, total_size, common_root))
    }

    /// Собирает метаданные отдельного файла или символьной ссылки
    fn get_file_info(path: &Path) -> Result<FileInfo> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("Не удалось получить метаданные для {}", path.display()))?;

        let abs_path = if path.is_relative() {
            std::env::current_dir()?.join(path)
        } else {
            path.to_path_buf()
        };

        let mtime = metadata
            .modified()
            .map(|t| DateTime::<Utc>::from(t))
            .unwrap_or_else(|_| Utc::now());

        let file_type = metadata.file_type();
        let is_symlink = file_type.is_symlink();

        let (size, hash, symlink_target) = if is_symlink {
            let target = fs::read_link(path).with_context(|| {
                format!(
                    "Не удалось прочитать цель символьной ссылки: {}",
                    path.display()
                )
            })?;
            (0, String::new(), Some(target))
        } else if file_type.is_file() {
            let size = metadata.len();
            let hash = utils::calculate_file_hash(path)?;
            (size, hash, None)
        } else {
            return Err(anyhow::anyhow!(
                "Необычный тип файла (не обычный файл и не символьная ссылка): {}",
                path.display()
            ));
        };

        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            let uid = metadata.uid();
            let gid = metadata.gid();
            (Some(mode), Some(uid), Some(gid))
        };

        #[cfg(not(unix))]
        let (mode, uid, gid) = (None, None, None);

        Ok(FileInfo {
            path: abs_path,
            size,
            mtime,
            hash,
            mode,
            #[cfg(unix)]
            uid,
            #[cfg(unix)]
            gid,
            is_symlink,
            symlink_target,
        })
    }

    /// Создаёт TAR.GZ архив из отсканированных файлов и сохраняет его во временный файл
    fn create_archive(&mut self) -> Result<()> {
        debug!("Начинаю создание архива");

        if !self.common_root.exists() {
            return Err(anyhow::anyhow!(
                "Общий корневой каталог не существует: {:?}",
                self.common_root
            ));
        }
        if !self.common_root.is_dir() {
            return Err(anyhow::anyhow!(
                "Общий корневой каталог не является директорией: {:?}",
                self.common_root
            ));
        }

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_path_buf();

        let file = fs::File::create(&path)?;
        let encoder = GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = Builder::new(encoder);

        for (idx, file_info) in self.files.iter().enumerate() {
            if !file_info.path.exists() {
                debug!("[{}]: файл не существует, пропускаю", idx);
                continue;
            }

            let rel_path = file_info
                .path
                .strip_prefix(&self.common_root)
                .with_context(|| {
                    format!(
                        "Не удалось получить относительный путь для {} (корень: {})",
                        file_info.path.display(),
                        self.common_root.display()
                    )
                })?;

            let mut header = tar::Header::new_gnu();
            header.set_mtime(file_info.mtime.timestamp() as u64);

            if let Some(mode) = file_info.mode {
                header.set_mode(mode);
            }

            #[cfg(unix)]
            {
                if let (Some(uid), Some(gid)) = (file_info.uid, file_info.gid) {
                    header.set_uid(uid.into());
                    header.set_gid(gid.into());
                }
            }

            if file_info.is_symlink {
                if let Some(target) = &file_info.symlink_target {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_cksum();
                    tar_builder
                        .append_link(&mut header, rel_path, target)
                        .context("Не удалось добавить символьную ссылку")?;
                } else {
                    eprintln!(
                        "[ПРЕДУПРЕЖДЕНИЕ] Символьная ссылка {} не имеет цели, пропускаю",
                        file_info.path.display()
                    );
                    continue;
                }
            } else {
                let _metadata = fs::metadata(&file_info.path).context(format!(
                    "Не удалось прочитать метаданные для {}",
                    file_info.path.display()
                ))?;

                let mut src_file = fs::File::open(&file_info.path).context(format!(
                    "Не удалось открыть файл: {}",
                    file_info.path.display()
                ))?;

                header.set_size(file_info.size);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();

                tar_builder
                    .append_data(&mut header, rel_path, &mut src_file)
                    .context("Не удалось добавить файл в архив")?;
            }
        }

        let encoder = tar_builder
            .into_inner()
            .context("Не удалось завершить построение архива")?;
        encoder
            .finish()
            .context("Не удалось завершить сжатие архива")?;

        self.temp_archive = Some(temp_file);
        Ok(())
    }
}

impl BackupSource for FileSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn size_hint(&self) -> Option<u64> {
        Some(self.total_size)
    }

    fn read(&mut self) -> Result<Box<dyn Read + Send + '_>> {
        if self.temp_archive.is_none() {
            self.create_archive()?;
        }
        let file = fs::File::open(self.temp_archive.as_ref().unwrap().path())?;
        Ok(Box::new(file))
    }

    fn metadata(&self) -> Value {
        let file_list: Vec<Value> = self
            .files
            .iter()
            .map(|f| {
                let rel_path = f.path.strip_prefix(&self.common_root).unwrap_or(&f.path);
                let mut obj = serde_json::json!({
                    "abs_path": f.path.display().to_string(),
                    "rel_path": rel_path.display().to_string(),
                    "size": f.size,
                    "mtime": f.mtime.to_rfc3339(),
                    "hash": f.hash,
                    "is_symlink": f.is_symlink,
                });
                if let Some(mode) = f.mode {
                    obj["mode"] = serde_json::json!(mode);
                }
                #[cfg(unix)]
                {
                    if let Some(uid) = f.uid {
                        obj["uid"] = serde_json::json!(uid);
                    }
                    if let Some(gid) = f.gid {
                        obj["gid"] = serde_json::json!(gid);
                    }
                }
                if let Some(target) = &f.symlink_target {
                    obj["symlink_target"] = serde_json::json!(target.display().to_string());
                }
                obj
            })
            .collect();

        serde_json::json!({
            "type": "file",
            "paths": self.paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "exclude_patterns": self.exclude_patterns,
            "file_count": self.files.len(),
            "total_size": self.total_size,
            "common_root": self.common_root.display().to_string(),
            "files": file_list,
        })
    }

    fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}
