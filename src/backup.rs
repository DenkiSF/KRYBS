// src/backup.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use filetime::FileTime;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::{Archive, Builder};

#[cfg(unix)]
use nix::unistd::{chown, Gid, Uid};

use crate::config::Config;
use crate::crypto::Crypto;
use crate::storage::{BackupInfo, BackupStorage, BackupType};

// ============================================================================
// Structures
// ============================================================================

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct BackupResult {
    pub id: String,
    pub backup_type: BackupType,
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub file_count: usize,
    pub size_bytes: u64,
    pub archive_size: u64,
    pub encrypted: bool,
    pub duration_secs: f64,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub backup_id: String,
    pub quick: bool,
    pub archive_ok: bool,
    pub decryption_ok: bool,
    pub extraction_ok: bool,
    pub files_checked: u64,
    pub files_matched: u64,
    pub files_missing: Vec<String>,
    pub files_corrupted: Vec<String>,
    pub errors: Vec<String>,
}

impl VerificationResult {
    pub fn is_ok(&self) -> bool {
        self.archive_ok
            && self.decryption_ok
            && self.extraction_ok
            && self.files_missing.is_empty()
            && self.files_corrupted.is_empty()
    }
}

#[derive(Debug)]
pub struct BackupEngine {
    pub storage: BackupStorage,
    pub config: Arc<Config>,
    pub crypto: Crypto,
}

// ============================================================================
// Implementation BackupEngine
// ============================================================================

impl BackupEngine {
    pub fn new(storage: BackupStorage, config: Config) -> Result<Self> {
        let crypto = if config.crypto.master_key_path.exists() {
            match Crypto::load_key(&config.crypto.master_key_path) {
                Ok(key) => {
                    println!("[INFO] Encryption enabled with Kuznechik cipher");
                    Crypto::new_with_key(key)
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to load encryption key: {}", e);
                    eprintln!("[WARN] Continuing without encryption");
                    Crypto::new_without_encryption()
                }
            }
        } else {
            println!("[INFO] Encryption key not found, encryption disabled");
            Crypto::new_without_encryption()
        };

        Ok(Self {
            storage,
            config: Arc::new(config),
            crypto,
        })
    }

    // ------------------------------------------------------------------------
    // Backup creation
    // ------------------------------------------------------------------------

    pub async fn create_backup(
        &self,
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        profile_name: Option<&str>,
        progress: bool,
    ) -> Result<BackupResult> {
        let start_time = Utc::now();
        let profile = profile_name.unwrap_or("manual");

        println!("[INFO] Starting backup for profile: {}", profile);
        println!("[INFO] Source paths: {:?}", paths);
        println!(
            "[INFO] Encryption: {}",
            if self.crypto.is_enabled() {
                "ENABLED (Kuznechik)"
            } else {
                "DISABLED"
            }
        );

        if !exclude_patterns.is_empty() {
            println!("[INFO] Exclude patterns: {:?}", exclude_patterns);
        }

        println!("[INFO] Scanning files...");
        let files = self.scan_paths(&paths, &exclude_patterns, progress).await?;

        if files.is_empty() {
            return Err(anyhow::anyhow!("No files found to backup"));
        }

        let total_size: u64 = files.iter().map(|f| f.size).sum();
        println!(
            "[INFO] Found {} files (total: {})",
            files.len(),
            crate::storage::bytes_to_human(total_size)
        );

        let backup_id = self.storage.generate_id(BackupType::Full, start_time);
        let backup_dir = self.storage.backup_path(&backup_id);

        println!("[INFO] Creating backup directory: {}", backup_dir.display());
        fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;

        let tar_path = backup_dir.join("data.tar.gz");
        println!("[INFO] Creating archive: {}", tar_path.display());

        let archive_size = self.create_tar(&files, &tar_path, progress).await?;
        self.validate_archive(&tar_path)?;

        let (final_archive_path, final_archive_size, encrypted) = if self.crypto.is_enabled() {
            let encrypted_path = tar_path.with_file_name("data.tar.gz.enc");
            println!("[INFO] Encrypting archive with Kuznechik cipher...");
            self.crypto
                .encrypt_file(&tar_path, &encrypted_path)
                .context("Failed to encrypt archive")?;
            if self.config.crypto.delete_plain {
                fs::remove_file(&tar_path)?;
                println!("[INFO] Removed plaintext archive (delete_plain=true)");
            }
            let encrypted_size = fs::metadata(&encrypted_path)?.len();
            (encrypted_path, encrypted_size, true)
        } else {
            (tar_path.clone(), archive_size, false)
        };

        let manifest_path = backup_dir.join("manifest.json");
        println!("[INFO] Creating manifest: {}", manifest_path.display());
        let manifest = self.create_manifest(&files, encrypted)?;
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest")?;

        let backup_info = BackupInfo {
            id: backup_id.clone(),
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: files.len() as u64,
            size_encrypted: final_archive_size,
            checksum: Some(calculate_file_hash(&final_archive_path).await?),
            encrypted: Some(encrypted),
        };

        self.storage.write_local_index(&backup_info)?;

        let end_time = Utc::now();
        let duration = end_time.signed_duration_since(start_time);
        let duration_secs = duration.num_milliseconds() as f64 / 1000.0;

        let result = BackupResult {
            id: backup_id,
            backup_type: BackupType::Full,
            timestamp: start_time,
            profile: profile.to_string(),
            file_count: files.len(),
            size_bytes: total_size,
            archive_size: final_archive_size,
            encrypted,
            duration_secs,
        };

        println!("\n[SUCCESS] Backup created: {}", result.id);
        println!("  Profile:      {}", profile);
        println!("  Files:        {}", files.len());
        println!(
            "  Original:     {}",
            crate::storage::bytes_to_human(total_size)
        );
        println!(
            "  Archive:      {}",
            crate::storage::bytes_to_human(final_archive_size)
        );

        if total_size > 0 {
            let ratio = final_archive_size as f64 / total_size as f64;
            if final_archive_size < total_size {
                let compression = (1.0 - ratio) * 100.0;
                println!("  Compression:  +{:.1}% (saved)", compression);
            } else if final_archive_size > total_size {
                let increase = (ratio - 1.0) * 100.0;
                if encrypted {
                    println!("  Overhead:     {:.1}% (larger due to metadata + encryption)", increase);
                } else {
                    println!("  Overhead:     {:.1}% (larger due to metadata)", increase);
                }
            } else {
                println!("  Compression:  0.0% (no change)");
            }
        } else {
            println!("  Compression:  N/A (empty files)");
        }

        println!(
            "  Encryption:   {}",
            if encrypted { "✓ (Kuznechik)" } else { "✗" }
        );
        println!("  Duration:     {:.1}s", duration_secs);
        println!("  Location:     {}", backup_dir.display());

        Ok(result)
    }

    pub async fn scan_paths(
        &self,
        paths: &[PathBuf],
        exclude_patterns: &[String],
        show_progress: bool,
    ) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();
        let globset = build_globset(exclude_patterns)?;

        let pb = if show_progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} Scanning: {pos} files found...")?,
            );
        }

        for path in paths {
            if !path.exists() {
                eprintln!("[WARN] Path does not exist: {}", path.display());
                continue;
            }

            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                if path.is_dir() {
                    continue;
                }

                if let Some(ref globset) = globset {
                    let path_str = path.to_string_lossy();
                    if globset.is_match(path_str.as_ref()) {
                        continue;
                    }
                }

                match self.get_file_info(path).await {
                    Ok(file_info) => {
                        files.push(file_info);
                        if let Some(ref pb) = pb {
                            pb.inc(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[WARN] Skipping {}: {}", path.display(), e);
                    }
                }
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message(format!("Found {} files", files.len()));
        }

        Ok(files)
    }

    async fn get_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

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
            let target = fs::read_link(path)
                .with_context(|| format!("Failed to read symlink target: {}", path.display()))?;
            (0, String::new(), Some(target))
        } else if file_type.is_file() {
            let size = metadata.len();
            let hash = calculate_file_hash(path).await?;
            (size, hash, None)
        } else {
            return Err(anyhow::anyhow!(
                "Not a regular file or symlink: {}",
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

    pub async fn create_tar(
        &self,
        files: &[FileInfo],
        output_path: &Path,
        show_progress: bool,
    ) -> Result<u64> {
        let common_root = self.find_common_root(files)?;

        let pb = if show_progress {
            Some(ProgressBar::new(files.len() as u64))
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} {msg}\n[{bar:40.cyan/blue}] {pos}/{len} files ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message("Creating archive...");
        }

        let file = fs::File::create(output_path).context("Failed to create archive file")?;
        let encoder = GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = Builder::new(encoder);

        for file_info in files {
            let rel_path = file_info
                .path
                .strip_prefix(&common_root)
                .with_context(|| {
                    format!(
                        "Failed to get relative path for {} (root: {})",
                        file_info.path.display(),
                        common_root.display()
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
                    header.set_uid(uid.into()); // u32 -> u64
                    header.set_gid(gid.into()); // u32 -> u64
                }
            }

            if file_info.is_symlink {
                if let Some(target) = &file_info.symlink_target {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_cksum();
                    tar_builder.append_link(&mut header, rel_path, target)?;
                } else {
                    eprintln!(
                        "[WARN] Symlink {} has no target, skipping",
                        file_info.path.display()
                    );
                    continue;
                }
            } else {
                let mut src_file = fs::File::open(&file_info.path).with_context(|| {
                    format!("Failed to open file: {}", file_info.path.display())
                })?;

                header.set_size(file_info.size);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                tar_builder.append_data(&mut header, rel_path, &mut src_file)?;
            }

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        tar_builder
            .into_inner()
            .context("Failed to get inner encoder")?
            .finish()
            .context("Failed to finish compression")?;

        if let Some(pb) = pb {
            pb.finish_with_message("Archive created successfully");
        }

        let metadata = fs::metadata(output_path)?;
        Ok(metadata.len())
    }

    pub fn validate_archive(&self, path: &Path) -> Result<()> {
        println!("[INFO] Validating archive: {}", path.display());

        let file = fs::File::open(path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let mut count = 0;
        for entry in archive.entries()? {
            let entry = entry?;
            if entry.header().path().is_err() {
                return Err(anyhow::anyhow!("Invalid path in archive entry"));
            }
            count += 1;
        }

        println!("[INFO] Archive validation passed: {} files", count);
        Ok(())
    }

    fn find_common_root(&self, files: &[FileInfo]) -> Result<PathBuf> {
        if files.is_empty() {
            return Err(anyhow::anyhow!("No files to backup"));
        }

        let mut common = files[0]
            .path
            .parent()
            .unwrap_or(&files[0].path)
            .to_path_buf();

        for file in files.iter().skip(1) {
            common = self.common_prefix(&common, &file.path);
            if common.as_os_str().is_empty() {
                common = file.path.parent().unwrap_or(&file.path).to_path_buf();
            }
        }

        if !common.is_absolute() {
            common = std::env::current_dir()?.join(common);
        }

        Ok(common)
    }

    fn common_prefix(&self, a: &Path, b: &Path) -> PathBuf {
        let a_components: Vec<_> = a.components().collect();
        let b_components: Vec<_> = b.components().collect();

        let mut common = PathBuf::new();

        for (a_comp, b_comp) in a_components.iter().zip(b_components.iter()) {
            if a_comp == b_comp {
                common.push(a_comp);
            } else {
                break;
            }
        }

        common
    }

    fn create_manifest(&self, files: &[FileInfo], encrypted: bool) -> Result<serde_json::Value> {
        let common_root = self.find_common_root(files)?;

        let file_list: Vec<serde_json::Value> = files
            .iter()
            .map(|f| {
                let rel_path = f.path.strip_prefix(&common_root)?;
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
                Ok(obj)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(serde_json::json!({
            "backup_type": "full",
            "file_count": files.len(),
            "total_size": files.iter().map(|f| f.size).sum::<u64>(),
            "timestamp": Utc::now().to_rfc3339(),
            "common_root": common_root.display().to_string(),
            "encrypted": encrypted,
            "encryption_algorithm": if encrypted { "GOST R 34.12-2015 (Kuznechik)" } else { "none" },
            "files": file_list,
        }))
    }

    // ------------------------------------------------------------------------
    // Backup verification
    // ------------------------------------------------------------------------

    pub async fn verify_backup(
        &self,
        backup_id: &str,
        quick: bool,
        progress: bool,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult {
            backup_id: backup_id.to_string(),
            quick,
            archive_ok: false,
            decryption_ok: false,
            extraction_ok: false,
            files_checked: 0,
            files_matched: 0,
            files_missing: Vec::new(),
            files_corrupted: Vec::new(),
            errors: Vec::new(),
        };

        let backup_info = match self.storage.read_backup_info(backup_id) {
            Ok(info) => info,
            Err(e) => {
                result.errors.push(format!("Failed to read backup info: {}", e));
                return Ok(result);
            }
        };

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let encrypted_path_wrong = backup_path.join("data.tar.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if encrypted_path_wrong.exists() {
            (&encrypted_path_wrong, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            result.errors.push("Archive not found".to_string());
            return Ok(result);
        };

        let manifest_path = backup_path.join("manifest.json");
        if !manifest_path.exists() {
            result.errors.push("Manifest file not found".to_string());
            return Ok(result);
        }

        result.archive_ok = true;

        let mut archive_to_use = archive_path.clone();
        if is_encrypted {
            if !self.crypto.is_enabled() {
                result
                    .errors
                    .push("Archive is encrypted but encryption is disabled".to_string());
                return Ok(result);
            }

            println!("[VERIFY] Testing decryption...");
            let temp_dir = tempfile::tempdir()?;
            let temp_archive = temp_dir.path().join("data.tar.gz");

            match self.crypto.decrypt_file(archive_path, &temp_archive) {
                Ok(_) => {
                    result.decryption_ok = true;
                    archive_to_use = temp_archive;
                }
                Err(e) => {
                    result.errors.push(format!("Decryption failed: {}", e));
                    return Ok(result);
                }
            }
        } else {
            result.decryption_ok = true;
        }

        println!("[VERIFY] Validating archive structure...");
        let file = match std::fs::File::open(&archive_to_use) {
            Ok(f) => f,
            Err(e) => {
                result.errors.push(format!("Failed to open archive: {}", e));
                return Ok(result);
            }
        };

        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let mut entry_count = 0;
        for entry in archive.entries()? {
            match entry {
                Ok(_) => entry_count += 1,
                Err(e) => {
                    result
                        .errors
                        .push(format!("Corrupted entry in archive: {}", e));
                    result.extraction_ok = false;
                    return Ok(result);
                }
            }
        }
        result.extraction_ok = true;
        result.files_checked = entry_count as u64;

        if quick {
            println!("[VERIFY] Quick verification passed (archive integrity OK)");
            return Ok(result);
        }

        println!("[VERIFY] Performing full verification (comparing file contents)...");
        let verify_dir = tempfile::tempdir()?;
        let extract_path = verify_dir.path();

        let file = std::fs::File::open(&archive_to_use)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        if progress {
            println!("[VERIFY] Extracting archive for verification...");
        }
        archive.unpack(extract_path)?;

        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

        let files = manifest["files"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid manifest format"))?;
        let total_files = files.len();

        let pb = if progress {
            let bar = indicatif::ProgressBar::new(total_files as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner} Verifying files [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            bar.set_message("Checking files...");
            Some(bar)
        } else {
            None
        };

        for file_entry in files {
            let rel_path = file_entry["rel_path"].as_str().unwrap_or("");
            let expected_hash = file_entry["hash"].as_str().unwrap_or("");
            let expected_size = file_entry["size"].as_u64().unwrap_or(0);

            let file_path = extract_path.join(rel_path);

            if !file_path.exists() {
                result.files_missing.push(rel_path.to_string());
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
                continue;
            }

            let metadata = match std::fs::metadata(&file_path) {
                Ok(m) => m,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (can't read metadata)", rel_path));
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    continue;
                }
            };

            if metadata.len() != expected_size {
                result
                    .files_corrupted
                    .push(format!("{} (size mismatch)", rel_path));
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
                continue;
            }

            let actual_hash = match calculate_file_hash(&file_path).await {
                Ok(h) => h,
                Err(_) => {
                    result
                        .files_corrupted
                        .push(format!("{} (can't compute hash)", rel_path));
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                    continue;
                }
            };

            if actual_hash == expected_hash {
                result.files_matched += 1;
            } else {
                result
                    .files_corrupted
                    .push(format!("{} (hash mismatch)", rel_path));
            }

            if let Some(ref pb) = pb {
                pb.inc(1);
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Verification complete");
        }

        result.files_checked = total_files as u64;
        Ok(result)
    }

    // ------------------------------------------------------------------------
    // Restore
    // ------------------------------------------------------------------------

    pub async fn restore_backup(
        &self,
        backup_id: &str,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        println!("[INFO] Restoring backup: {}", backup_id);
        println!("[INFO] Destination: {}", destination.display());

        let backup_info = self
            .storage
            .read_backup_info(backup_id)
            .context(format!("Failed to read backup info: {}", backup_id))?;

        let backup_path = self.storage.backup_path(&backup_info.id);
        let encrypted_path = backup_path.join("data.tar.gz.enc");
        let encrypted_path_wrong = backup_path.join("data.tar.tar.gz.enc");
        let plain_path = backup_path.join("data.tar.gz");

        let (archive_path, is_encrypted) = if encrypted_path.exists() {
            (&encrypted_path, true)
        } else if encrypted_path_wrong.exists() {
            (&encrypted_path_wrong, true)
        } else if plain_path.exists() {
            (&plain_path, false)
        } else {
            return Err(anyhow::anyhow!("Archive not found: {}", backup_info.id));
        };

        println!("[INFO] Archive: {}", archive_path.display());
        println!("[INFO] Encrypted: {}", is_encrypted);

        if is_encrypted && !self.crypto.is_enabled() {
            return Err(anyhow::anyhow!(
                "Backup is encrypted but encryption is not enabled. Load encryption key first."
            ));
        }

        let temp_dir = tempfile::tempdir()?;
        let temp_archive = temp_dir.path().join("data.tar.gz");

        if is_encrypted {
            println!("[INFO] Decrypting archive with Kuznechik cipher...");
            self.crypto
                .decrypt_file(archive_path, &temp_archive)
                .context("Failed to decrypt archive")?;
        } else {
            fs::copy(archive_path, &temp_archive)?;
        }

        self.extract_archive(&temp_archive, destination, specific_path, overwrite, progress)
            .await?;

        println!("[SUCCESS] Restore completed to {}", destination.display());
        Ok(())
    }

    async fn extract_archive(
        &self,
        archive_path: &Path,
        destination: &Path,
        specific_path: Option<&Path>,
        overwrite: bool,
        progress: bool,
    ) -> Result<()> {
        let file = fs::File::open(archive_path)
            .context(format!("Failed to open archive: {}", archive_path.display()))?;

        let pb = if progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = pb {
            pb.set_style(ProgressStyle::default_spinner().template("{spinner} Extracting: {msg}")?);
            pb.set_message("Starting...");
        }

        let mut archive = Archive::new(GzDecoder::new(file));

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path_in_archive = entry.path()?.to_path_buf();

            if let Some(specific_path) = specific_path {
                if !path_in_archive.starts_with(specific_path) {
                    continue;
                }
            }

            let dest_path = destination.join(&path_in_archive);

            if dest_path.exists() && !overwrite {
                if let Some(ref pb) = pb {
                    pb.set_message(format!("Skipping: {} (exists)", path_in_archive.display()));
                }
                continue;
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let entry_type = entry.header().entry_type();

            if entry_type == tar::EntryType::Symlink {
                let link_target = entry.link_name()?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Symlink entry has no target: {}",
                        path_in_archive.display()
                    )
                })?;

                #[cfg(unix)]
                std::os::unix::fs::symlink(&link_target, &dest_path)?;

                #[cfg(windows)]
                {
                    use std::os::windows::fs::{symlink_file, symlink_dir};
                    if symlink_file(&link_target, &dest_path).is_err() {
                        symlink_dir(&link_target, &dest_path)?;
                    }
                }
            } else {
                entry.unpack(&dest_path)?;
            }

            // Restore metadata
            let header = entry.header();

            if let Ok(mtime) = header.mtime() {
                let mtime_system = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime);
                filetime::set_file_mtime(&dest_path, FileTime::from_system_time(mtime_system))?;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mode) = header.mode() {
                    fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode))?;
                }

                if let (Ok(uid), Ok(gid)) = (header.uid(), header.gid()) {
                    let uid_u32 = u32::try_from(uid)
                        .context(format!("UID value {} too large for u32", uid))?;
                    let gid_u32 = u32::try_from(gid)
                        .context(format!("GID value {} too large for u32", gid))?;
                    chown(
                        &dest_path,
                        Some(Uid::from_raw(uid_u32)),
                        Some(Gid::from_raw(gid_u32)),
                    )?;
                }
            }

            if let Some(ref pb) = pb {
                pb.set_message(format!("Extracted: {}", path_in_archive.display()));
            }
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Extraction completed");
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------------

    pub fn encryption_status(&self) -> &'static str {
        if self.crypto.is_enabled() {
            "ENABLED (Kuznechik GOST R 34.12-2015)"
        } else {
            "DISABLED"
        }
    }

    pub fn check_backup_interval(
        &self,
        profile: &str,
        min_interval: Duration,
    ) -> Result<Option<Duration>> {
        let last_time = self.storage.last_backup_time_for_profile(profile)?;

        if let Some(last) = last_time {
            let elapsed = Utc::now() - last;
            if elapsed < min_interval {
                let time_left = min_interval - elapsed;
                return Ok(Some(time_left));
            }
        }

        Ok(None)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
        builder.add(glob);
    }

    Ok(Some(builder.build()?))
}

pub async fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_paths_empty() {
        let temp_dir = tempdir().unwrap();
        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(&[temp_dir.path().to_path_buf()], &[], false)
            .await
            .unwrap();

        assert_eq!(files.len(), 0);
    }

    #[tokio::test]
    async fn test_scan_paths_with_files() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(&[temp_dir.path().to_path_buf()], &[], false)
            .await
            .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, file_path);
        assert_eq!(files[0].size, 12);
    }

    #[tokio::test]
    async fn test_calculate_file_hash() -> Result<()> {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content")?;

        let hash = calculate_file_hash(&file_path).await?;
        assert_eq!(hash.len(), 64);
        Ok(())
    }

    #[test]
    fn test_build_globset() -> Result<()> {
        let patterns = vec!["*.tmp".to_string(), "cache/*".to_string()];

        let globset = build_globset(&patterns)?;
        assert!(globset.is_some());

        let globset = globset.unwrap();
        assert!(globset.is_match("test.tmp"));
        assert!(globset.is_match("cache/file.txt"));
        assert!(!globset.is_match("test.txt"));

        Ok(())
    }

    #[tokio::test]
    async fn test_create_and_validate_archive() -> Result<()> {
        let temp_dir = tempdir()?;

        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file1, "content 1")?;
        fs::write(&file2, "content 2")?;

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = vec![
            FileInfo {
                path: file1.clone(),
                size: 9,
                mtime: Utc::now(),
                hash: calculate_file_hash(&file1).await?,
                mode: None,
                #[cfg(unix)]
                uid: None,
                #[cfg(unix)]
                gid: None,
                is_symlink: false,
                symlink_target: None,
            },
            FileInfo {
                path: file2.clone(),
                size: 9,
                mtime: Utc::now(),
                hash: calculate_file_hash(&file2).await?,
                mode: None,
                #[cfg(unix)]
                uid: None,
                #[cfg(unix)]
                gid: None,
                is_symlink: false,
                symlink_target: None,
            },
        ];

        let archive_path = temp_dir.path().join("test.tar.gz");
        let size = engine.create_tar(&files, &archive_path, false).await?;

        assert!(archive_path.exists());
        assert!(size > 0);

        engine.validate_archive(&archive_path)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_scan_paths_with_exclude() -> Result<()> {
        let temp_dir = tempdir()?;

        let file1 = temp_dir.path().join("include.txt");
        let file2 = temp_dir.path().join("exclude.tmp");
        fs::write(&file1, "include")?;
        fs::write(&file2, "exclude")?;

        let storage = crate::storage::BackupStorage::new(temp_dir.path().to_str().unwrap());
        let config = Config::default();
        let engine = BackupEngine::new(storage, config).unwrap();

        let files = engine
            .scan_paths(
                &[temp_dir.path().to_path_buf()],
                &["*.tmp".to_string()],
                false,
            )
            .await?;

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path.file_name().unwrap(), "include.txt");
        Ok(())
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::config::{Config, CoreConfig, CryptoConfig};
    use crate::storage::BackupStorage;
    use tempfile::tempdir;
    use std::fs;
    use std::path::PathBuf;

    fn test_config(temp_root: &std::path::Path) -> Config {
        let backup_dir = temp_root.join("backups");
        let key_path = temp_root.join("master.key");
        let key = Crypto::generate_key();
        Crypto::save_key(&key, &key_path).unwrap();
        Config {
            core: CoreConfig {
                backup_dir: backup_dir.clone(),
                ..CoreConfig::default()
            },
            crypto: CryptoConfig {
                master_key_path: key_path,
                delete_plain: true,
                ..CryptoConfig::default()
            },
            ..Config::default()
        }
    }

    fn create_test_files(dir: &std::path::Path) -> Vec<PathBuf> {
        let file1 = dir.join("file1.txt");
        let file2 = dir.join("file2.txt");
        let subdir = dir.join("subdir");
        let file3 = subdir.join("file3.txt");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(&file1, b"content 1").unwrap();
        fs::write(&file2, b"content 2 with longer text").unwrap();
        fs::write(&file3, b"content 3 in subdir").unwrap();
        vec![file1, file2, file3]
    }

    async fn create_test_backup(
        engine: &BackupEngine,
        source_paths: Vec<PathBuf>,
        profile: &str,
    ) -> BackupResult {
        engine
            .create_backup(source_paths, vec![], Some(profile), false)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_verify_backup_quick_unencrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(result.is_ok());
        assert!(result.quick);
        assert!(result.archive_ok);
        assert!(result.decryption_ok);
        assert!(result.extraction_ok);
        assert_eq!(result.files_checked, 3);
        assert!(result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_full_unencrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(result.is_ok());
        assert!(!result.quick);
        assert_eq!(result.files_checked, 3);
        assert_eq!(result.files_matched, 3);
        assert!(result.files_missing.is_empty());
        assert!(result.files_corrupted.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_quick_encrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config)?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(result.is_ok());
        assert!(result.decryption_ok);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_full_encrypted() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage, config)?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(result.is_ok());
        assert_eq!(result.files_matched, 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_corrupted_archive() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");
        let mut archive = fs::OpenOptions::new().append(true).open(&archive_path)?;
        use std::io::Write;
        archive.write_all(b"CORRUPT")?;
        archive.sync_all()?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(!result.errors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_corrupted_file() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");

        let extract_dir = tempfile::tempdir()?;
        let file = fs::File::open(&archive_path)?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        archive.unpack(extract_dir.path())?;

        let file1_path = extract_dir.path().join("file1.txt");
        fs::write(&file1_path, b"MODIFIED CONTENT")?;

        let new_archive_path = backup_path.join("data.tar.gz.modified");
        let tar_file = fs::File::create(&new_archive_path)?;
        let encoder = flate2::write::GzEncoder::new(tar_file, flate2::Compression::default());
        let mut builder = Builder::new(encoder);
        builder.append_dir_all(".", extract_dir.path())?;
        builder.into_inner()?.finish()?;

        fs::remove_file(&archive_path)?;
        fs::rename(&new_archive_path, &archive_path)?;

        let result = engine.verify_backup(backup_id, false, false).await?;
        assert!(!result.is_ok());
        assert_eq!(result.files_corrupted.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_missing_manifest() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let manifest_path = backup_path.join("manifest.json");
        fs::remove_file(&manifest_path)?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.contains("Manifest")));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_missing_archive() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());
        let mut config_no_crypto = config.clone();
        config_no_crypto.crypto.master_key_path = PathBuf::from("/nonexistent");
        let storage = BackupStorage::new(&config_no_crypto.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config_no_crypto)?;

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let backup_path = storage.backup_path(backup_id);
        let archive_path = backup_path.join("data.tar.gz");
        fs::remove_file(&archive_path)?;

        let result = engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.contains("Archive not found")));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_backup_wrong_key() -> Result<()> {
        let temp_root = tempdir()?;
        let config = test_config(temp_root.path());

        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;
        let test_files = create_test_files(&source_dir);

        let storage = BackupStorage::new(&config.core.backup_dir.display().to_string());
        storage.init()?;
        let engine = BackupEngine::new(storage.clone(), config.clone())?;

        let backup_result = create_test_backup(&engine, test_files, "test-profile").await;
        let backup_id = &backup_result.id;

        let wrong_key_path = temp_root.path().join("wrong.key");
        let wrong_key = Crypto::generate_key();
        Crypto::save_key(&wrong_key, &wrong_key_path)?;
        let mut wrong_config = config;
        wrong_config.crypto.master_key_path = wrong_key_path;
        let wrong_engine = BackupEngine::new(storage, wrong_config)?;

        let result = wrong_engine.verify_backup(backup_id, true, false).await?;
        assert!(!result.is_ok());
        assert!(!result.decryption_ok);
        assert!(result.errors.iter().any(|e| e.contains("Decryption failed")));
        Ok(())
    }
}

#[cfg(test)]
mod interval_tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::BackupStorage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_check_interval_no_backups() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage, config)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(24))?;
        assert_eq!(result, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_check_interval_with_recent_backup() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let backup_info = BackupInfo {
            id: "test-backup".to_string(),
            backup_type: BackupType::Full,
            timestamp: Utc::now(),
            profile: "test-profile".to_string(),
            file_count: 0,
            size_encrypted: 0,
            checksum: None,
            encrypted: Some(false),
        };
        storage.write_local_index(&backup_info)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(1))?;
        assert!(result.is_some());
        assert!(result.unwrap() < Duration::hours(1));
        Ok(())
    }

    #[tokio::test]
    async fn test_check_interval_old_backup() -> Result<()> {
        let temp_dir = tempdir()?;
        let storage = BackupStorage::new(temp_dir.path().to_str().unwrap());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let old_time = Utc::now() - Duration::days(2);
        let backup_info = BackupInfo {
            id: "old-backup".to_string(),
            backup_type: BackupType::Full,
            timestamp: old_time,
            profile: "test-profile".to_string(),
            file_count: 0,
            size_encrypted: 0,
            checksum: None,
            encrypted: Some(false),
        };
        storage.write_local_index(&backup_info)?;

        let result = engine.check_backup_interval("test-profile", Duration::hours(24))?;
        assert_eq!(result, None);
        Ok(())
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::BackupStorage;
    use tempfile::tempdir;

    #[tokio::test]
    #[cfg(unix)]
    async fn test_backup_restore_symlink() -> Result<()> {
        use std::os::unix;

        let temp_root = tempdir()?;
        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;

        let real_file = source_dir.join("real.txt");
        fs::write(&real_file, "content")?;
        let symlink_path = source_dir.join("link.txt");
        unix::fs::symlink(&real_file, &symlink_path)?;

        let backup_dir = temp_root.path().join("backups");
        let storage = BackupStorage::new(&backup_dir.display().to_string());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage.clone(), config)?;

        let result = engine
            .create_backup(vec![source_dir.clone()], vec![], Some("test"), false)
            .await?;

        let restore_dir = temp_root.path().join("restore");
        engine
            .restore_backup(&result.id, &restore_dir, None, true, false)
            .await?;

        let restored_symlink = restore_dir.join("source").join("link.txt");
        assert!(restored_symlink.exists());
        assert!(restored_symlink
            .symlink_metadata()?
            .file_type()
            .is_symlink());

        let target = fs::read_link(&restored_symlink)?;
        let expected_target = restore_dir.join("source").join("real.txt");
        assert_eq!(target, expected_target);

        let restored_content = fs::read_to_string(&expected_target)?;
        assert_eq!(restored_content, "content");
        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_backup_restore_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_root = tempdir()?;
        let source_dir = temp_root.path().join("source");
        fs::create_dir_all(&source_dir)?;

        let file_path = source_dir.join("exec.sh");
        fs::write(&file_path, "#!/bin/sh\necho hello")?;

        let mut perms = fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&file_path, perms)?;

        let backup_dir = temp_root.path().join("backups");
        let storage = BackupStorage::new(&backup_dir.display().to_string());
        storage.init()?;
        let config = Config::default();
        let engine = BackupEngine::new(storage, config)?;

        let result = engine
            .create_backup(vec![file_path.clone()], vec![], Some("test"), false)
            .await?;

        let restore_dir = temp_root.path().join("restore");
        engine
            .restore_backup(&result.id, &restore_dir, None, true, false)
            .await?;

        let restored_file = restore_dir.join("exec.sh");
        assert!(restored_file.exists());

        let restored_mode = restored_file.metadata()?.permissions().mode();
        assert!(restored_mode & 0o111 != 0);
        assert_eq!(restored_mode & 0o777, 0o755);
        Ok(())
    }
}