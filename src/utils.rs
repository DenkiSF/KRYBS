// src/utils.rs

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use streebog::{Digest, Streebog256};

/// Строит GlobSet из списка паттернов исключения.
pub fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
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

/// Синхронное вычисление хеша файла по ГОСТ Р 34.11-2012 (Стрибог, 256 бит).
pub fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;

    let mut hasher = Streebog256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Находит общий префикс двух путей.
pub fn common_prefix(a: &Path, b: &Path) -> PathBuf {
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

/// Находит общий корневой каталог для списка путей.
pub fn find_common_root(paths: &[PathBuf]) -> Result<PathBuf> {
    if paths.is_empty() {
        anyhow::bail!("No paths to find common root");
    }

    let mut common = paths[0].parent().unwrap_or(&paths[0]).to_path_buf();
    for path in paths.iter().skip(1) {
        common = common_prefix(&common, path);
        if common.as_os_str().is_empty() {
            common = path.parent().unwrap_or(path).to_path_buf();
        }
    }

    if !common.is_absolute() {
        common = std::env::current_dir()?.join(common);
    }
    Ok(common)
}

/// Преобразует байты в человекочитаемый формат (B, KB, MB, GB, TB).
pub fn bytes_to_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2}{}", size, UNITS[unit_idx])
}

/// Преобразует человекочитаемый размер обратно в байты (например, "1.5MB" -> 1572864).
pub fn human_to_bytes(human: &str) -> Option<u64> {
    let human = human.trim().to_lowercase();
    let units = [
        ("tb", 1024u64.pow(4)),
        ("gb", 1024u64.pow(3)),
        ("mb", 1024u64.pow(2)),
        ("kb", 1024u64),
        ("b", 1),
    ];

    for (unit, multiplier) in units {
        if human.ends_with(unit) {
            let num_str = &human[..human.len() - unit.len()];
            if let Ok(num) = num_str.trim().parse::<f64>() {
                return Some((num * multiplier as f64) as u64);
            }
        }
    }

    human.parse::<u64>().ok()
}