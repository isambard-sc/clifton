// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};

/// The Clifton cache directory
pub fn cache_dir() -> Result<std::path::PathBuf> {
    Ok(dirs::cache_dir().unwrap_or(".".parse()?).join("clifton"))
}

/// Ensure that the cache directory exists, and return its path
fn ensure_cache_dir() -> Result<std::path::PathBuf> {
    let cache_dir = cache_dir()?;
    match cache_dir.try_exists() {
        Ok(true) => (),
        Ok(false) => {
            std::fs::create_dir_all(&cache_dir).context(format!(
                "Could not create cache directory `{}`.",
                cache_dir.display()
            ))?;
        }
        Err(err) => return Err(err).context("Cound not check for existence of cache directory."),
    };
    Ok(cache_dir)
}

/// Write a file to the cache, overwriting any existing file
pub fn write_file<P: AsRef<std::path::Path>, C: AsRef<[u8]>>(file: P, contents: C) -> Result<()> {
    let cache_dir = ensure_cache_dir()?;
    let path = cache_dir.join(file);
    let mut f = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        f = f.mode(0o600).clone(); // u=rw,g=,o=
    }
    f.write(true)
        .truncate(true)
        .create(true)
        .open(&path)
        .context(format!("Could not open cache file `{}`.", path.display()))?
        .write_all(contents.as_ref())
        .context("Could not write to cache.")?;
    Ok(())
}

/// Read a file from the cache
pub fn read_file<P: AsRef<std::path::Path>>(file: P) -> Result<String> {
    let cache_dir = cache_dir()?;
    let path = cache_dir.join(file);
    Ok(std::fs::read_to_string(path)?)
}

/// Delete a file from the cache
pub fn delete_file<P: AsRef<std::path::Path>>(file: P) -> Result<()> {
    let cache_dir = cache_dir()?;
    let path = cache_dir.join(file);
    std::fs::remove_file(&path)
        .context(format!("Could not delete cache file `{}`.", path.display()))
}

/// Delete the entire cache directory
pub fn delete_all() -> Result<()> {
    match std::fs::remove_dir_all(cache_dir()?) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
    .context(format!(
        "Could not delete cache directory `{}`.",
        cache_dir()?.display()
    ))
}
