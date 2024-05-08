use dashmap::DashMap;
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use thiserror::Error;
use walkdir::WalkDir;

pub const INFECTED_HASHES: &[&str] = &[
    "179b5da318604f97616b5108f305e2a8e4609484",
    "1a1c4dcae846866c58cc1abf71fb7f7aa4e7352a",
    "e4d55310039b965fce6756da5286b481cfb09946",
    "2f47e57a6bedc729359ffaf6f0149876008b5cc3",
    "2f47e57a6bedc729359ffaf6f0149876008b5cc3",
];

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO Error: {0}")]
    IO(#[from] std::io::Error),
    #[error("WalkDir Error: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("Error joining tasks")]
    JoinError,
}

pub fn compute_file_hashes(
    dir: &Path,
    scanned_file_count: Arc<AtomicI32>,
    discovered_file_count: Arc<AtomicI32>,
) -> Result<DashMap<String, PathBuf>, ScanError> {
    let hashes = Arc::new(DashMap::new());
    let mut handles = vec![];

    for entry in WalkDir::new(dir).follow_links(true) {
        let entry = entry?;

        if entry.path().is_file() {
            discovered_file_count.fetch_add(1, Ordering::Relaxed);

            let hashes_clone = hashes.clone();
            let scanned_file_count = scanned_file_count.clone();
            let handle = std::thread::spawn(move || {
                if let Ok(hash) = compute_file_sha1(entry.path()) {
                    hashes_clone.insert(hash, entry.path().to_path_buf());

                    scanned_file_count.fetch_add(1, Ordering::Relaxed);
                }
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().map_err(|_| ScanError::JoinError)?;
    }

    Ok(Arc::try_unwrap(hashes).unwrap())
}

fn compute_file_sha1(file_path: &Path) -> Result<String, ScanError> {
    const BUFFER_SIZE: usize = 1024 * 1024; // 1 MB buffer size

    let mut file = File::open(file_path)?;
    let mut hasher = Sha1::new();
    let mut buffer = vec![0; BUFFER_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of file
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn remove_files(paths: Vec<PathBuf>) -> Result<(), ScanError> {
    for file in paths {
        if file.exists() {
            std::fs::remove_file(file)?;
        }
    }

    Ok(())
}
