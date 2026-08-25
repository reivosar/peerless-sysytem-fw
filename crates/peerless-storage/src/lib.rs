//! Local, verified filesystem content-addressed storage.

use peerless_core::ContentId;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Reads at most `limit` bytes and reports `InvalidData` instead of allocating
/// an attacker-controlled file in full. The bound remains effective if the
/// file grows after it is opened.
pub fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(limit.min(64 * 1024)).unwrap_or(64 * 1024));
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} byte limit"),
        ))
    } else {
        Ok(bytes)
    }
}

/// Atomically replaces a regular file without ever exposing a partial write.
///
/// Temporary files are unique and created with `O_EXCL`; `mode` is applied at
/// creation time on Unix so private data is never briefly world-readable.
pub fn atomic_replace(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let (temporary, mut file) = unique_temporary(parent, path.file_name(), mode)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_directory(parent)
}

/// Atomically creates a new file and refuses to replace an existing one.
pub fn atomic_create(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let (temporary, mut file) = unique_temporary(parent, path.file_name(), mode)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary)?;
            sync_directory(parent)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

fn unique_temporary(
    parent: &Path,
    file_name: Option<&std::ffi::OsStr>,
    mode: Option<u32>,
) -> io::Result<(PathBuf, fs::File)> {
    let name = file_name
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("data");
    loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.{}.{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CasError {
    #[error("content {0} was not found")]
    NotFound(ContentId),
    #[error("stored content does not match its identifier: {0}")]
    Corrupt(ContentId),
    #[error("CAS I/O failed: {0}")]
    Io(#[from] io::Error),
}

pub struct FileCas {
    root: PathBuf,
}

impl FileCas {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<ContentId, CasError> {
        let id = ContentId::of(bytes);
        let path = self.path_for(id);
        if path.exists() {
            self.verify_existing(id, &path)?;
            return Ok(id);
        }
        let parent = path.parent().expect("CAS paths always have a parent");
        fs::create_dir_all(parent)?;

        let (temporary, mut file) = loop {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                ".{}.{}.{sequence}.tmp",
                id.hex_digest(),
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => break (candidate, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(file);
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {
                fs::remove_file(&temporary)?;
                Ok(id)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary);
                self.verify_existing(id, &path)?;
                Ok(id)
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                Err(error.into())
            }
        }
    }

    pub fn get(&self, id: ContentId) -> Result<Vec<u8>, CasError> {
        let path = self.path_for(id);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CasError::NotFound(id))
            }
            Err(error) => return Err(error.into()),
        };
        if !id.verify(&bytes) {
            return Err(CasError::Corrupt(id));
        }
        Ok(bytes)
    }

    pub fn contains(&self, id: ContentId) -> bool {
        self.path_for(id).is_file()
    }

    pub fn stats(&self) -> Result<(u64, u64), CasError> {
        let mut objects = 0u64;
        let mut bytes = 0u64;
        for prefix in fs::read_dir(&self.root)? {
            let prefix = prefix?;
            if !prefix.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(prefix.path())? {
                let entry = entry?;
                if entry.file_type()?.is_file()
                    && !entry.file_name().to_string_lossy().starts_with('.')
                {
                    objects += 1;
                    bytes += entry.metadata()?.len();
                }
            }
        }
        Ok((objects, bytes))
    }

    fn verify_existing(&self, id: ContentId, path: &Path) -> Result<(), CasError> {
        let bytes = fs::read(path)?;
        if id.verify(&bytes) {
            Ok(())
        } else {
            Err(CasError::Corrupt(id))
        }
    }

    fn path_for(&self, id: ContentId) -> PathBuf {
        let digest = id.hex_digest();
        self.root.join(&digest[..2]).join(&digest[2..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn put_is_idempotent_and_get_verifies_content() {
        let directory = tempfile::tempdir().unwrap();
        let cas = FileCas::open(directory.path()).unwrap();
        let first = cas.put(b"immutable").unwrap();
        let second = cas.put(b"immutable").unwrap();
        assert_eq!(first, second);
        assert_eq!(cas.get(first).unwrap(), b"immutable");
    }

    #[test]
    fn missing_content_is_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let cas = FileCas::open(directory.path()).unwrap();
        assert!(matches!(
            cas.get(ContentId::of(b"absent")),
            Err(CasError::NotFound(_))
        ));
    }

    #[test]
    fn corrupted_content_is_never_returned_or_silently_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let cas = FileCas::open(directory.path()).unwrap();
        let id = cas.put(b"authentic").unwrap();
        fs::write(cas.path_for(id), b"corrupt").unwrap();
        assert!(matches!(cas.get(id), Err(CasError::Corrupt(found)) if found == id));
        assert!(matches!(cas.put(b"authentic"), Err(CasError::Corrupt(found)) if found == id));
    }

    #[test]
    fn concurrent_idempotent_puts_leave_one_complete_object() {
        let directory = tempfile::tempdir().unwrap();
        let cas = Arc::new(FileCas::open(directory.path()).unwrap());
        let barrier = Arc::new(Barrier::new(16));
        let threads = (0..16)
            .map(|_| {
                let cas = Arc::clone(&cas);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cas.put(b"concurrent immutable object")
                })
            })
            .collect::<Vec<_>>();
        let ids = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(cas.get(ids[0]).unwrap(), b"concurrent immutable object");
        assert_eq!(cas.stats().unwrap(), (1, 27));
    }

    #[test]
    fn concurrent_atomic_replacements_never_expose_partial_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metadata");
        let barrier = Arc::new(Barrier::new(16));
        let expected = (0..16)
            .map(|index| format!("writer-{index}:{}", "x".repeat(4096)).into_bytes())
            .collect::<Vec<_>>();
        std::thread::scope(|scope| {
            for payload in &expected {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                scope.spawn(move || {
                    barrier.wait();
                    atomic_replace(&path, payload, Some(0o600)).unwrap();
                });
            }
        });
        assert!(expected.contains(&fs::read(path).unwrap()));
        assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn limited_read_stops_at_the_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("untrusted");
        fs::write(&path, vec![7; 1025]).unwrap();
        assert_eq!(read_limited(&path, 1025).unwrap().len(), 1025);
        assert_eq!(
            read_limited(&path, 1024).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
