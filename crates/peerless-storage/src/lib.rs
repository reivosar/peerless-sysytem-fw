//! Local, verified filesystem content-addressed storage.

use peerless_core::ContentId;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

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

        let temporary = parent.join(format!(".{}.{}.tmp", id.hex_digest(), std::process::id()));
        fs::write(&temporary, bytes)?;
        match fs::rename(&temporary, &path) {
            Ok(()) => Ok(id),
            Err(_error) if path.exists() => {
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
}
