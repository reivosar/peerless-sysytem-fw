//! Partition-tolerant mutable documents backed by Automerge.

use automerge::{transaction::Transactable, AutoCommit, ObjId, ObjType, ReadDoc, ROOT};
use peerless_storage::{atomic_replace, read_limited};
use std::{
    fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use thiserror::Error;

const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyPolicy {
    Eventual,
    Strong,
    Immutable,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Automerge failed: {0}")]
    Automerge(#[from] automerge::AutomergeError),
    #[error("state value is not a string")]
    NotAString,
    #[error("state document exceeds the {MAX_DOCUMENT_BYTES} byte limit")]
    TooLarge,
}

pub struct StateStore {
    root: PathBuf,
    persistence_lock: Arc<Mutex<()>>,
    persistence_lock_path: PathBuf,
}

impl StateStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StateError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let persistence_lock_path = root.join(".persistence.lock");
        Ok(Self {
            root,
            persistence_lock: Arc::new(Mutex::new(())),
            persistence_lock_path,
        })
    }

    pub fn document(&self, name: &str) -> Result<StateDocument, StateError> {
        let path = self.root.join(format!("{}.automerge", safe_name(name)));
        let document = if path.exists() {
            AutoCommit::load(&read_bounded(&path)?)?
        } else {
            let mut document = AutoCommit::new();
            document.put_object(ROOT, "values", ObjType::Map)?;
            document
        };
        Ok(StateDocument {
            path,
            document,
            persistence_lock: Arc::clone(&self.persistence_lock),
            persistence_lock_path: self.persistence_lock_path.clone(),
        })
    }
    pub fn merge_snapshot(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        let path = self.root.join(format!("{}.automerge", safe_name(name)));
        ensure_bounded(bytes)?;
        let mut incoming = AutoCommit::load(bytes)?;
        let _guard = self
            .persistence_lock
            .lock()
            .expect("state persistence lock poisoned");
        let _file_guard = acquire_file_lock(&self.persistence_lock_path)?;
        if path.exists() {
            let mut current = AutoCommit::load(&read_bounded(&path)?)?;
            current.merge(&mut incoming)?;
            let merged = current.save();
            ensure_bounded(&merged)?;
            atomic_replace(&path, &merged, None)?;
        } else {
            atomic_replace(&path, bytes, None)?;
        }
        Ok(())
    }
}

pub struct StateDocument {
    path: PathBuf,
    document: AutoCommit,
    persistence_lock: Arc<Mutex<()>>,
    persistence_lock_path: PathBuf,
}

impl StateDocument {
    fn values(&self) -> ObjId {
        self.document
            .get(ROOT, "values")
            .expect("root lookup failed")
            .expect("values map missing")
            .1
    }

    pub fn put(&mut self, key: &str, value: &str) -> Result<(), StateError> {
        self.document.put(self.values(), key, value)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<String>, StateError> {
        let Some((value, _)) = self.document.get(self.values(), key)? else {
            return Ok(None);
        };
        value
            .to_str()
            .map(|value| Some(value.to_owned()))
            .ok_or(StateError::NotAString)
    }

    pub fn merge(&mut self, other: &mut Self) -> Result<(), StateError> {
        self.document.merge(&mut other.document)?;
        Ok(())
    }

    pub fn snapshot(&mut self) -> Vec<u8> {
        self.document.save()
    }

    pub fn merge_snapshot(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        ensure_bounded(bytes)?;
        let mut other = AutoCommit::load(bytes)?;
        self.document.merge(&mut other)?;
        Ok(())
    }

    pub fn save(&mut self) -> Result<(), StateError> {
        let _guard = self
            .persistence_lock
            .lock()
            .expect("state persistence lock poisoned");
        let _file_guard = acquire_file_lock(&self.persistence_lock_path)?;
        if self.path.exists() {
            let mut persisted = AutoCommit::load(&read_bounded(&self.path)?)?;
            self.document.merge(&mut persisted)?;
        }
        let bytes = self.document.save();
        ensure_bounded(&bytes)?;
        atomic_replace(&self.path, &bytes, None)?;
        Ok(())
    }
}

fn ensure_bounded(bytes: &[u8]) -> Result<(), StateError> {
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        Err(StateError::TooLarge)
    } else {
        Ok(())
    }
}

fn acquire_file_lock(path: &std::path::Path) -> Result<fs::File, StateError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()?;
    Ok(file)
}

fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, StateError> {
    read_limited(path, MAX_DOCUMENT_BYTES).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            StateError::TooLarge
        } else {
            StateError::Io(error)
        }
    })
}

fn safe_name(name: &str) -> String {
    name.as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                char::from(*byte).to_string()
            } else {
                format!("~{byte:02x}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    #[test]
    fn offline_partitions_converge_after_bidirectional_merge() {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let mut first = StateStore::open(first_root.path())
            .unwrap()
            .document("project")
            .unwrap();
        // Both replicas begin with the same document history, then partition.
        fs::write(
            second_root.path().join("project.automerge"),
            first.snapshot(),
        )
        .unwrap();
        let mut second = StateStore::open(second_root.path())
            .unwrap()
            .document("project")
            .unwrap();

        first.put("from-a", "one").unwrap();
        second.put("from-b", "two").unwrap();
        first.merge(&mut second).unwrap();
        let snapshot = first.snapshot();
        second.merge_snapshot(&snapshot).unwrap();

        for document in [&first, &second] {
            assert_eq!(document.get("from-a").unwrap().as_deref(), Some("one"));
            assert_eq!(document.get("from-b").unwrap().as_deref(), Some("two"));
        }
    }

    #[test]
    fn document_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let mut document = store.document("persistent").unwrap();
        document.put("name", "peerless").unwrap();
        document.save().unwrap();
        drop(document);
        assert_eq!(
            store
                .document("persistent")
                .unwrap()
                .get("name")
                .unwrap()
                .as_deref(),
            Some("peerless")
        );
    }

    #[test]
    fn distinct_and_hostile_document_names_never_alias() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let names = ["a/b", "a?b", "a~2fb", "../escape", "日本語", "a_b"];
        for (index, name) in names.iter().enumerate() {
            let mut document = store.document(name).unwrap();
            document.put("index", &index.to_string()).unwrap();
            document.save().unwrap();
        }
        for (index, name) in names.iter().enumerate() {
            assert_eq!(
                store.document(name).unwrap().get("index").unwrap(),
                Some(index.to_string())
            );
        }
        assert!(!root
            .path()
            .parent()
            .unwrap()
            .join("escape.automerge")
            .exists());
    }

    #[test]
    fn concurrent_stale_documents_merge_instead_of_losing_updates() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path()).unwrap();
        let mut seed = store.document("shared").unwrap();
        seed.put("seed", "present").unwrap();
        seed.save().unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(12));
        std::thread::scope(|scope| {
            for index in 0..12 {
                let root = root.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let store = StateStore::open(root).unwrap();
                    let mut document = store.document("shared").unwrap();
                    document.put(&format!("writer-{index}"), "present").unwrap();
                    barrier.wait();
                    document.save().unwrap();
                });
            }
        });

        let merged = store.document("shared").unwrap();
        assert_eq!(merged.get("seed").unwrap().as_deref(), Some("present"));
        for index in 0..12 {
            assert_eq!(
                merged.get(&format!("writer-{index}")).unwrap().as_deref(),
                Some("present")
            );
        }
    }

    #[test]
    fn oversized_persisted_document_is_rejected_before_allocation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("large.automerge");
        let mut file = fs::File::create(&path).unwrap();
        file.seek(std::io::SeekFrom::Start(MAX_DOCUMENT_BYTES))
            .unwrap();
        file.set_len(MAX_DOCUMENT_BYTES + 1).unwrap();
        let store = StateStore::open(root.path()).unwrap();
        assert!(matches!(store.document("large"), Err(StateError::TooLarge)));
    }
}
