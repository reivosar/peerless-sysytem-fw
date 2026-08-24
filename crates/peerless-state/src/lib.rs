//! Partition-tolerant mutable documents backed by Automerge.

use automerge::{transaction::Transactable, AutoCommit, ObjId, ObjType, ReadDoc, ROOT};
use std::{fs, io, path::PathBuf};
use thiserror::Error;

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
}

pub struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StateError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn document(&self, name: &str) -> Result<StateDocument, StateError> {
        let path = self.root.join(format!("{}.automerge", safe_name(name)));
        let document = if path.exists() {
            AutoCommit::load(&fs::read(&path)?)?
        } else {
            let mut document = AutoCommit::new();
            document.put_object(ROOT, "values", ObjType::Map)?;
            document
        };
        Ok(StateDocument { path, document })
    }
    pub fn merge_snapshot(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        let path = self.root.join(format!("{}.automerge", safe_name(name)));
        if !path.exists() {
            AutoCommit::load(bytes)?;
            fs::write(path, bytes)?;
            return Ok(());
        }
        let mut document = self.document(name)?;
        document.merge_snapshot(bytes)?;
        document.save()
    }
}

pub struct StateDocument {
    path: PathBuf,
    document: AutoCommit,
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
        let mut other = AutoCommit::load(bytes)?;
        self.document.merge(&mut other)?;
        Ok(())
    }

    pub fn save(&mut self) -> Result<(), StateError> {
        let bytes = self.document.save();
        let temporary = self.path.with_extension("automerge.tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
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
}
