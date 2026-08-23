use peerless_compute::PeerReputation;
use peerless_core::{NodeId, Task};
use peerless_protocol::SignedExecutionRecord;
use rusqlite::{params, Connection};
use std::{path::Path, sync::Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("metadata database failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("metadata JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct Metadata {
    connection: Mutex<Connection>,
}

impl Metadata {
    pub fn open(path: &Path) -> Result<Self, MetadataError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp INTEGER NOT NULL,
               kind TEXT NOT NULL,
               details TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tasks (
               task_id TEXT PRIMARY KEY,
               state TEXT NOT NULL,
               executor TEXT,
               updated_at INTEGER NOT NULL,
               requester_json TEXT,
               task_json TEXT,
               result_json TEXT
             );
             CREATE TABLE IF NOT EXISTS peers (
               peer_id TEXT PRIMARY KEY,
               node_id TEXT NOT NULL,
               addresses TEXT NOT NULL,
               last_seen INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS reputation (
               node_id TEXT PRIMARY KEY,
               success INTEGER NOT NULL DEFAULT 0,
               failure INTEGER NOT NULL DEFAULT 0,
               invalid_result INTEGER NOT NULL DEFAULT 0,
               timeout INTEGER NOT NULL DEFAULT 0,
               average_latency_ms REAL NOT NULL DEFAULT 0
             );",
        )?;
        for migration in [
            "ALTER TABLE tasks ADD COLUMN requester_json TEXT",
            "ALTER TABLE tasks ADD COLUMN task_json TEXT",
            "ALTER TABLE tasks ADD COLUMN result_json TEXT",
        ] {
            let _ = connection.execute(migration, []);
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn event(&self, timestamp: u64, kind: &str, details: &str) -> Result<(), MetadataError> {
        self.connection
            .lock()
            .expect("metadata lock poisoned")
            .execute(
                "INSERT INTO events(timestamp, kind, details) VALUES (?1, ?2, ?3)",
                params![timestamp as i64, kind, details],
            )?;
        Ok(())
    }

    pub fn task(
        &self,
        task_id: &str,
        state: &str,
        executor: Option<&NodeId>,
        at: u64,
    ) -> Result<(), MetadataError> {
        self.connection.lock().expect("metadata lock poisoned").execute(
            "INSERT INTO tasks(task_id, state, executor, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(task_id) DO UPDATE SET state=excluded.state, executor=excluded.executor, updated_at=excluded.updated_at",
            params![task_id, state, executor.map(ToString::to_string), at as i64],
        )?;
        Ok(())
    }

    pub fn reputation(&self, node: &NodeId) -> Result<PeerReputation, MetadataError> {
        let connection = self.connection.lock().expect("metadata lock poisoned");
        let mut statement = connection.prepare("SELECT success, failure, invalid_result, timeout, average_latency_ms FROM reputation WHERE node_id=?1")?;
        match statement.query_row([node.to_string()], |row| {
            Ok(PeerReputation {
                success: row.get::<_, i64>(0)? as u64,
                failure: row.get::<_, i64>(1)? as u64,
                invalid_result: row.get::<_, i64>(2)? as u64,
                timeout: row.get::<_, i64>(3)? as u64,
                average_latency_ms: row.get(4)?,
            })
        }) {
            Ok(value) => Ok(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(PeerReputation::default()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn completed_task(
        &self,
        task: &Task,
        requester: &NodeId,
        result: &SignedExecutionRecord,
        at: u64,
    ) -> Result<(), MetadataError> {
        self.connection.lock().expect("metadata lock poisoned").execute(
            "INSERT INTO tasks(task_id, state, executor, updated_at, requester_json, task_json, result_json)
             VALUES (?1, 'completed', ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(task_id) DO UPDATE SET state='completed', executor=excluded.executor,
             updated_at=excluded.updated_at, requester_json=excluded.requester_json,
             task_json=excluded.task_json, result_json=excluded.result_json",
            params![
                task.task_id,
                result.record.executor.to_string(),
                at as i64,
                serde_json::to_string(requester)?,
                serde_json::to_string(task)?,
                serde_json::to_string(result)?,
            ],
        )?;
        Ok(())
    }

    pub fn completed_tasks(
        &self,
    ) -> Result<Vec<(Task, NodeId, SignedExecutionRecord)>, MetadataError> {
        let connection = self.connection.lock().expect("metadata lock poisoned");
        let mut statement = connection.prepare(
            "SELECT task_json, requester_json, result_json FROM tasks
             WHERE state='completed' AND task_json IS NOT NULL AND requester_json IS NOT NULL AND result_json IS NOT NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut completed = Vec::new();
        for row in rows {
            let (task, requester, result) = row?;
            completed.push((
                serde_json::from_str(&task)?,
                serde_json::from_str(&requester)?,
                serde_json::from_str(&result)?,
            ));
        }
        Ok(completed)
    }

    pub fn peer(
        &self,
        peer_id: &str,
        node: &NodeId,
        addresses: &str,
        at: u64,
    ) -> Result<(), MetadataError> {
        self.connection.lock().expect("metadata lock poisoned").execute(
            "INSERT INTO peers(peer_id, node_id, addresses, last_seen) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_id) DO UPDATE SET node_id=excluded.node_id, addresses=excluded.addresses, last_seen=excluded.last_seen",
            params![peer_id, node.to_string(), addresses, at as i64],
        )?;
        Ok(())
    }

    pub fn peer_count(&self) -> Result<u64, MetadataError> {
        Ok(self
            .connection
            .lock()
            .expect("metadata lock poisoned")
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get::<_, i64>(0))?
            as u64)
    }

    pub fn record_success(&self, node: &NodeId, latency_ms: f64) -> Result<(), MetadataError> {
        self.connection.lock().expect("metadata lock poisoned").execute(
            "INSERT INTO reputation(node_id, success, average_latency_ms) VALUES (?1, 1, ?2)
             ON CONFLICT(node_id) DO UPDATE SET
               average_latency_ms=((reputation.average_latency_ms * reputation.success) + excluded.average_latency_ms) / (reputation.success + 1),
               success=reputation.success + 1",
            params![node.to_string(), latency_ms],
        )?;
        Ok(())
    }

    pub fn record_failure(
        &self,
        node: &NodeId,
        invalid: bool,
        timeout: bool,
    ) -> Result<(), MetadataError> {
        let statement = if invalid {
            "INSERT INTO reputation(node_id, invalid_result) VALUES (?1, 1)
             ON CONFLICT(node_id) DO UPDATE SET invalid_result=reputation.invalid_result + 1"
        } else if timeout {
            "INSERT INTO reputation(node_id, timeout) VALUES (?1, 1)
             ON CONFLICT(node_id) DO UPDATE SET timeout=reputation.timeout + 1"
        } else {
            "INSERT INTO reputation(node_id, failure) VALUES (?1, 1)
             ON CONFLICT(node_id) DO UPDATE SET failure=reputation.failure + 1"
        };
        self.connection
            .lock()
            .expect("metadata lock poisoned")
            .execute(statement, [node.to_string()])?;
        Ok(())
    }

    pub fn counts(&self) -> Result<(u64, u64), MetadataError> {
        let connection = self.connection.lock().expect("metadata lock poisoned");
        let events = connection.query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })? as u64;
        let tasks = connection
            .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get::<_, i64>(0))?
            as u64;
        Ok((events, tasks))
    }
}
