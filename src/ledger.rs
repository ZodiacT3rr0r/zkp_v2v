//! SQLite-backed tamper-evident hash-chained audit ledger for ZKP proof records.
//!
//! Every proof generated or verified by the CLI is appended to `audit_log` with:
//!   entry_hash = SHA-256("V2V_AUDIT_v1" || prev_hash || timestamp || actor || action || proof_json)
//! Modifying or deleting any historical row breaks the cryptographic chain, detected by `verify_chain()`.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_DOMAIN_TAG: &[u8] = b"V2V_AUDIT_v1";

/// A single tamper-evident audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub proof_json: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

fn compute_entry_hash(
    prev_hash: &str,
    timestamp: &str,
    actor: &str,
    action: &str,
    proof_json: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN_TAG);
    for field in [prev_hash, timestamp, actor, action, proof_json] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// SQLite-backed hash-chained audit ledger.
pub struct AuditLedger {
    conn: Connection,
}

impl AuditLedger {
    /// Open (or create) a tamper-evident audit ledger at the given path.
    ///
    /// Use `":memory:"` for an in-memory DB (useful for testing).
    pub fn new(path: &str) -> Result<Self, String> {
        let conn =
            Connection::open(path).map_err(|e| format!("Failed to open ledger DB: {}", e))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                actor      TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                proof_json TEXT    NOT NULL,
                prev_hash  TEXT    NOT NULL DEFAULT '',
                entry_hash TEXT    NOT NULL DEFAULT ''
            );",
        )
        .map_err(|e| format!("Failed to create table: {}", e))?;

        // Backwards-compatible migration for legacy DBs lacking hash-chain columns.
        let _ = conn.execute(
            "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''",
            [],
        );

        Ok(Self { conn })
    }

    /// Log a proof to the hash-chained audit ledger.
    ///
    /// Returns the row ID of the inserted entry.
    pub fn log_proof(
        &self,
        actor: &str,
        action: &str,
        proof_json: &str,
    ) -> Result<i64, String> {
        let timestamp: String = self
            .conn
            .query_row("SELECT datetime('now')", [], |row| row.get(0))
            .map_err(|e| format!("Failed to fetch timestamp: {}", e))?;

        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("Failed to fetch previous hash: {}", e))?
            .filter(|h: &String| !h.is_empty())
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let entry_hash =
            compute_entry_hash(&prev_hash, &timestamp, actor, action, proof_json);

        self.conn
            .execute(
                "INSERT INTO audit_log (timestamp, actor, action, proof_json, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![timestamp, actor, action, proof_json, prev_hash, entry_hash],
            )
            .map_err(|e| format!("Failed to insert: {}", e))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Verify the integrity of the entire SHA-256 hash chain from genesis.
    /// Returns Ok(true) if every entry matches its expected prev_hash and entry_hash,
    /// or Ok(false) if any row was modified, reordered, or deleted.
    pub fn verify_chain(&self) -> Result<bool, String> {
        let entries = self.get_all_proofs()?;
        let mut expected_prev = GENESIS_HASH.to_string();

        for entry in entries {
            if entry.prev_hash != expected_prev {
                return Ok(false);
            }
            let expected_hash = compute_entry_hash(
                &entry.prev_hash,
                &entry.timestamp,
                &entry.actor,
                &entry.action,
                &entry.proof_json,
            );
            if entry.entry_hash != expected_hash {
                return Ok(false);
            }
            expected_prev = entry.entry_hash;
        }
        Ok(true)
    }

    /// Retrieve all audit entries for a given actor.
    pub fn get_proofs_by_actor(&self, actor: &str) -> Result<Vec<AuditEntry>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, actor, action, proof_json, prev_hash, entry_hash
                 FROM audit_log WHERE actor = ?1 ORDER BY id",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let entries = stmt
            .query_map(params![actor], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    proof_json: row.get(4)?,
                    prev_hash: row.get(5)?,
                    entry_hash: row.get(6)?,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Row read failed: {}", e))?;

        Ok(entries)
    }

    /// Retrieve all audit entries.
    pub fn get_all_proofs(&self) -> Result<Vec<AuditEntry>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, actor, action, proof_json, prev_hash, entry_hash
                 FROM audit_log ORDER BY id",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let entries = stmt
            .query_map([], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    proof_json: row.get(4)?,
                    prev_hash: row.get(5)?,
                    entry_hash: row.get(6)?,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Row read failed: {}", e))?;

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_insert_and_retrieve() {
        let ledger = AuditLedger::new(":memory:").expect("open");
        let id = ledger
            .log_proof("consumer_1", "commit_consumer", r#"{"cid":1}"#)
            .expect("insert");
        assert!(id > 0, "row ID must be positive");

        let all = ledger.get_all_proofs().expect("get_all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].actor, "consumer_1");
        assert_eq!(all[0].action, "commit_consumer");
        assert_eq!(all[0].proof_json, r#"{"cid":1}"#);
        assert!(!all[0].timestamp.is_empty(), "timestamp must be set");
        assert_eq!(all[0].prev_hash, GENESIS_HASH);
        assert_eq!(all[0].entry_hash.len(), 64);
        assert!(ledger.verify_chain().expect("verify"), "fresh chain must verify");
    }

    #[test]
    fn test_ledger_by_actor() {
        let ledger = AuditLedger::new(":memory:").expect("open");
        ledger
            .log_proof("consumer_1", "commit", r#"{"a":1}"#)
            .expect("insert");
        ledger
            .log_proof("provider_10", "commit", r#"{"b":2}"#)
            .expect("insert");
        ledger
            .log_proof("consumer_1", "verify", r#"{"a":3}"#)
            .expect("insert");

        let c1 = ledger.get_proofs_by_actor("consumer_1").expect("query");
        assert_eq!(c1.len(), 2);
        assert_eq!(c1[0].action, "commit");
        assert_eq!(c1[1].action, "verify");

        let p10 = ledger.get_proofs_by_actor("provider_10").expect("query");
        assert_eq!(p10.len(), 1);
        assert!(ledger.verify_chain().expect("verify"));
    }

    #[test]
    fn test_ledger_empty() {
        let ledger = AuditLedger::new(":memory:").expect("open");
        let all = ledger.get_all_proofs().expect("get_all");
        assert!(all.is_empty(), "new ledger must be empty");

        let by_actor = ledger
            .get_proofs_by_actor("nobody")
            .expect("by_actor");
        assert!(by_actor.is_empty(), "unknown actor must return empty");
        assert!(ledger.verify_chain().expect("verify"));
    }

    #[test]
    fn test_ledger_multiple_actors() {
        let ledger = AuditLedger::new(":memory:").expect("open");
        for i in 0..5 {
            let actor = format!("vehicle_{}", i);
            ledger
                .log_proof(&actor, "commit", &format!(r#"{{"id":{}}}"#, i))
                .expect("insert");
        }
        let all = ledger.get_all_proofs().expect("get_all");
        assert_eq!(all.len(), 5);
        assert!(ledger.verify_chain().expect("verify"));

        for i in 0..5 {
            let actor = format!("vehicle_{}", i);
            let entries = ledger.get_proofs_by_actor(&actor).expect("by_actor");
            assert_eq!(entries.len(), 1);
        }
    }

    #[test]
    fn test_ledger_detects_tampering() {
        let ledger = AuditLedger::new(":memory:").expect("open");
        ledger
            .log_proof("consumer_1", "commit_consumer", r#"{"cid":1}"#)
            .expect("insert 1");
        ledger
            .log_proof("provider_2", "prove_profit", r#"{"pid":2}"#)
            .expect("insert 2");
        assert!(ledger.verify_chain().expect("valid before tamper"));

        // Tamper with row 1's proof_json directly in SQLite
        ledger
            .conn
            .execute(
                "UPDATE audit_log SET proof_json = ?1 WHERE id = 1",
                params![r#"{"cid":999}"#],
            )
            .expect("tamper");
        assert!(
            !ledger.verify_chain().expect("verify after tamper"),
            "hash chain must detect retroactive tampering"
        );
    }
}
