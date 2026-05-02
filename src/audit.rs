//! Hash-chained append-only audit log.
//! Each entry's SHA-256 covers the entry without `entry_hash` populated,
//! then stores the hash inside — creating a tamper-evident chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

// Event type constants — use these everywhere, never raw strings.
pub const ANOMALY_DETECTED: &str = "ANOMALY_DETECTED";
pub const AGENT_REASONING:  &str = "AGENT_REASONING";
pub const SCRIPT_SUBMITTED: &str = "SCRIPT_SUBMITTED";
pub const SANDBOX_RESULT:   &str = "SANDBOX_RESULT";
pub const AGENT_SUMMARY:    &str = "AGENT_SUMMARY";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq:        u64,
    pub timestamp:  String,
    pub prev_hash:  String,
    pub event_type: String,
    pub detail:     serde_json::Value,
    pub entry_hash: String,
}

fn audit_path() -> PathBuf {
    PathBuf::from("scratch_repo/nos_audit.jsonl")
}

fn last_hash_and_seq() -> (String, u64) {
    let path = audit_path();
    if !path.exists() { return ("0".repeat(64), 0); }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = content.trim_end().lines().collect();
    let seq = lines.len() as u64;
    let last_hash = lines.last()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["entry_hash"].as_str().map(String::from))
        .unwrap_or_else(|| "0".repeat(64));
    (last_hash, seq)
}

/// Append one hash-chained audit entry to /tmp/nos_audit.jsonl.
pub fn append_audit_entry(event_type: &str, detail: serde_json::Value) -> std::io::Result<()> {
    let (prev_hash, seq) = last_hash_and_seq();

    let mut entry = AuditEntry {
        seq,
        timestamp:  time::OffsetDateTime::now_utc().to_string(),
        prev_hash,
        event_type: event_type.to_string(),
        detail,
        entry_hash: String::new(),
    };

    // Hash entry without entry_hash, then store hash.
    let serialized = serde_json::to_string(&entry).unwrap();
    entry.entry_hash = hex::encode(Sha256::digest(serialized.as_bytes()));

    let mut file = OpenOptions::new()
        .append(true).create(true)
        .open(audit_path())?;
    writeln!(file, "{}", serde_json::to_string(&entry).unwrap())?;
    Ok(())
}
