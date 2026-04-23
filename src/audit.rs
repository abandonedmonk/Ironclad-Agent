use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::time::Instant;
use time;

/// One execution record in the audit log.
/// Serializes to a single JSON line in audit.log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// SHA-256 hash of the script file.
    pub script_hash: String,

    /// Execution timestamp in ISO 8601 format.
    pub timestamp_iso8601: String,

    /// Execution duration in milliseconds.
    pub duration_ms: u128,

    /// Exit code from sandbox (0 = success, non-zero = error).
    pub exit_code: i32,

    /// First 500 chars of stdout + stderr.
    pub output_preview: String,
}

/// Append one audit entry to audit.log as a JSON line.
/// Entries are immutable: opened in append-only mode so audit trail cannot be edited.
pub fn append_audit_entry(entry: &AuditEntry) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("audit.log")?;

    let json = serde_json::to_string(entry)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;

    Ok(())
}
