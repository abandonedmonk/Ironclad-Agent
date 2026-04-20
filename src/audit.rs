use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::time::Instant;
use time;

/// One execution record in the audit log.
/// Serializes to a single JSON line in audit.log.
#[derive(Debug, Clone, Serialize)]
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
///
/// This function must:
/// 1. Open audit.log in append mode (file stays open, new lines added without editing old ones)
/// 2. Serialize entry to JSON
/// 3. Write JSON + newline to file
/// 4. Return Ok(()) or propagate io::Error
///
/// Why append-only matters:
/// - No entry can be edited or deleted after it's written
/// - This creates an immutable audit trail
/// - Verification in Step 14 will scan this log to prove execution
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
