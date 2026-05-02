use crate::audit::AuditEntry;
use crate::crypto;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn verify_script_execution(_script_path: &std::path::Path) -> std::io::Result<()> {
    let rehash = crypto::compute_script_sha256(_script_path)?;
    
    let audit_path = std::path::PathBuf::from("scratch_repo/nos_audit.jsonl");

    if !audit_path.exists() {
        println!("Audit log not found at {:?}", audit_path);
        return Ok(());
    }

    let file = File::open(audit_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let entry: AuditEntry = serde_json::from_str(&line)?;

        if entry.event_type == "SANDBOX_RESULT" {
            if let Some(hash) = entry.detail.get("script_hash").and_then(|v| v.as_str()) {
                if hash == rehash {
                    println!("Verified: executed at {}", entry.timestamp);
                    return Ok(());
                }
            }
        }
    }

    println!("NOT FOUND");
    Ok(())
}
