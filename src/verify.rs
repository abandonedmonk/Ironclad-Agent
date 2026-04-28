use crate::audit::AuditEntry;
use crate::crypto;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn verify_script_execution(_script_path: &std::path::Path) -> std::io::Result<()> {
    let rehash = crypto::compute_script_sha256(_script_path)?;
    let file = File::open("audit.log")?;

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let entry: AuditEntry = serde_json::from_str(&line)?;

        if rehash == entry.script_hash {
            println!("Verified: executed at {}", entry.timestamp_iso8601);
            return Ok(());
        }
    }

    println!("NOT FOUND");
    Ok(())
}
