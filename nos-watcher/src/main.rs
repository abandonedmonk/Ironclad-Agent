//! nos-watcher — Polls scratch_repo/nos_alert.json for changes and triggers the Ironclad agent.
//!
//! Uses POLLING (not OS file events) because WSL2 writes to Windows filesystem
//! paths (/mnt/d/...) do not trigger Windows file system change notifications.
//!
//! Build:  cargo build --release -p nos-watcher
//! Run:    ./target/release/nos-watcher  (from workspace root)

use anyhow::Result;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

// ── Path helpers ─────────────────────────────────────────────────────────────

fn alert_path() -> PathBuf {
    PathBuf::from("scratch_repo/nos_alert.json")
}

fn audit_path() -> PathBuf {
    PathBuf::from("scratch_repo/nos_audit.jsonl")
}

fn agent_bin() -> PathBuf {
    let release = PathBuf::from("target/release/ironclad-agent");
    if release.exists() {
        return release;
    }
    PathBuf::from("target/debug/ironclad-agent")
}

// ── Audit (hash-chained JSONL) ────────────────────────────────────────────────

mod audit {
    use chrono::Utc;
    use hex;
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Write, path::PathBuf};

    pub fn write(
        path: &PathBuf,
        event_type: &str,
        detail: &serde_json::Value,
    ) -> std::io::Result<()> {
        let (prev_hash, seq) = last_hash_and_seq(path);

        let mut entry = serde_json::json!({
            "seq":        seq,
            "timestamp":  Utc::now().to_rfc3339(),
            "prev_hash":  prev_hash,
            "event_type": event_type,
            "detail":     detail,
            "entry_hash": ""
        });

        let serialized = serde_json::to_string(&entry).unwrap();
        let hash = hex::encode(Sha256::digest(serialized.as_bytes()));
        entry["entry_hash"] = serde_json::Value::String(hash);

        let mut file = OpenOptions::new().append(true).create(true).open(path)?;
        writeln!(file, "{}", serde_json::to_string(&entry).unwrap())?;
        Ok(())
    }

    fn last_hash_and_seq(path: &PathBuf) -> (String, u64) {
        let zero = "0".repeat(64);
        if !path.exists() {
            return (zero, 0);
        }
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<&str> = content.trim_end().lines().collect();
        let seq = lines.len() as u64;
        let last_hash = lines
            .last()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| v["entry_hash"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "0".repeat(64));
        (last_hash, seq)
    }
}

// ── Main (polling loop) ───────────────────────────────────────────────────────

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let alert = alert_path();
    println!("👁  Polling {:?} for anomaly alerts (every 2s)...", alert);
    println!("    [WSL polling mode — bypasses Windows file event limitations]");
    println!("    Waiting for {:?} to appear...\n", alert);

    // Track the last modification time we handled
    let mut last_handled_mtime: Option<SystemTime> = None;

    loop {
        std::thread::sleep(Duration::from_secs(2));

        // Check if the alert file exists
        let metadata = match std::fs::metadata(&alert) {
            Ok(m) => m,
            Err(_) => {
                // File doesn't exist yet — print a dot so the user knows we're alive
                print!(".");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                continue;
            }
        };

        let mtime = match metadata.modified() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("⚠️  Could not read mtime: {e}");
                continue;
            }
        };

        // Only act if the file is newer than the last one we handled
        let is_new = match last_handled_mtime {
            None => true,
            Some(prev) => mtime > prev,
        };

        if is_new {
            println!("\n📂 Alert file changed — reading...");
            last_handled_mtime = Some(mtime);
            if let Err(e) = handle_alert() {
                eprintln!("❌ Error handling alert: {e}");
            }
        }
    }
}

fn handle_alert() -> Result<()> {
    let raw = std::fs::read_to_string(alert_path())?;
    println!("   Raw content: {}", &raw[..raw.len().min(120)]);

    let alert: serde_json::Value = serde_json::from_str(&raw)?;

    // 1. Log ANOMALY_DETECTED audit entry.
    audit::write(&audit_path(), "ANOMALY_DETECTED", &alert)?;
    println!("   ✅ Audit entry written to {:?}", audit_path());

    println!("\n🔴 ANOMALY DETECTED");
    println!("   Process : {}", alert["process"]);
    println!("   Metric  : {} = {}", alert["metric"], alert["observed_value"]);
    println!("   Score   : {} | Severity: {}\n", alert["anomaly_score"], alert["severity"]);

    // 2. Build a task string for the agent.
    let task = format!(
        "A system anomaly was detected: metric '{}' on process '{}' showed {} \
         (anomaly score: {}, severity: {}). \
         Write a Python script to diagnose this. Use the os and subprocess modules \
         to check system resource usage (CPU, memory, open file descriptors). \
         Print a clear summary of findings.",
        alert["metric"],
        alert["process"],
        alert["observed_value"],
        alert["anomaly_score"],
        alert["severity"]
    );

    // 3. Log AGENT_REASONING start entry.
    audit::write(
        &audit_path(),
        "AGENT_REASONING",
        &serde_json::json!({
            "step": "Agent received anomaly alert, beginning diagnosis"
        }),
    )?;

    // 4. Run ironclad-agent as a subprocess.
    let bin = agent_bin();
    println!("🧠 Invoking {:?}...\n", bin);
    let status = std::process::Command::new(&bin)
        .arg(&task)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch agent at {:?}: {}", bin, e))?;

    println!("\n✅ Agent finished (exit {})", status.code().unwrap_or(-1));
    Ok(())
}
