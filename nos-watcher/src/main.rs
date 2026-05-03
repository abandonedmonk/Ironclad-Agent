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
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let release = PathBuf::from(format!("target/release/ironclad-agent{}", exe_suffix));
    if release.exists() {
        return release;
    }
    PathBuf::from(format!("target/debug/ironclad-agent{}", exe_suffix))
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
    // Cooldown after invoking the agent to avoid rate limiting (30s)
    let mut cooldown_until: Option<SystemTime> = None;

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

        // Skip if we're in cooldown after a recent agent invocation
        if let Some(until) = cooldown_until {
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                if let Ok(until_ts) = until.duration_since(std::time::UNIX_EPOCH) {
                    if now < until_ts {
                        continue;
                    }
                }
            }
            cooldown_until = None;
        }

        if is_new {
            println!("\n📂 Alert file changed — reading...");
            last_handled_mtime = Some(mtime);
            if let Err(e) = handle_alert() {
                eprintln!("❌ Error handling alert: {e}");
            }
            // Cooldown: ignore new alerts for 30s to avoid LLM rate limiting
            cooldown_until = Some(std::time::SystemTime::now() + Duration::from_secs(30));
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
        "These are SIMULATED metrics for testing — analyze the pattern, do NOT treat them as a real system problem. \
         Metric '{}' on process '{}' showed {} (anomaly score: {}, severity: {}). \
         Read /proc files (e.g., /proc/stat, /proc/meminfo, /proc/loadavg) to check current system resource usage, \
         compare with the simulated anomaly values, and explain the pattern. \
         Do NOT use subprocess, psutil, or os.system — they are not available in the WASM sandbox. \
         Use only open() to read /proc/ files and the standard library. \
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

    // 4. Run ironclad-agent as a subprocess and capture output.
    let bin = agent_bin();
    println!("🧠 Invoking {:?}...\n", bin);
    let output = std::process::Command::new(&bin)
        .arg(&task)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to launch agent at {:?}: {}", bin, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 5. Log agent output to audit trail.
    audit::write(
        &audit_path(),
        "AGENT_OUTPUT",
        &serde_json::json!({
            "exit_code": output.status.code().unwrap_or(-1),
            "stdout_preview": stdout.lines().take(20).collect::<Vec<_>>().join("\n"),
            "stderr": if stderr.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(stderr.to_string()) },
        }),
    )?;

    println!("\n{}", stdout);
    if !stderr.is_empty() {
        eprintln!("Agent stderr:\n{}", stderr);
    }
    println!("\n✅ Agent finished (exit {})", output.status.code().unwrap_or(-1));
    Ok(())
}
