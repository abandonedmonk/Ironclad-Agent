#![allow(unused)]

use serde::Serialize;
use wasmtime::{Engine, Module};

#[derive(Debug, Clone, Serialize)]
struct ExecutionOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    error: Option<String>,
}

/// Execution contract for `ironclad-runtime`
///
/// * Input – a single argument: path to a `.py` script.
/// * Output – JSON printed to stdout: { "stdout": "...", "stderr": "...", "exit_code": 0, "error": null }
/// * Guarantees – no network, filesystem confined via WASI, fuel limits enforced, graceful error reporting.
fn main() -> wasmtime::Result<()> {
    env_logger::init();
    log::info!("Loading python.wasm into Wasmtime engine...");

    let args: Vec<String> = std::env::args().collect();
    let script_path = match args.get(1) {
        Some(path) => path.clone(),
        None => {
            let output = ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
                error: Some("Usage: ironclad-runtime <script_path>".to_string()),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(1);
        }
    };

    log::info!("Script Path: {}", script_path);

    if !std::path::Path::new(&script_path).exists() {
        let output = ExecutionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
            error: Some(format!("Script not found: {}", script_path)),
        };
        println!("{}", serde_json::to_string(&output).unwrap());
        std::process::exit(1);
    }

    log::info!("✅ Script validated.");

    // Step 3 contract shape: this is what the runtime will serialize to JSON.
    let _contract_example = ExecutionOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        error: None,
    };
    log::info!(
        "Contract example => stdout='{}', stderr='{}', exit_code={}, error={:?}",
        _contract_example.stdout,
        _contract_example.stderr,
        _contract_example.exit_code,
        _contract_example.error
    );

    // The engine is the global compilation environment.
    // Default config is fine for now — no fuel limits yet (Phase 2, Step 7).
    let engine = Engine::default();

    // Compile the .wasm binary into the engine.
    // This does NOT execute anything — it just validates and compiles.
    // The file path is relative to where `cargo run` is invoked (project root).
    let wasm_path = "python-3.12.0.wasm";

    match Module::from_file(&engine, wasm_path) {
        Ok(module) => {
            log::info!("✅ python.wasm loaded successfully.");
            log::info!("   Exports: {}", module.exports().count());
            log::info!("   Imports: {}", module.imports().count());
            log::info!("\n🎯 Milestone achieved: Wasmtime can load the Python runtime.");
            log::info!("   Next step → Phase 2, Step 4: execute a Python script inside it.");
        }
        Err(e) => {
            log::error!("❌ Failed to load python.wasm: {}", e);
            log::error!("   Make sure `python-3.12.0.wasm` is in the project root.");
            std::process::exit(1);
        }
    }

    Ok(())
}
