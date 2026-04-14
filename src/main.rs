#![allow(unused)]

use serde::Serialize;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::{self, DirPerms, FilePerms, p1::WasiP1Ctx};

/// Captures stdout/stderr from executed scripts
#[derive(Debug, Clone, Serialize)]
struct ExecutionOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
    error: Option<String>,
}

/// Defines our runtime's input/output contract
fn main() -> wasmtime::Result<()> {
    // Enable structured logging
    env_logger::init();
    log::info!("Booting Wasmtime engine...");

    // Grab script path from CLI args
    let args: Vec<String> = std::env::args().collect();
    let script_path = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            // Bail with usage if no script provided
            let output = ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
                error: Some("Usage: ironclad-runtime <script_path>".to_string()),
            };
            log::error!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(1);
        }
    };

    // Validate script exists
    log::info!("Checking: {}", script_path);
    if !std::path::Path::new(&script_path).exists() {
        let output = ExecutionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
            error: Some(format!("Missing script: {}", script_path)),
        };
        log::error!("{}", serde_json::to_string(&output).unwrap());
        std::process::exit(1);
    }

    log::info!("✓ Script check passed");

    // Example of our JSON output format
    let _demo = ExecutionOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        error: None,
    };
    log::info!(
        "Sample output: stdout='{}', stderr='{}', code={}, err={:?}",
        _demo.stdout,
        _demo.stderr,
        _demo.exit_code,
        _demo.error
    );

    // Ensure sandbox dir exists for WASI
    std::fs::create_dir_all(".sandbox")?;

    // Stage the requested script into the sandbox and run that guest path.
    let host_script_in_sandbox = ".sandbox/script.py";
    std::fs::copy(&script_path, host_script_in_sandbox)?;
    let guest_script_path: &str = "/sandbox/script.py";

    // Prepare WASM execution environment
    let engine = Engine::default();
    let mut wasi_builder = wasmtime_wasi::WasiCtxBuilder::new();
    // Allow stdio passthrough for debugging
    wasi_builder.inherit_stdio();
    // argv[0] program name and argv[1] script path in the guest filesystem
    wasi_builder.arg("python.wasm");
    wasi_builder.arg(guest_script_path);
    // Mount our sandbox at /sandbox inside WASM
    wasi_builder.preopened_dir(
        "./.sandbox",     // Host path
        "/sandbox",       // Guest path
        DirPerms::all(),  // Permissions for dirs
        FilePerms::all(), // Permissions for files
    )?;
    let wasi = wasi_builder.build_p1();

    // Link WASI imports to our context
    let mut linker = Linker::<WasiP1Ctx>::new(&engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s| s)?;

    // Load and validate the WASM module
    let wasm_path = "python-3.12.0.wasm";
    let module = match Module::from_file(&engine, wasm_path) {
        Ok(m) => m,
        Err(e) => {
            log::error!("WASM load failed: {}", e);
            log::error!("Put python-3.12.0.wasm in project root");
            std::process::exit(1);
        }
    };

    log::info!(
        "✓ WASM ready ({} exports, {} imports)",
        module.exports().count(),
        module.imports().count()
    );

    // Prepare execution store with WASI context
    let mut store = Store::new(&engine, wasi);

    // Instantiate module with our imports
    let _instance = linker.instantiate(&mut store, &module)?;
    log::info!("✓ Module linked and instantiated");

    // Try common WASI entry points across module styles.
    if let Some(start) = _instance.get_func(&mut store, "_start") {
        log::info!("Using '_start' entrypoint");
        start.typed::<(), ()>(&store)?.call(&mut store, ())?;
    } else if let Some(initialize) = _instance.get_func(&mut store, "_initialize") {
        log::info!("Using '_initialize' entrypoint");
        initialize.typed::<(), ()>(&store)?.call(&mut store, ())?;
    } else {
        let exports = module
            .exports()
            .map(|e| e.name().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(wasmtime::Error::msg(format!(
            "No supported entrypoint found. Tried '_start' and '_initialize'. Exports: [{}]",
            exports
        )));
    }

    Ok(())
}
