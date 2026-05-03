//! # Ironclad Runtime — WASM Sandbox for Secure Script Execution
//!
//! This binary sandboxes Python scripts using WebAssembly (Wasmtime) and WASI.
//! It enforces:
//! - CPU Limits: Via fuel-based execution budgets
//! - Filesystem Isolation: Restricted to a single sandbox directory
//! - Network Blocking: WASI grants no socket permissions
//!
//! Input: Path to a Python script  
//! Output: JSON with { stdout, stderr, exit_code, error }

use serde::Serialize;
use std::collections::HashSet;
use std::time::Instant;
use wasmtime::{Config, Engine, Linker, Module, Store, Trap};
use wasmtime_wasi::{self, DirPerms, FilePerms, p1::WasiP1Ctx};

mod audit;
mod crypto;
mod packages;
mod verify;
use packages::{
    PackageApproval, PackageRequest, PackageResolutionConfig, build_package_error_json,
    detect_forbidden_install_attempt, extract_package_requests_from_script, manifest_summary,
    parse_package_list, resolve_packages,
};

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

/// CPU fuel budget per execution. Units: abstract fuel cost per Wasm instruction.
/// ~100 billion fuel allows normal scripts to run; infinite loops killed in milliseconds.
const FUEL_BUDGET: u64 = 100_000_000_000;

/// Policy: Allow string fallback for fuel error detection?
/// - `true`: Compatibility mode — trap downcast + text matching (development)
/// - `false`: Strict mode — trap downcast only (production)
const FUEL_DETECTION_USE_FALLBACK: bool = true;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Describes one supported entrypoint.
#[derive(Debug, Clone)]
struct EntrypointSpec {
    name: &'static str,
}

/// All entrypoints this runtime knows how to call.
/// Each WASM module can export one of these names as its entry point.
const ENTRYPOINT_CANDIDATES: &[EntrypointSpec] = &[
    EntrypointSpec { name: "_start" },
    EntrypointSpec {
        name: "_initialize",
    },
];

/// Execution result: captured output + exit status.
/// This struct is serialized to JSON and returned to the agent.
#[derive(Debug, Clone, Serialize)]
struct ExecutionOutput {
    /// Complete stdout from the sandboxed script.
    stdout: String,
    /// Complete stderr from the sandboxed script.
    stderr: String,
    /// Exit code (0 = success, non-zero = error or out-of-fuel).
    exit_code: i32,
    /// Error message (Some if execution failed, None if succeeded).
    error: Option<String>,
}

#[derive(Debug)]
struct RuntimeArgs {
    script_path: Option<String>,
    cli_packages: Vec<PackageRequest>,
    verify_path: Option<String>,
}

fn parse_runtime_args(args: &[String]) -> Result<RuntimeArgs, String> {
    let mut script_path = None;
    let mut cli_packages = Vec::new();
    let mut verify_path = None;

    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--verify" => {
                let path = args
                    .get(index + 1)
                    .ok_or_else(|| "Usage: ironclad-runtime --verify <script_path>".to_string())?;
                verify_path = Some(path.clone());
                break;
            }
            "--packages" => {
                let packages = args.get(index + 1).ok_or_else(|| {
                    "--packages requires a comma-separated package list".to_string()
                })?;
                cli_packages.extend(parse_package_list(packages));
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(format!("Unknown flag: {}", value));
            }
            value => {
                if script_path.is_none() {
                    script_path = Some(value.to_string());
                    index += 1;
                } else {
                    return Err(format!("Unexpected argument: {}", value));
                }
            }
        }
    }

    Ok(RuntimeArgs {
        script_path,
        cli_packages,
        verify_path,
    })
}

fn emit_json_error_and_exit(message: String) -> ! {
    let output = ExecutionOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 1,
        error: Some(message),
    };
    log::error!("{}", serde_json::to_string(&output).unwrap());
    std::process::exit(1);
}

fn merge_package_requests(
    cli_packages: Vec<PackageRequest>,
    script_packages: Vec<PackageRequest>,
) -> Vec<PackageRequest> {
    let mut merged = cli_packages;
    merged.extend(script_packages);
    merged
}

fn build_pythonpath(approvals: &[PackageApproval], mount_path: &str) -> String {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    let mount_entry = mount_path.to_string();
    if seen.insert(mount_entry.clone()) {
        entries.push(mount_entry);
    }

    for approval in approvals {
        if approval.wheel == "stdlib" {
            continue;
        }

        if seen.insert(approval.mount_path.clone()) {
            entries.push(approval.mount_path.clone());
        }
    }

    entries.join(":")
}

// ============================================================================
// FUEL ERROR CLASSIFICATION
// ============================================================================

/// Detects whether an error is due to out-of-fuel (CPU budget exhaustion).
///
/// * Primary path: Wasmtime trap downcast → authoritative.  
/// * Fallback path: String matching → only if policy allows (compatible with wrapped errors).
///
/// ⚠️ Gotcha: String matching is brittle across Wasmtime versions. Keep strict mode as default.
fn is_out_of_fuel(error: &wasmtime::Error) -> bool {
    match error.downcast_ref::<Trap>() {
        Some(trap) => *trap == Trap::OutOfFuel, // ✅ Authoritative: native trap type
        None => {
            // Fallback: error is wrapped, try string matching per policy
            if FUEL_DETECTION_USE_FALLBACK {
                error
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("out of fuel")
            } else {
                false // Strict mode: don't guess if we can't prove it
            }
        }
    }
}

// ============================================================================
// ENTRYPOINT INVOCATION (Shared Handler)
// ============================================================================

/// Invokes a WASM entrypoint with centralized fuel error handling.
///
/// * What it does:
/// 1. Finds the first available entrypoint from candidates
/// 2. Calls that entrypoint with a nullary (no-arg) signature
/// 3. Classifies execution result: success, out-of-fuel, or other error
///
/// * Design benefit: One error handler for all endpoints — no per-endpoint branching.
///
/// ⚠️ Limitation: Currently assumes fn() -> () signature for all entrypoints.
/// When adding support for other signatures, extract the typed call into an adapter.
fn invoke_with_shared_handler(
    store: &mut Store<WasiP1Ctx>,
    instance: &wasmtime::Instance,
    module: &Module,
    entrypoints: &[EntrypointSpec],
) -> wasmtime::Result<String> {
    // Step 1: Find the first entrypoint this module exports
    let entrypoint = entrypoints
        .iter()
        .find_map(|spec| {
            if instance.get_func(&mut *store, spec.name).is_some() {
                Some(spec.name.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            // No supported entrypoint found; list what's actually exported
            let exports = module
                .exports()
                .map(|e| e.name().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            wasmtime::Error::msg(format!(
                "No supported entrypoint found. Tried {:?}. Exports: [{}]",
                entrypoints, exports
            ))
        })?;

    // Step 2: Invoke the entrypoint with standard (nullary) signature
    let func = instance.get_typed_func::<(), ()>(&mut *store, &entrypoint)?;

    // Step 3: Call and classify the result
    match func.call(&mut *store, ()) {
        Ok(()) => Ok(entrypoint), // Success: return which endpoint ran
        Err(error) if is_out_of_fuel(&error) => Err(wasmtime::Error::msg(format!(
            "Execution stopped: fuel exhausted while running entrypoint '{}'",
            entrypoint
        ))),
        Err(error) => Err(error), // Other error: pass through unchanged
    }
}

// ============================================================================
// MAIN RUNTIME
// ============================================================================

/// Entry point for the Ironclad sandbox runtime.
///
/// * Contract:
/// - Input: CLI arg = path to Python script file
/// - Output: JSON on stdout: { stdout, stderr, exit_code, error }
/// - Exit code: 0 = success, 1 = error
///
/// * Execution flow:
/// 1. Parse script path from CLI args
/// 2. Validate script exists
/// 3. Load python.wasm module
/// 4. Create WASI context (filesystem isolation + fuel limit)
/// 5. Instantiate module and invoke entrypoint
/// 6. Return results as JSON
fn main() -> wasmtime::Result<()> {
    // Initialize logging with a sensible default when RUST_LOG is not set.
    // This keeps logs visible during normal `cargo run` usage.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Stdout)
        .init();
    log::info!("Booting Wasmtime engine...");

    // ========================================================================
    // Parse & Validate Input
    // ========================================================================

    let args: Vec<String> = std::env::args().collect();
    let runtime_args = match parse_runtime_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => emit_json_error_and_exit(error),
    };

    if let Some(verify_path) = runtime_args.verify_path {
        if let Err(error) = verify::verify_script_execution(std::path::Path::new(&verify_path)) {
            let output = ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
                error: Some(format!("Verification failed: {}", error)),
            };
            log::error!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(1);
        }

        std::process::exit(0);
    }

    let script_path = match runtime_args.script_path {
        Some(path) => path,
        None => emit_json_error_and_exit(
            "Usage: ironclad-runtime <script_path> [--packages name1,name2] | --verify <script_path>".to_string(),
        ),
    };

    // Verify the script file exists before proceeding
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

    // Hash the script before execution.
    let script_hash = match crypto::compute_script_sha256(std::path::Path::new(&script_path)) {
        Ok(hash) => hash,
        Err(e) => {
            let output = ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
                error: Some(format!("Failed to hash script: {}", e)),
            };
            log::error!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(1);
        }
    };
    log::info!("Script SHA-256: {}", script_hash);

    // Resolve package requirements before sandbox startup.
    let script_packages =
        match extract_package_requests_from_script(std::path::Path::new(&script_path)) {
            Ok(requests) => requests,
            Err(error) => {
                let output = ExecutionOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 1,
                    error: Some(format!("Failed to inspect package requirements: {}", error)),
                };
                log::error!("{}", serde_json::to_string(&output).unwrap());
                std::process::exit(1);
            }
        };

    if let Ok(Some(rejection)) =
        detect_forbidden_install_attempt(std::path::Path::new(&script_path))
    {
        let output = ExecutionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
            error: Some(
                serde_json::json!({
                    "status": "execution_rejected",
                    "reason": rejection.reason.clone(),
                    "packages_rejected": [rejection.clone()],
                })
                .to_string(),
            ),
        };
        log::error!("{}", serde_json::to_string(&output).unwrap());
        std::process::exit(1);
    }

    let requested_packages = merge_package_requests(runtime_args.cli_packages, script_packages);
    let package_config = PackageResolutionConfig::default_local();
    let package_summary = match resolve_packages(&requested_packages, &package_config) {
        Ok(summary) => summary,
        Err(error) => {
            let output = ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 1,
                error: Some(format!("Package resolution failed: {}", error)),
            };
            log::error!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(1);
        }
    };

    let pythonpath = build_pythonpath(&package_summary.approved, &package_config.mount_path);

    let package_resolution_json = Some(manifest_summary(&package_summary));
    if !package_summary.rejected.is_empty() {
        let error_json = build_package_error_json(&package_summary);
        if let Err(error) = audit::append_audit_entry(
            audit::SANDBOX_RESULT,
            serde_json::json!({
                "script_hash": script_hash,
                "exit_code": 1,
                "runtime_ms": 0,
                "error": "package_rejection",
                "package_resolution": package_resolution_json,
                "output": error_json,
            }),
        ) {
            log::warn!(
                "Failed to append audit entry for package rejection: {}",
                error
            );
        }

        let output = ExecutionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
            error: Some(error_json),
        };
        log::error!("{}", serde_json::to_string(&output).unwrap());
        std::process::exit(1);
    }

    // ========================================================================
    // Prepare Sandbox & WASM Environment
    // ========================================================================

    // Create sandbox directory on host (guest will access via /sandbox)
    std::fs::create_dir_all(".sandbox")?;
    std::fs::create_dir_all(&package_config.vault_dir)?;

    // Copy the input script into the sandbox so WASM can read it
    let host_script_in_sandbox = ".sandbox/script.py";
    std::fs::copy(&script_path, host_script_in_sandbox)?;
    let guest_script_path: &str = "/sandbox/script.py";

    // Configure Wasmtime engine with fuel tracking enabled
    let mut config = Config::new();
    // Keep debug metadata in debug builds only; it slows down release startup.
    config.debug_info(cfg!(debug_assertions));
    config.consume_fuel(true); // Enable per-instruction fuel counting
    match wasmtime::Cache::from_file(None)
        .or_else(|_| wasmtime::Cache::new(wasmtime::CacheConfig::new()))
    {
        Ok(cache) => {
            config.cache(Some(cache));
            log::info!("Wasmtime compilation cache enabled");
        }
        Err(error) => {
            log::warn!(
                "Wasmtime cache unavailable, continuing without cache: {}",
                error
            );
        }
    }

    // Create the WASM runtime engine (global shared state for compilation)
    let engine = Engine::new(&config).unwrap();

    // ========================================================================
    // Configure WASI Context (Sandboxing)
    // ========================================================================

    // Set up WASI with:
    // * stdio passthrough (inherit host stdout/stderr)
    // * argv: program name + script path
    // * filesystem: only ./.sandbox → /sandbox mapping (no host access)
    let mut wasi_builder = wasmtime_wasi::WasiCtxBuilder::new();
    wasi_builder.inherit_stdio(); // Pass through stdin/stdout/stderr for debugging
    wasi_builder.arg("python.wasm"); // argv[0]
    wasi_builder.arg(guest_script_path); // argv[1]

    // ⭐ Key sandbox boundary: host ./.sandbox → guest /sandbox
    // Python scripts can only access files in /sandbox; host filesystem is unreachable
    wasi_builder.preopened_dir(
        "./.sandbox",     // Host path
        "/sandbox",       // Guest path (what WASM sees)
        DirPerms::all(),  // All directory permissions
        FilePerms::all(), // All file permissions
    )?;

    // Package vault is mounted read-only at the Python site-packages path.
    wasi_builder.preopened_dir(
        package_config.vault_dir.as_path(),
        package_config.mount_path.as_str(),
        DirPerms::all(),
        FilePerms::all(),
    )?;

    // /proc is mounted read-only so diagnostic scripts can read system metrics.
    // Only DirPerms::READ and FilePerms::READ — no writes, no directory creation.
    if std::path::Path::new("/proc").exists() {
        let _ = wasi_builder.preopened_dir(
            "/proc",
            "/proc",
            DirPerms::READ,
            FilePerms::READ,
        );
    }

    wasi_builder.env("PYTHONPATH", &pythonpath);

    // ❌ Network is NOT granted: no socket permissions in WASI context
    // Attempting urllib.request.urlopen(...) will fail with permission error

    let wasi = wasi_builder.build_p1();

    // Link WASI imports to the linker (makes WASI syscalls available to WASM)
    let mut linker = Linker::<WasiP1Ctx>::new(&engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s| s)?;

    // ========================================================================
    // Load WASM Module
    // ========================================================================

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

    // ========================================================================
    // Create Execution Store & Instantiate
    // ========================================================================

    // Create per-execution store with WASI context and fuel budget attached
    let mut store = Store::new(&engine, wasi);
    store.set_fuel(FUEL_BUDGET)?;

    // Instantiate: link module imports (WASI) with the linker
    let _instance = linker.instantiate(&mut store, &module)?;
    log::info!("✓ Module linked and instantiated");

    // ========================================================================
    // Execute and measure duration for audit logging
    // ========================================================================

    // Capture start time before the sandbox call.
    let exec_start = Instant::now();

    // Call the entrypoint with centralized fuel error handling.
    let used_entrypoint =
        invoke_with_shared_handler(&mut store, &_instance, &module, ENTRYPOINT_CANDIDATES)?;

    // Convert the elapsed time to milliseconds for the audit record.
    let exec_duration_ms = exec_start.elapsed().as_millis();

    // Report fuel consumption for instrumentation/tuning
    let fuel_left = store.get_fuel()?;
    log::info!(
        "Entrypoint '{}' completed. Fuel used: {} (remaining: {}), Duration: {}ms",
        used_entrypoint,
        FUEL_BUDGET.saturating_sub(fuel_left),
        fuel_left,
        exec_duration_ms
    );

    // ========================================================================
    // Build and append the audit log entry
    // ========================================================================

    audit::append_audit_entry(
        audit::SANDBOX_RESULT,
        serde_json::json!({
            "script_hash": script_hash,
            "exit_code": 0,
            "runtime_ms": exec_duration_ms,
            "package_resolution": package_resolution_json,
            "entrypoint": used_entrypoint,
        }),
    )?;

    log::info!("Audit entry appended to audit.log");

    Ok(())
}
