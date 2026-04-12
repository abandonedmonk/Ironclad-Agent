use wasmtime::{Engine, Module};

fn main() -> wasmtime::Result<()> {
    println!("🔒 Ironclad Runtime — Phase 1, Step 2");
    println!("Loading python.wasm into Wasmtime engine...\n");

    // The engine is the global compilation environment.
    // Default config is fine for now — no fuel limits yet (Phase 2, Step 7).
    let engine = Engine::default();

    // Compile the .wasm binary into the engine.
    // This does NOT execute anything — it just validates and compiles.
    // The file path is relative to where `cargo run` is invoked (project root).
    let wasm_path = "python-3.12.0.wasm";

    match Module::from_file(&engine, wasm_path) {
        Ok(module) => {
            println!("✅ python.wasm loaded successfully.");
            println!("   Exports: {}", module.exports().count());
            println!("   Imports: {}", module.imports().count());
            println!("\n🎯 Milestone achieved: Wasmtime can load the Python runtime.");
            println!("   Next step → Phase 2, Step 4: execute a Python script inside it.");
        }
        Err(e) => {
            eprintln!("❌ Failed to load python.wasm: {}", e);
            eprintln!("   Make sure `python-3.12.0.wasm` is in the project root.");
            std::process::exit(1);
        }
    }

    Ok(())
}
