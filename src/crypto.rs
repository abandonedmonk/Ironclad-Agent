use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Compute SHA-256 for a script file and return lowercase hex.
pub fn compute_script_sha256(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 1024];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break; // EOF
        }

        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 2);
    for byte in result {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{:02x}", byte);
    }

    Ok(hex)
}
