use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use zip::ZipArchive;

const DEFAULT_PACKAGE_MOUNT_PATH: &str = "/opt/python-site-packages";
const DEFAULT_VAULT_DIR: &str = ".sandbox/package-vault";
const DEFAULT_MANIFEST_PATH: &str = ".sandbox/package-vault/manifest.json";

const BUILTIN_PACKAGES: &[&str] = &[
    "json",
    "collections",
    "decimal",
    "statistics",
    "re",
    "typing",
    "pathlib",
    "math",
    "itertools",
    "functools",
    "operator",
    "datetime",
    "time",
];

const BLOCKED_PACKAGES: &[&str] = &["numpy", "pandas", "scipy", "tensorflow", "torch"];

const IMPORT_ALIASES: &[(&str, &str)] = &[
    ("yaml", "pyyaml"),
    ("dateutil", "python-dateutil"),
    ("pil", "pillow"),
    ("bs4", "beautifulsoup4"),
    ("sklearn", "scikit-learn"),
    ("cv2", "opencv-python"),
];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifestEntry {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub wheel: String,
    pub size_bytes: u64,
    pub pure_python: bool,
    pub audited: bool,
    pub fetch_date: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<PackageRequest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageApproval {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub wheel: String,
    pub size_bytes: u64,
    pub mount_path: String,
    pub source_url: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<PackageRequest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageRejection {
    pub status: String,
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub reason: String,
    pub details: String,
    pub alternatives: Vec<String>,
    pub retry_possible: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageResolutionSummary {
    pub requested: Vec<PackageRequest>,
    pub approved: Vec<PackageApproval>,
    pub rejected: Vec<PackageRejection>,
    pub mount_path: String,
    pub vault_dir: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone)]
pub struct PackageResolutionConfig {
    pub vault_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub mount_path: String,
    pub allow_any_pure_python: bool,
}

impl PackageResolutionConfig {
    pub fn default_local() -> Self {
        Self {
            vault_dir: PathBuf::from(DEFAULT_VAULT_DIR),
            manifest_path: PathBuf::from(DEFAULT_MANIFEST_PATH),
            mount_path: DEFAULT_PACKAGE_MOUNT_PATH.to_string(),
            allow_any_pure_python: true,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PypiProjectResponse {
    info: PypiProjectInfo,
    releases: BTreeMap<String, Vec<PypiReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiProjectInfo {
    version: String,
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PypiReleaseFile {
    filename: String,
    url: String,
    size: u64,
    #[serde(default)]
    packagetype: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    digests: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PackageManifestFile {
    packages: Vec<PackageManifestEntry>,
}

pub fn parse_package_request(raw: &str) -> Option<PackageRequest> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed
        .trim_matches(|ch| ch == ',' || ch == ';')
        .trim()
        .to_string();

    if normalized.is_empty() {
        return None;
    }

    let mut parts = normalized.splitn(2, "==");
    let name = canonicalize_name(parts.next().unwrap_or_default());
    let version = parts.next().map(|value| value.trim().to_string());

    if name.is_empty() {
        None
    } else {
        Some(PackageRequest { name, version })
    }
}

pub fn parse_package_list(raw: &str) -> Vec<PackageRequest> {
    raw.split(',').filter_map(parse_package_request).collect()
}

pub fn extract_package_requests_from_script(path: &Path) -> std::io::Result<Vec<PackageRequest>> {
    let contents = fs::read_to_string(path)?;
    let mut requests = Vec::new();

    for line in contents.lines().take(40) {
        let trimmed = line.trim_start();
        let upper = trimmed.to_ascii_uppercase();
        if let Some(pos) = upper.find("# REQUIRES:") {
            let after = &trimmed[pos + "# REQUIRES:".len()..];
            requests.extend(parse_package_list(after));
        }
    }

    Ok(requests)
}

pub fn detect_forbidden_install_attempt(path: &Path) -> std::io::Result<Option<PackageRejection>> {
    let contents = fs::read_to_string(path)?;
    let lowered = contents.to_ascii_lowercase();

    let indicators = [
        "pip install",
        "python -m pip",
        "uv pip",
        "subprocess.run([\"pip\"",
        "subprocess.run('pip",
        "subprocess.run(\"pip",
    ];

    if indicators
        .iter()
        .any(|indicator| lowered.contains(indicator))
    {
        return Ok(Some(reject(
            "package_installation_forbidden",
            None,
            "policy_denied",
            "The sandbox does not allow scripts to install packages at runtime. Declare PyPI distribution names with a # REQUIRES: comment and let the host resolver fetch them before execution.",
            vec![
                "Add a # REQUIRES: pyyaml, python-dateutil comment".to_string(),
                "Ask the agent to use PyPI distribution names, not import names".to_string(),
            ],
            false,
        )));
    }

    Ok(None)
}

pub fn resolve_packages(
    requested: &[PackageRequest],
    config: &PackageResolutionConfig,
) -> std::io::Result<PackageResolutionSummary> {
    fs::create_dir_all(&config.vault_dir)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(to_io_error)?;

    let manifest = load_manifest(&config.manifest_path)?;

    let mut approved = Vec::new();
    let mut rejected = Vec::new();
    let mut queue: VecDeque<PackageRequest> = requested.iter().cloned().collect();
    let mut seen = HashSet::new();

    while let Some(request) = queue.pop_front() {
        let key = canonicalize_key(&request.name, request.version.as_deref());
        if !seen.insert(key) {
            continue;
        }

        match resolve_single_package(&client, &request, config, &manifest) {
            Ok((approval, dependencies)) => {
                approved.push(approval);
                for dependency in dependencies {
                    queue.push_back(dependency);
                }
            }
            Err(rejection) => rejected.push(rejection),
        }
    }

    Ok(PackageResolutionSummary {
        requested: requested.to_vec(),
        approved,
        rejected,
        mount_path: config.mount_path.clone(),
        vault_dir: config.vault_dir.to_string_lossy().to_string(),
        manifest_path: config.manifest_path.to_string_lossy().to_string(),
    })
}

pub fn build_package_error_json(summary: &PackageResolutionSummary) -> String {
    serde_json::json!({
        "status": "execution_rejected",
        "reason": "package_missing",
        "packages_requested": summary.requested,
        "packages_approved": summary.approved,
        "packages_rejected": summary.rejected,
        "mount_path": summary.mount_path,
        "vault_dir": summary.vault_dir,
        "manifest_path": summary.manifest_path,
    })
    .to_string()
}

pub fn manifest_summary(summary: &PackageResolutionSummary) -> String {
    serde_json::to_string(summary).unwrap_or_else(|_| "{}".to_string())
}

fn resolve_single_package(
    client: &Client,
    request: &PackageRequest,
    config: &PackageResolutionConfig,
    manifest: &PackageManifestFile,
) -> Result<(PackageApproval, Vec<PackageRequest>), PackageRejection> {
    let package_name = canonicalize_name(&request.name);

    if is_builtin_package(&package_name) {
        return Ok((
            PackageApproval {
                name: package_name,
                version: request
                    .version
                    .clone()
                    .unwrap_or_else(|| "stdlib".to_string()),
                hash: "stdlib".to_string(),
                wheel: "stdlib".to_string(),
                size_bytes: 0,
                mount_path: config.mount_path.clone(),
                source_url: "stdlib".to_string(),
                dependencies: Vec::new(),
            },
            Vec::new(),
        ));
    }

    if BLOCKED_PACKAGES.contains(&package_name.as_str()) {
        return Err(reject(
            &package_name,
            request.version.clone(),
            "policy_denied",
            &format!(
                "Package '{}' is blocked by policy because it typically requires native extensions.",
                package_name
            ),
            vec![
                "statistics".to_string(),
                "decimal".to_string(),
                "mpmath".to_string(),
                "sympy".to_string(),
            ],
            false,
        ));
    }

    if !config.allow_any_pure_python && !is_builtin_package(&package_name) {
        return Err(reject(
            &package_name,
            request.version.clone(),
            "policy_denied",
            &format!(
                "Package '{}' is not in the curated allowlist for this runtime.",
                package_name
            ),
            vec!["Use a built-in module or a curated pure-Python alternative".to_string()],
            false,
        ));
    }

    if let Some(entry) = manifest.packages.iter().find(|entry| {
        entry.name == package_name
            && request
                .version
                .as_deref()
                .is_none_or(|version| version == entry.version)
    }) {
        let wheel_path = config.vault_dir.join(&entry.wheel);
        if wheel_path.exists() {
            return Ok((
                PackageApproval {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    hash: entry.hash.clone(),
                    wheel: entry.wheel.clone(),
                    size_bytes: entry.size_bytes,
                    mount_path: format!("{}/{}", config.mount_path, entry.wheel),
                    source_url: "manifest-cache".to_string(),
                    dependencies: entry.dependencies.clone(),
                },
                entry.dependencies.clone(),
            ));
        }
    }

    let project = fetch_project_metadata(client, &package_name).map_err(|error| {
        reject(
            &package_name,
            request.version.clone(),
            "network_fetch_failed",
            &format!(
                "Failed to query PyPI metadata for '{}': {}",
                package_name, error
            ),
            vec!["Retry the execution".to_string()],
            true,
        )
    })?;

    let version = request
        .version
        .clone()
        .unwrap_or_else(|| project.info.version.clone());

    let release_files = project.releases.get(&version).ok_or_else(|| {
        reject(
            &package_name,
            request.version.clone(),
            "version_not_found",
            &format!(
                "Package '{}' does not publish version '{}'.",
                package_name, version
            ),
            vec![project.info.version.clone()],
            false,
        )
    })?;

    let wheel =
        select_pure_python_wheel(&package_name, &version, release_files).ok_or_else(|| {
            classify_release_failure(&package_name, request.version.clone(), release_files)
        })?;

    let wheel_bytes = client
        .get(&wheel.url)
        .send()
        .and_then(|response| response.error_for_status())
        .and_then(|response| response.bytes())
        .map_err(|error| {
            reject(
                &package_name,
                Some(version.clone()),
                "network_fetch_failed",
                &format!("Failed to download wheel '{}': {}", wheel.filename, error),
                vec!["Retry the execution".to_string()],
                true,
            )
        })?;

    let wheel_bytes = wheel_bytes.to_vec();
    if wheel.size != wheel_bytes.len() as u64 {
        return Err(reject(
            &package_name,
            Some(version.clone()),
            "cache_corruption",
            &format!(
                "Wheel size mismatch for '{}': expected {} bytes, downloaded {} bytes.",
                wheel.filename,
                wheel.size,
                wheel_bytes.len()
            ),
            vec!["Retry the execution".to_string()],
            true,
        ));
    }

    let expected_hash = wheel.digests.get("sha256").cloned().unwrap_or_default();
    let computed_hash = sha256_hex(&wheel_bytes);
    if !expected_hash.is_empty() && expected_hash != computed_hash {
        return Err(reject(
            &package_name,
            Some(version.clone()),
            "hash_mismatch",
            &format!(
                "Wheel hash mismatch for '{}': expected {}, computed {}.",
                wheel.filename, expected_hash, computed_hash
            ),
            vec!["Retry the execution".to_string()],
            false,
        ));
    }

    validate_wheel_pure_python(&wheel_bytes).map_err(|details| {
        reject(
            &package_name,
            Some(version.clone()),
            "contains_native_code",
            &details,
            vec![
                "statistics".to_string(),
                "decimal".to_string(),
                "mpmath".to_string(),
                "sympy".to_string(),
            ],
            false,
        )
    })?;

    let wheel_file_name = format!("{}-{}.whl", package_name, computed_hash);
    let wheel_path = config.vault_dir.join(&wheel_file_name);
    fs::write(&wheel_path, &wheel_bytes).map_err(|error| {
        reject(
            &package_name,
            Some(version.clone()),
            "cache_corruption",
            &format!("Failed to persist wheel '{}': {}", wheel_file_name, error),
            vec!["Retry the execution".to_string()],
            true,
        )
    })?;

    let dependencies = parse_dependencies(
        project
            .info
            .requires_dist
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(&[]),
    );
    let entry = PackageManifestEntry {
        name: package_name.clone(),
        version: version.clone(),
        hash: computed_hash.clone(),
        wheel: wheel_file_name.clone(),
        size_bytes: wheel_bytes.len() as u64,
        pure_python: true,
        audited: true,
        fetch_date: OffsetDateTime::now_utc().date().to_string(),
        dependencies: dependencies.clone(),
    };

    append_manifest(&config.manifest_path, &entry).map_err(|error| {
        reject(
            &package_name,
            Some(version.clone()),
            "cache_corruption",
            &format!("Failed to update package manifest: {}", error),
            vec!["Retry the execution".to_string()],
            true,
        )
    })?;

    Ok((
        PackageApproval {
            name: package_name,
            version,
            hash: computed_hash,
            wheel: wheel_file_name.clone(),
            size_bytes: wheel_bytes.len() as u64,
            mount_path: format!("{}/{}", config.mount_path, wheel_file_name),
            source_url: wheel.url.clone(),
            dependencies,
        },
        parse_dependencies(
            project
                .info
                .requires_dist
                .as_ref()
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
        ),
    ))
}

fn fetch_project_metadata(
    client: &Client,
    package_name: &str,
) -> Result<PypiProjectResponse, reqwest::Error> {
    client
        .get(format!("https://pypi.org/pypi/{}/json", package_name))
        .send()?
        .error_for_status()?
        .json::<PypiProjectResponse>()
}

fn select_pure_python_wheel<'a>(
    package_name: &str,
    _version: &str,
    release_files: &'a [PypiReleaseFile],
) -> Option<&'a PypiReleaseFile> {
    release_files.iter().find(|file| {
        let filename = file.filename.to_ascii_lowercase();
        let expected_prefix = package_name.to_ascii_lowercase().replace("-", "_");

        !file.yanked
            && file.packagetype == "bdist_wheel"
            && filename.ends_with("-none-any.whl")
            && filename.contains(&expected_prefix)
    })
}

fn classify_release_failure(
    package_name: &str,
    requested_version: Option<String>,
    release_files: &[PypiReleaseFile],
) -> PackageRejection {
    let version = requested_version.clone();
    let filenames: Vec<String> = release_files
        .iter()
        .map(|file| file.filename.clone())
        .collect();

    if filenames.is_empty() {
        return reject(
            package_name,
            version,
            "package_not_found",
            &format!(
                "Package '{}' has no release files published on PyPI.",
                package_name
            ),
            vec![],
            false,
        );
    }

    if filenames
        .iter()
        .any(|filename| filename.ends_with(".tar.gz") || filename.ends_with(".zip"))
    {
        return reject(
            package_name,
            version,
            "source_distribution_only",
            &format!(
                "Package '{}' only provides source distributions: {}.",
                package_name,
                filenames.join(", ")
            ),
            vec!["Use a pure-Python alternative".to_string()],
            false,
        );
    }

    if filenames.iter().any(|filename| {
        let lower = filename.to_ascii_lowercase();
        lower.contains("manylinux")
            || lower.contains("musllinux")
            || lower.contains("win_amd64")
            || lower.contains("macosx")
    }) {
        return reject(
            package_name,
            version,
            "native_extension_required",
            &format!(
                "Package '{}' only publishes platform wheels: {}.",
                package_name,
                filenames.join(", ")
            ),
            vec!["Use statistics, decimal, mpmath, or sympy".to_string()],
            false,
        );
    }

    reject(
        package_name,
        version,
        "no_suitable_distribution",
        &format!(
            "Package '{}' has no compatible pure-Python wheel.",
            package_name
        ),
        vec!["Use a pure-Python alternative".to_string()],
        false,
    )
}

fn validate_wheel_pure_python(wheel_bytes: &[u8]) -> Result<(), String> {
    let cursor = Cursor::new(wheel_bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|error| format!("Wheel is not a valid ZIP archive: {}", error))?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("Failed to inspect wheel entry: {}", error))?;
        let name = file.name().to_ascii_lowercase();

        if name.ends_with('/') {
            continue;
        }

        if has_forbidden_extension(&name) {
            return Err(format!(
                "Native extension detected in wheel entry '{}'.",
                name
            ));
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("Failed to read wheel entry '{}': {}", name, error))?;

        if looks_like_native_binary(&bytes) {
            return Err(format!(
                "Binary payload detected in wheel entry '{}'.",
                name
            ));
        }
    }

    Ok(())
}

fn has_forbidden_extension(name: &str) -> bool {
    const FORBIDDEN_EXTENSIONS: &[&str] = &[
        ".so", ".pyd", ".dylib", ".dll", ".a", ".lib", ".c", ".cpp", ".cc", ".h", ".hpp",
    ];

    FORBIDDEN_EXTENSIONS
        .iter()
        .any(|extension| name.ends_with(extension))
}

fn looks_like_native_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(b"!<arch>\n")
}

fn parse_dependencies(raw: &[String]) -> Vec<PackageRequest> {
    raw.iter()
        .filter_map(|entry| {
            let requirement = entry.split(';').next().unwrap_or_default().trim();
            if requirement.is_empty() {
                return None;
            }

            let name = requirement
                .split([' ', '(', '[', '<', '>', '=', '~', '!'])
                .next()
                .unwrap_or_default()
                .trim();

            if name.is_empty() {
                None
            } else {
                Some(PackageRequest {
                    name: canonicalize_name(name),
                    version: None,
                })
            }
        })
        .collect()
}

fn append_manifest(path: &Path, entry: &PackageManifestEntry) -> std::io::Result<()> {
    let mut manifest = load_manifest(path)?;
    manifest.packages.push(entry.clone());
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn load_manifest(path: &Path) -> std::io::Result<PackageManifestFile> {
    if !path.exists() {
        return Ok(PackageManifestFile {
            packages: Vec::new(),
        });
    }

    let raw = fs::read_to_string(path)?;
    let parsed =
        serde_json::from_str::<PackageManifestFile>(&raw).unwrap_or_else(|_| PackageManifestFile {
            packages: Vec::new(),
        });
    Ok(parsed)
}

fn reject(
    package_name: &str,
    version: Option<String>,
    reason: &str,
    details: &str,
    alternatives: Vec<String>,
    retry_possible: bool,
) -> PackageRejection {
    PackageRejection {
        status: "rejected".to_string(),
        package: package_name.to_string(),
        version,
        reason: reason.to_string(),
        details: details.to_string(),
        alternatives,
        retry_possible,
    }
}

fn canonicalize_name(name: &str) -> String {
    let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
    IMPORT_ALIASES
        .iter()
        .find_map(|(import_name, package_name)| {
            if normalized == *import_name {
                Some((*package_name).to_string())
            } else {
                None
            }
        })
        .unwrap_or(normalized)
}

fn canonicalize_key(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) => format!("{}=={}", canonicalize_name(name), version.trim()),
        None => canonicalize_name(name),
    }
}

fn is_builtin_package(name: &str) -> bool {
    BUILTIN_PACKAGES.contains(&name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{:02x}", byte);
    }

    hex
}

fn to_io_error(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_handles_versions() {
        let request = parse_package_request("requests==2.31.0").unwrap();
        assert_eq!(request.name, "requests");
        assert_eq!(request.version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn parse_request_normalizes_names() {
        let request = parse_package_request("Python_Dateutil").unwrap();
        assert_eq!(request.name, "python-dateutil");
    }

    #[test]
    fn parse_request_maps_import_aliases() {
        let yaml_request = parse_package_request("yaml").unwrap();
        let dateutil_request = parse_package_request("dateutil").unwrap();

        assert_eq!(yaml_request.name, "pyyaml");
        assert_eq!(dateutil_request.name, "python-dateutil");
    }

    #[test]
    fn parse_list_ignores_empty_segments() {
        let requests = parse_package_list("requests, , pyyaml==6.0.1");
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn builtin_packages_are_detected() {
        assert!(is_builtin_package("json"));
        assert!(!is_builtin_package("requests"));
    }
}
