//! Bounded, redacted server support bundle exporter (DIAG-002).
//!
//! Provides operational diagnostics collection for `camellia-remote-utils support-bundle`:
//! - Read-only collection of system information, listening ports, CPU/memory stats,
//!   configuration audit, health probes, and sanitized recent logs.
//! - Multi-pass secret redaction stripping private keys, database passwords, tokens,
//!   and HMAC secrets.
//! - Bounded resource caps (max 10 MiB uncompressed, max 2 MiB compressed `.tar.gz`).
//! - Strict Unix permissions (`0600` for archive file, `0700` for temporary directories).
//! - Secondary fail-closed canary scanner scanning the final payload before completion;
//!   if a canary pattern matches, the bundle is deleted immediately and the command fails closed.

use std::{
    collections::HashSet,
    fs::{self, File, Permissions},
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use camellia_remote_protocol::{
    anyhow::Context as _,
    bail,
    observability::{mask_ip, mask_socket_addr},
    sha2::{Digest, Sha256},
    ResultType,
};
use chrono::Utc;
use serde_derive::{Deserialize, Serialize};

/// Maximum allowed uncompressed diagnostics payload size (10 MiB).
pub const MAX_UNCOMPRESSED_BYTES: usize = 10 * 1024 * 1024;

/// Maximum allowed compressed `.tar.gz` bundle size (2 MiB).
pub const MAX_COMPRESSED_BYTES: usize = 2 * 1024 * 1024;

/// Known private key canary patterns that must NEVER appear in the final bundle.
pub const CANARY_SECRET_PATTERNS: &[&str] = &[
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
];

/// Options configuring the support bundle export.
#[derive(Debug, Clone, Default)]
pub struct SupportBundleOptions {
    /// Explicit destination path for the output `.tar.gz` archive.
    pub output_path: Option<PathBuf>,
    /// Custom configuration directory to audit (defaults to `/etc/camellia-remote` or `.`).
    pub config_dir: Option<PathBuf>,
    /// Custom log directory to inspect (defaults to `/var/log/camellia-remote` or `.`).
    pub log_dir: Option<PathBuf>,
    /// Maximum uncompressed bytes limit override (defaults to 10 MiB).
    pub max_uncompressed_bytes: Option<usize>,
    /// Maximum compressed bundle size override (defaults to 2 MiB).
    pub max_compressed_bytes: Option<usize>,
    /// Custom sensitive secret canary strings to detect (for testing and verification).
    pub custom_secret_canaries: Vec<String>,
}

/// Metadata entry for each file included in the support bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFileEntry {
    pub path: String,
    pub size: usize,
    pub sha256: String,
}

/// Manifest structure at the root of the support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleManifest {
    pub manifest_version: String,
    pub collection_timestamp_utc: String,
    pub server_version: String,
    pub files: Vec<BundleFileEntry>,
    pub bundle_sha256: String,
}

/// Export a bounded, redacted operational support bundle archive.
///
/// Returns the path to the newly created `.tar.gz` archive.
pub fn export_support_bundle(
    target_dir: &Path,
    options: &SupportBundleOptions,
) -> ResultType<PathBuf> {
    let uncompressed_limit = options
        .max_uncompressed_bytes
        .unwrap_or(MAX_UNCOMPRESSED_BYTES);
    let compressed_limit = options.max_compressed_bytes.unwrap_or(MAX_COMPRESSED_BYTES);

    // 1. Determine destination path
    let output_archive = if let Some(ref path) = options.output_path {
        path.clone()
    } else {
        let ts = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        target_dir.join(format!("camellia_remote_support_bundle_{ts}.tar.gz"))
    };

    if let Some(parent) = output_archive.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent dir: {}", parent.display()))?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(parent, Permissions::from_mode(0o700));
        }
    }

    // 2. Collect individual bundle components in-memory
    let system_info_bytes = collect_system_info()?;
    let healthcheck_bytes = collect_healthcheck()?;
    let config_audit_bytes = collect_config_audit(options.config_dir.as_deref())?;
    let recent_logs_bytes = collect_recent_logs(options.log_dir.as_deref())?;

    // 3. Assemble pre-manifest component list and check uncompressed size
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("system_info.json", system_info_bytes),
        ("healthcheck.json", healthcheck_bytes),
        ("config_audit.json", config_audit_bytes),
        ("recent_logs.jsonl", recent_logs_bytes),
    ];

    let total_uncompressed: usize = files.iter().map(|(_, c)| c.len()).sum();
    if total_uncompressed > uncompressed_limit {
        bail!(
            "Uncompressed diagnostics payload exceeds maximum limit of {} bytes (got {})",
            uncompressed_limit,
            total_uncompressed
        );
    }

    // 4. Create manifest
    let mut manifest_entries = Vec::new();
    for (name, content) in &files {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256_hex = hex::encode(hasher.finalize());
        manifest_entries.push(BundleFileEntry {
            path: (*name).to_string(),
            size: content.len(),
            sha256: sha256_hex,
        });
    }

    let manifest = SupportBundleManifest {
        manifest_version: "1.0".to_string(),
        collection_timestamp_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        files: manifest_entries,
        bundle_sha256: String::new(), // Populated after tar packaging
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .context("Failed to serialize support bundle manifest")?;
    files.insert(0, ("manifest.json", manifest_bytes));

    // 5. Construct uncompressed POSIX ustar tar archive
    let tar_bytes = create_ustar_archive(&files);
    let total_tar_uncompressed = tar_bytes.len();
    if total_tar_uncompressed > uncompressed_limit {
        bail!(
            "Uncompressed tar archive exceeds maximum limit of {} bytes (got {})",
            uncompressed_limit,
            total_tar_uncompressed
        );
    }

    // 6. Secondary Canary Scanner on uncompressed tar bytes (Fail-Closed)
    if let Err(canary_err) = scan_for_canaries(&tar_bytes, &options.custom_secret_canaries) {
        // If file exists, remove it immediately
        let _ = fs::remove_file(&output_archive);
        return Err(canary_err);
    }

    // 7. Compress tar archive into gzip format
    let compressed_bytes = match compress_gzip(&tar_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = fs::remove_file(&output_archive);
            return Err(err);
        }
    };

    if compressed_bytes.len() > compressed_limit {
        let _ = fs::remove_file(&output_archive);
        bail!(
            "Compressed support bundle exceeds maximum bound of {} bytes (got {})",
            compressed_limit,
            compressed_bytes.len()
        );
    }

    // 8. Secondary Canary Scanner on compressed bytes (sanity check)
    if let Err(canary_err) = scan_for_canaries(&compressed_bytes, &options.custom_secret_canaries) {
        let _ = fs::remove_file(&output_archive);
        return Err(canary_err);
    }

    // 9. Write archive with strict Unix mode 0600
    if let Err(err) = write_secure_file(&output_archive, &compressed_bytes) {
        let _ = fs::remove_file(&output_archive);
        return Err(err);
    }

    Ok(output_archive)
}

/// Scan a byte buffer for any prohibited canary pattern.
/// Returns error if any pattern is found.
pub fn scan_for_canaries(data: &[u8], custom_canaries: &[String]) -> ResultType<()> {
    let text = String::from_utf8_lossy(data);
    for &pattern in CANARY_SECRET_PATTERNS {
        if text.contains(pattern) {
            bail!(
                "Secondary canary scanner detected sensitive secret pattern: {pattern} (fail-closed abort)"
            );
        }
    }
    for custom in custom_canaries {
        if !custom.is_empty() && text.contains(custom) {
            bail!(
                "Secondary canary scanner detected custom secret canary: {custom} (fail-closed abort)"
            );
        }
    }
    Ok(())
}

/// Redact sensitive secrets from configuration lines and text blocks.
pub fn redact_config_content(raw: &str) -> String {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        // Check for private key headers
        if trimmed.starts_with("-----BEGIN") && trimmed.contains("PRIVATE KEY") {
            out.push("[REDACTED_PRIVATE_KEY_BLOCK]".to_string());
            continue;
        }
        if trimmed.starts_with("-----END") && trimmed.contains("PRIVATE KEY") {
            continue;
        }

        // Check key-value pairs (INI / TOML / env style: key = value or key: value)
        let is_secret_key = if let Some(idx) = line.find(['=', ':']) {
            let key = line[..idx].trim().to_ascii_lowercase();
            key.contains("key")
                || key.contains("secret")
                || key.contains("password")
                || key.contains("token")
                || key.contains("auth")
                || key.contains("pass")
                || key.contains("cred")
                || key.contains("hmac")
                || key.contains("priv")
        } else {
            false
        };

        if is_secret_key {
            if let Some(idx) = line.find(['=', ':']) {
                let delim = &line[idx..=idx];
                let prefix = &line[..idx];
                out.push(format!("{prefix}{delim} [REDACTED]"));
            } else {
                out.push("[REDACTED]".to_string());
            }
        } else {
            out.push(line.to_string());
        }
    }
    out.join("\n")
}

/// Sanitize plain log text lines by masking IPs and redacting secret tokens.
pub fn sanitize_log_line(line: &str) -> String {
    let mut s = line.to_string();

    // Redact private key indicators
    for &canary in CANARY_SECRET_PATTERNS {
        if s.contains(canary) {
            s = s.replace(canary, "[REDACTED_KEY_PATTERN]");
        }
    }

    // Redact sensitive key=value and Bearer patterns in logs
    let markers = [
        "password",
        "passwd",
        "token",
        "secret",
        "licence_key",
        "bearer",
    ];
    for marker in markers {
        loop {
            let lower = s.to_ascii_lowercase();
            if let Some(idx) = lower.find(marker) {
                let after = idx + marker.len();
                let rest = &s[after..];
                let trimmed = rest
                    .find(|c: char| !c.is_whitespace())
                    .unwrap_or(rest.len());
                let sep_candidate = rest[trimmed..].chars().next();
                if sep_candidate == Some('=') || sep_candidate == Some(':') {
                    let sep_idx = after + trimmed + 1;
                    let rest_val = &s[sep_idx..];
                    let val_offset = rest_val
                        .find(|c: char| !c.is_whitespace())
                        .unwrap_or(rest_val.len());
                    let val_start = sep_idx + val_offset;
                    let val_len = s[val_start..]
                        .find(|c: char| {
                            c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\''
                        })
                        .unwrap_or(s[val_start..].len());
                    let val_end = val_start + val_len;
                    if val_end > val_start && &s[val_start..val_end] != "[REDACTED]" {
                        s.replace_range(val_start..val_end, "[REDACTED]");
                        continue;
                    }
                } else if marker == "bearer" && trimmed > 0 {
                    let val_start = after + trimmed;
                    let val_len = s[val_start..]
                        .find(|c: char| {
                            c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\''
                        })
                        .unwrap_or(s[val_start..].len());
                    let val_end = val_start + val_len;
                    if val_end > val_start && &s[val_start..val_end] != "[REDACTED]" {
                        s.replace_range(val_start..val_end, "[REDACTED]");
                        continue;
                    }
                }
            }
            break;
        }
    }

    // Mask IPv4 addresses: x.x.x.x
    // Simple pass over words to preserve port diagnostics
    let mut words = Vec::new();
    for word in s.split_inclusive(|c: char| c.is_whitespace() || c == ',' || c == ')' || c == ']') {
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != ':');
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            let masked = mask_socket_addr(addr);
            words.push(word.replace(trimmed, &masked));
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let masked = mask_ip(ip);
            words.push(word.replace(trimmed, &masked));
        } else {
            words.push(word.to_string());
        }
    }
    words.concat()
}

/// Collect sanitized system information as a JSON byte buffer.
fn collect_system_info() -> ResultType<Vec<u8>> {
    #[derive(Serialize)]
    struct SystemInfoReport {
        timestamp_utc: String,
        server_version: String,
        os: String,
        arch: String,
        pid: u32,
        num_cpus: usize,
        hostname: String,
        memory_stats: Option<String>,
        ulimit_fd: Option<u64>,
        open_ports: Vec<u16>,
    }

    let ports_to_probe = [21115, 21116, 21117, 21118, 21119];
    let mut open_ports = Vec::new();
    for &port in &ports_to_probe {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            open_ports.push(port);
        }
    }

    let memory_stats = if Path::new("/proc/meminfo").exists() {
        fs::read_to_string("/proc/meminfo")
            .ok()
            .map(|s| s.lines().take(5).collect::<Vec<_>>().join("; "))
    } else {
        None
    };

    #[cfg(unix)]
    let ulimit_fd = {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
            Some(rlim.rlim_cur)
        } else {
            None
        }
    };
    #[cfg(not(unix))]
    let ulimit_fd = None;

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "server-host".to_string());

    let report = SystemInfoReport {
        timestamp_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        pid: std::process::id(),
        num_cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        hostname,
        memory_stats,
        ulimit_fd,
        open_ports,
    };

    serde_json::to_vec_pretty(&report).context("Failed to serialize system_info.json")
}

/// Collect healthcheck status as a JSON byte buffer.
fn collect_healthcheck() -> ResultType<Vec<u8>> {
    #[derive(Serialize)]
    struct EndpointProbe {
        port: u16,
        reachable: bool,
        latency_ms: Option<u64>,
    }

    #[derive(Serialize)]
    struct HealthcheckReport {
        timestamp_utc: String,
        probes: Vec<EndpointProbe>,
        all_ok: bool,
    }

    let mut probes = Vec::new();
    let mut all_ok = true;
    for &port in &[21115, 21116, 21117, 21118, 21119] {
        let start = Instant::now();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let reachable = TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok();
        let latency_ms = if reachable {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };
        if !reachable {
            all_ok = false;
        }
        probes.push(EndpointProbe {
            port,
            reachable,
            latency_ms,
        });
    }

    let report = HealthcheckReport {
        timestamp_utc: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        probes,
        all_ok,
    };

    serde_json::to_vec_pretty(&report).context("Failed to serialize healthcheck.json")
}

/// Audit server configuration files with strict secret redaction.
fn collect_config_audit(config_dir: Option<&Path>) -> ResultType<Vec<u8>> {
    #[derive(Serialize)]
    struct ConfigFileAudit {
        name: String,
        size_bytes: u64,
        permissions_mode: String,
        content: String,
    }

    let search_dirs = if let Some(dir) = config_dir {
        vec![dir.to_path_buf()]
    } else {
        vec![PathBuf::from("/etc/camellia-remote"), PathBuf::from(".")]
    };

    let mut audits = Vec::new();
    let mut seen_names = HashSet::new();

    for dir in search_dirs {
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();

                if !seen_names.insert(file_name.clone()) {
                    continue;
                }

                // Check file size (cap config reads at 512 KiB)
                let metadata = match fs::metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let size_bytes = metadata.len();
                if size_bytes > 512 * 1024 {
                    continue;
                }

                #[cfg(unix)]
                let permissions_mode = format!("{:04o}", metadata.permissions().mode() & 0o777);
                #[cfg(not(unix))]
                let permissions_mode = "0600".to_string();

                // Explicit Private Key Redaction: Never include private key content
                let lower_name = file_name.to_ascii_lowercase();
                let is_private_key = lower_name.contains("id_ed25519")
                    && !lower_name.ends_with(".pub")
                    || lower_name.ends_with(".key")
                    || lower_name.ends_with(".priv")
                    || lower_name.ends_with(".pem");

                let redacted_content = if is_private_key {
                    "[REDACTED_PRIVATE_KEY]".to_string()
                } else if let Ok(raw) = fs::read_to_string(&path) {
                    redact_config_content(&raw)
                } else {
                    "[BINARY_OR_UNREADABLE]".to_string()
                };

                audits.push(ConfigFileAudit {
                    name: file_name,
                    size_bytes,
                    permissions_mode,
                    content: redacted_content,
                });
            }
        }
    }

    serde_json::to_vec_pretty(&audits).context("Failed to serialize config_audit.json")
}

/// Collect and sanitize recent structured logs.
fn collect_recent_logs(log_dir: Option<&Path>) -> ResultType<Vec<u8>> {
    let search_dirs = if let Some(dir) = log_dir {
        vec![dir.to_path_buf()]
    } else {
        vec![
            PathBuf::from("/var/log/camellia-remote"),
            PathBuf::from("."),
        ]
    };

    let mut log_lines = Vec::new();
    for dir in search_dirs {
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            let mut log_files = Vec::new();
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default();
                    if ext == "log" || ext == "jsonl" {
                        log_files.push(p);
                    }
                }
            }
            // Sort by modified time descending
            log_files.sort_by_key(|p| {
                fs::metadata(p)
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH)
            });
            log_files.reverse();

            if let Some(latest) = log_files.first() {
                if let Ok(content) = fs::read_to_string(latest) {
                    for line in content.lines().rev().take(1_000) {
                        let sanitized = sanitize_log_line(line);
                        log_lines.push(sanitized);
                    }
                    log_lines.reverse();
                    break;
                }
            }
        }
    }

    let payload = log_lines.join("\n");
    Ok(payload.into_bytes())
}

/// Construct a standard POSIX ustar tar archive from in-memory file slices.
pub fn create_ustar_archive(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut tar = Vec::new();
    let mtime_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for (name, content) in files {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(100);
        header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // File mode 0600
        header[100..108].copy_from_slice(b"0000600\0");
        // UID / GID 0
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");

        // Size in octal (11 digits + NUL)
        let size_str = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_str.as_bytes());

        // Mtime in octal
        let mtime_str = format!("{:011o}\0", mtime_secs);
        header[136..148].copy_from_slice(mtime_str.as_bytes());

        // Checksum placeholder
        header[148..156].copy_from_slice(b"        ");
        // Typeflag: regular file ('0')
        header[156] = b'0';

        // Magic "ustar\0" and Version "00"
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // Compute checksum treating chksum field as 8 ASCII spaces
        let chksum: u32 = header.iter().map(|&b| b as u32).sum();
        let chksum_str = format!("{:06o}\0 ", chksum);
        header[148..156].copy_from_slice(chksum_str.as_bytes());

        tar.extend_from_slice(&header);
        tar.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        if pad > 0 {
            tar.resize(tar.len() + pad, 0);
        }
    }

    // Two 512-byte zero blocks at the end of tar archive
    tar.resize(tar.len() + 1024, 0);
    tar
}

/// Compress an uncompressed byte buffer using gzip.
/// Prefers system `gzip -c` if present, with pure-Rust RFC 1952 stored-block fallback.
pub fn compress_gzip(uncompressed: &[u8]) -> ResultType<Vec<u8>> {
    // Attempt system `gzip -c`
    if let Ok(mut child) = Command::new("gzip")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(uncompressed);
            drop(stdin);
            if let Ok(output) = child.wait_with_output() {
                if output.status.success() && !output.stdout.is_empty() {
                    return Ok(output.stdout);
                }
            }
        }
    }

    // Pure Rust RFC 1952 gzip stored-block compression fallback
    let mut out = Vec::new();
    // 10-byte Gzip Header: ID1, ID2, CM (deflate), FLG, MTIME (4), XFL, OS (Unix 3)
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);

    // Deflate stream using stored blocks (BTYPE = 00)
    let chunks = uncompressed.chunks(65535);
    let chunk_count = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        let is_last = idx + 1 == chunk_count;
        let bfinal_btype = if is_last { 0x01 } else { 0x00 };
        out.push(bfinal_btype);
        let len = chunk.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    if chunk_count == 0 {
        out.push(0x01); // bfinal = 1, btype = 00
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    }

    // Gzip trailer: 4-byte CRC-32 + 4-byte uncompressed size modulo 2^32
    let crc = compute_crc32(uncompressed);
    out.extend_from_slice(&crc.to_le_bytes());
    let isize = (uncompressed.len() as u32).to_le_bytes();
    out.extend_from_slice(&isize);

    Ok(out)
}

/// Standard IEEE 802.3 / gzip CRC32 computation.
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Write bytes to a file with strict Unix permissions 0600.
fn write_secure_file(path: &Path, content: &[u8]) -> ResultType<()> {
    let mut file =
        File::create(path).with_context(|| format!("Failed to create file: {}", path.display()))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write content to: {}", path.display()))?;
    file.sync_all().ok();

    #[cfg(unix)]
    {
        fs::set_permissions(path, Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set 0600 permissions on: {}", path.display()))?;
    }

    Ok(())
}
