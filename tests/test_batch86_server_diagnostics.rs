//! Contract test suite for Batch 86 Server Diagnostics and Structured Logging (LOG-014, DIAG-002).

#[path = "../src/diagnostics.rs"]
mod diagnostics;

use std::{fs, net::SocketAddr, path::Path, process::Command};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use camellia_remote_protocol::{
    observability::{
        hash_peer_id, mask_socket_addr, CorrelationContextExt, StructuredEvent,
        STRUCTURED_SCHEMA_VERSION,
    },
    rendezvous_proto::CorrelationContext,
};
use diagnostics::{
    export_support_bundle, SupportBundleManifest, SupportBundleOptions, MAX_COMPRESSED_BYTES,
};

/// Helper to read all file entries inside a `.tar.gz` archive using system tar or python tarfile.
fn unpack_archive(archive_path: &Path, extract_to: &Path) {
    fs::create_dir_all(extract_to).expect("create extract dir");
    // Try system tar -xzf first
    let status = Command::new("tar")
        .args([
            "-xzf",
            archive_path.to_str().unwrap(),
            "-C",
            extract_to.to_str().unwrap(),
        ])
        .status();
    if status.is_err() || !status.as_ref().unwrap().success() {
        // Fallback to python tarfile
        let py_script = format!(
            "import tarfile\nwith tarfile.open(r'{}') as t:\n    t.extractall(r'{}')\n",
            archive_path.display(),
            extract_to.display()
        );
        let py_status = Command::new("python3")
            .args(["-c", &py_script])
            .status()
            .expect("run python tarfile extract");
        assert!(py_status.success(), "python tarfile extract failed");
    }
}

#[test]
fn test_support_bundle_creation_and_size_bounds() {
    let temp_root = std::env::temp_dir().join(format!("test_bundle_create_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    let config_dir = temp_root.join("config");
    let log_dir = temp_root.join("log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    // Create sample configuration
    fs::write(
        config_dir.join("camellia-remote.ini"),
        b"[server]\nrendezvous_server = 127.0.0.1:21116\nport = 21116\n",
    )
    .unwrap();

    // Create sample structured logs
    let sample_log = format!(
        "{{\"schema_version\":\"1.0.0\",\"service\":\"remote-server\",\"level\":\"INFO\",\"event\":\"rendezvous_registration\",\"trace_id\":\"abc123def456\",\"attempt_id\":\"789xyz\",\"peer_id_hash\":\"{}\",\"endpoint_masked\":\"127.0.0.1:21116\"}}\n",
        hash_peer_id("test_peer_123")
    );
    fs::write(log_dir.join("camellia-remote.log"), sample_log.as_bytes()).unwrap();

    let output_archive = temp_root.join("test_bundle.tar.gz");
    let options = SupportBundleOptions {
        output_path: Some(output_archive.clone()),
        config_dir: Some(config_dir),
        log_dir: Some(log_dir),
        max_uncompressed_bytes: None,
        max_compressed_bytes: None,
        custom_secret_canaries: Vec::new(),
    };

    let result_path = export_support_bundle(&temp_root, &options).expect("export support bundle");
    assert_eq!(result_path, output_archive);
    assert!(output_archive.is_file(), "Bundle archive must exist");

    // Verify compressed size bound
    let metadata = fs::metadata(&output_archive).expect("bundle metadata");
    let compressed_len = metadata.len() as usize;
    assert!(compressed_len > 0);
    assert!(
        compressed_len <= MAX_COMPRESSED_BYTES,
        "Compressed size ({compressed_len}) must be <= {MAX_COMPRESSED_BYTES}"
    );

    // Verify Unix file permissions 0600
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Support bundle file must have strict permissions 0600, got {:04o}",
            mode
        );
    }

    // Extract archive and verify constituent files
    let extract_dir = temp_root.join("extracted");
    unpack_archive(&output_archive, &extract_dir);

    assert!(extract_dir.join("manifest.json").is_file());
    assert!(extract_dir.join("system_info.json").is_file());
    assert!(extract_dir.join("healthcheck.json").is_file());
    assert!(extract_dir.join("config_audit.json").is_file());
    assert!(extract_dir.join("recent_logs.jsonl").is_file());

    // Verify manifest contents
    let manifest_raw = fs::read_to_string(extract_dir.join("manifest.json")).unwrap();
    let manifest: SupportBundleManifest = serde_json::from_str(&manifest_raw).unwrap();
    assert_eq!(manifest.manifest_version, "1.0");
    assert_eq!(manifest.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest.files.len(), 4); // system_info, healthcheck, config_audit, recent_logs

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_support_bundle_secret_redaction() {
    let temp_root = std::env::temp_dir().join(format!("test_bundle_redact_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    let config_dir = temp_root.join("config");
    let log_dir = temp_root.join("log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    // 1. Private key file
    let secret_key_material = "TOP_SECRET_SERVER_PRIVATE_ED25519_KEY_BYTES_DO_NOT_LEAK";
    fs::write(
        config_dir.join("id_ed25519"),
        secret_key_material.as_bytes(),
    )
    .unwrap();

    // 2. Sensitive configuration file
    let sensitive_db_pass = "DATABASE_ADMIN_PASSWORD_SUPER_SECRET_123";
    let sensitive_token = "BEARER_AUTH_TOKEN_XYZ_789";
    let sensitive_relay_key = "TOP_SECRET_RELAY_KEY_VALUE";
    let config_content = format!(
        "[server]\nkey = {sensitive_relay_key}\npassword = {sensitive_db_pass}\ntoken = {sensitive_token}\npublic_setting = allowed\n"
    );
    fs::write(
        config_dir.join("camellia-remote.ini"),
        config_content.as_bytes(),
    )
    .unwrap();

    // 3. Log file containing passwords, tokens, and raw IP addresses
    let log_pass = "PLAINTEXT_LOG_PASSWORD_456";
    let log_token = "PLAINTEXT_LOG_TOKEN_789";
    let raw_ip = "192.168.10.45";
    let raw_socket = "192.168.10.45:21116";
    let log_line = format!(
        "2026-11-16 02:00:00 INFO Connection from {raw_socket} authenticated password={log_pass} token={log_token}\n"
    );
    fs::write(log_dir.join("camellia-remote.log"), log_line.as_bytes()).unwrap();

    let output_archive = temp_root.join("redacted_bundle.tar.gz");
    let options = SupportBundleOptions {
        output_path: Some(output_archive.clone()),
        config_dir: Some(config_dir),
        log_dir: Some(log_dir),
        max_uncompressed_bytes: None,
        max_compressed_bytes: None,
        custom_secret_canaries: Vec::new(),
    };

    export_support_bundle(&temp_root, &options).expect("export support bundle with redactions");

    let extract_dir = temp_root.join("extracted");
    unpack_archive(&output_archive, &extract_dir);

    // Read all extracted content
    let config_audit_str = fs::read_to_string(extract_dir.join("config_audit.json")).unwrap();
    let recent_logs_str = fs::read_to_string(extract_dir.join("recent_logs.jsonl")).unwrap();

    // Verify ZERO presence of sensitive secrets
    assert!(
        !config_audit_str.contains(secret_key_material),
        "Private key content must NEVER be present in bundle"
    );
    assert!(
        !config_audit_str.contains(sensitive_db_pass),
        "Database password must NEVER be present in bundle"
    );
    assert!(
        !config_audit_str.contains(sensitive_token),
        "Auth token must NEVER be present in bundle"
    );
    assert!(
        !config_audit_str.contains(sensitive_relay_key),
        "Relay secret key must NEVER be present in bundle"
    );
    assert!(
        !recent_logs_str.contains(log_pass),
        "Log password must NEVER be present in bundle"
    );
    assert!(
        !recent_logs_str.contains(log_token),
        "Log token must NEVER be present in bundle"
    );

    // Verify redaction placeholders
    assert!(
        config_audit_str.contains("[REDACTED_PRIVATE_KEY]"),
        "id_ed25519 content must be replaced with [REDACTED_PRIVATE_KEY]"
    );
    assert!(
        config_audit_str.contains("[REDACTED]"),
        "Secret config values must be replaced with [REDACTED]"
    );
    assert!(
        recent_logs_str.contains("[REDACTED]"),
        "Log secrets must be replaced with [REDACTED]"
    );

    // Verify IP masking
    assert!(
        !recent_logs_str.contains(raw_ip),
        "Raw IP address ({raw_ip}) must be masked"
    );
    assert!(
        recent_logs_str.contains("192.168.10.***"),
        "Masked IP prefix (192.168.10.***) must be present"
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_secondary_canary_scanner_fail_closed_deletion() {
    let temp_root = std::env::temp_dir().join(format!("test_bundle_canary_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    let config_dir = temp_root.join("config");
    fs::create_dir_all(&config_dir).unwrap();

    // In disguise: a file named notes.txt containing a private key canary
    let canary_string = "BEGIN OPENSSH PRIVATE KEY";
    fs::write(
        config_dir.join("notes.txt"),
        format!("Important header: {canary_string}\n"),
    )
    .unwrap();

    let output_archive = temp_root.join("canary_bundle.tar.gz");
    let options = SupportBundleOptions {
        output_path: Some(output_archive.clone()),
        config_dir: Some(config_dir),
        log_dir: None,
        max_uncompressed_bytes: None,
        max_compressed_bytes: None,
        custom_secret_canaries: Vec::new(),
    };

    let result = export_support_bundle(&temp_root, &options);
    assert!(
        result.is_err(),
        "Export must fail when sensitive canary pattern matches"
    );
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("canary"),
        "Error message must mention canary detection, got: {err_msg}"
    );

    // Fail-closed verification: output file must be deleted immediately
    assert!(
        !output_archive.exists(),
        "Bundle archive must be deleted immediately upon canary detection"
    );

    // Test custom canary detection
    let custom_canary = "SUPER_CUSTOM_LEAKED_CANARY_TOKEN_999";
    let config_dir2 = temp_root.join("config2");
    fs::create_dir_all(&config_dir2).unwrap();
    fs::write(
        config_dir2.join("custom.txt"),
        format!("Data: {custom_canary}\n"),
    )
    .unwrap();

    let output_archive2 = temp_root.join("custom_canary_bundle.tar.gz");
    let options2 = SupportBundleOptions {
        output_path: Some(output_archive2.clone()),
        config_dir: Some(config_dir2),
        log_dir: None,
        max_uncompressed_bytes: None,
        max_compressed_bytes: None,
        custom_secret_canaries: vec![custom_canary.to_string()],
    };

    let result2 = export_support_bundle(&temp_root, &options2);
    assert!(result2.is_err());
    assert!(
        !output_archive2.exists(),
        "Custom canary bundle must be deleted"
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_uncompressed_and_compressed_size_bounds_enforcement() {
    let temp_root = std::env::temp_dir().join(format!("test_bundle_bounds_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    let output_archive = temp_root.join("oversized.tar.gz");

    // 1. Uncompressed limit bound: tiny 50-byte budget
    let options_uncompressed = SupportBundleOptions {
        output_path: Some(output_archive.clone()),
        config_dir: None,
        log_dir: None,
        max_uncompressed_bytes: Some(50),
        max_compressed_bytes: None,
        custom_secret_canaries: Vec::new(),
    };

    let res1 = export_support_bundle(&temp_root, &options_uncompressed);
    assert!(res1.is_err());
    let err1 = res1.err().unwrap().to_string();
    assert!(err1.contains("exceeds maximum"));
    assert!(!output_archive.exists());

    // 2. Compressed limit bound: tiny 10-byte budget
    let options_compressed = SupportBundleOptions {
        output_path: Some(output_archive.clone()),
        config_dir: None,
        log_dir: None,
        max_uncompressed_bytes: Some(10 * 1024 * 1024),
        max_compressed_bytes: Some(10),
        custom_secret_canaries: Vec::new(),
    };

    let res2 = export_support_bundle(&temp_root, &options_compressed);
    assert!(res2.is_err());
    let err2 = res2.err().unwrap().to_string();
    assert!(err2.contains("exceeds maximum"));
    assert!(!output_archive.exists());

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_structured_event_logging_and_correlation_propagation() {
    // 1. Test CorrelationContextExt validation & fail-closed regeneration
    let random_ctx = CorrelationContext::new_random();
    assert_eq!(random_ctx.trace_id.len(), 32);
    assert_eq!(random_ctx.attempt_id.len(), 16);

    let malformed_ctx =
        CorrelationContext::new_validated("not_hex_invalid_chars!!", "bad_attempt!", Some(101));
    assert_ne!(malformed_ctx.trace_id, "not_hex_invalid_chars!!");
    assert_eq!(malformed_ctx.trace_id.len(), 32);
    assert_eq!(malformed_ctx.session_id, 101);

    // 2. Test rendezvous_registration event
    let peer_id = "test-peer-987654";
    let addr: SocketAddr = "192.168.1.120:21116".parse().unwrap();
    let reg_event = StructuredEvent::new(
        "remote-server",
        "INFO",
        "rendezvous_registration",
        &random_ctx.trace_id,
        &random_ctx.attempt_id,
    )
    .with_stage("rendezvous")
    .with_result("ok")
    .with_peer_id(peer_id)
    .with_endpoint(addr)
    .with_attribute("protocol_version", "1.0.1")
    .with_attribute("serial", 42);

    assert_eq!(reg_event.schema_version, STRUCTURED_SCHEMA_VERSION);
    assert_eq!(reg_event.event, "rendezvous_registration");
    assert_eq!(reg_event.peer_id_hash, Some(hash_peer_id(peer_id)));
    assert_eq!(reg_event.endpoint_masked, Some(mask_socket_addr(addr)));

    let json_reg = reg_event.to_json().unwrap();
    assert!(json_reg.contains("\"event\":\"rendezvous_registration\""));
    assert!(json_reg.contains("\"schema_version\":\"1.0.0\""));
    assert!(json_reg.contains(&format!("\"peer_id_hash\":\"{}\"", hash_peer_id(peer_id))));

    // 3. Test rendezvous_punch_hole & rendezvous_relay_fallback events
    let correlation = CorrelationContext::new_random();
    let punch_event = StructuredEvent::from_correlation(
        "remote-server",
        "INFO",
        "rendezvous_punch_hole",
        &correlation,
    )
    .with_stage("rendezvous")
    .with_peer_id(peer_id)
    .with_endpoint(addr)
    .with_result("direct_punch");

    assert_eq!(punch_event.trace_id, correlation.trace_id);
    assert_eq!(punch_event.attempt_id, correlation.attempt_id);

    let fallback_event = StructuredEvent::from_correlation(
        "remote-server",
        "INFO",
        "rendezvous_relay_fallback",
        &correlation,
    )
    .with_stage("rendezvous")
    .with_peer_id(peer_id)
    .with_endpoint(addr)
    .with_attribute("relay_server", "relay.camellia.example.com:21117");

    let json_fallback = fallback_event.to_json().unwrap();
    assert!(json_fallback.contains("\"event\":\"rendezvous_relay_fallback\""));
    assert!(json_fallback.contains("relay.camellia.example.com:21117"));

    // 4. Test relay_allocated and relay_closed events
    let relay_alloc_event =
        StructuredEvent::from_correlation("remote-server", "INFO", "relay_allocated", &correlation)
            .with_stage("relay")
            .with_result("ok")
            .with_endpoint(addr)
            .with_attribute("uuid_pseudo", "pseudo-1234");

    let json_alloc = relay_alloc_event.to_json().unwrap();
    assert!(json_alloc.contains("\"event\":\"relay_allocated\""));
    assert!(json_alloc.contains("\"stage\":\"relay\""));

    let relay_closed_event =
        StructuredEvent::from_correlation("remote-server", "INFO", "relay_closed", &correlation)
            .with_stage("relay")
            .with_result("normal_close")
            .with_endpoint(addr)
            .with_duration_ms(15_420)
            .with_attribute("byte_count", 1_048_576u64)
            .with_attribute("close_reason", "normal_close");

    let json_closed = relay_closed_event.to_json().unwrap();
    assert!(json_closed.contains("\"event\":\"relay_closed\""));
    assert!(json_closed.contains("\"duration_ms\":15420"));
    assert!(json_closed.contains("\"byte_count\":1048576"));
    assert!(json_closed.contains("\"close_reason\":\"normal_close\""));

    // 5. Verify round-trip deserialization
    let deserialized: StructuredEvent = serde_json::from_str(&json_closed).unwrap();
    assert_eq!(deserialized.event, "relay_closed");
    assert_eq!(deserialized.duration_ms, Some(15_420));
}
