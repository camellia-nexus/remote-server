use camellia_remote_protocol::tokio;
use camellia_remote_server::common::{
    mask_ip_str, pseudonymize_pk, pseudonymize_uuid, verify_console_auth,
};
use sqlx::Connection as _;
use std::fs;
use std::net::TcpListener;
use std::process::Command;

#[test]
fn test_log003_pseudonymization_and_masking_contracts() {
    // 1. Raw UUID masking contract
    let raw_uuid = "c0ffee00-1234-5678-9abc-def012345678";
    let masked_uuid = pseudonymize_uuid(raw_uuid.as_bytes());
    assert!(masked_uuid.starts_with("uuid#"));
    assert!(!masked_uuid.contains(raw_uuid));
    assert_eq!(masked_uuid.len(), 13); // "uuid#" (5) + 8 hex chars

    let empty_masked = pseudonymize_uuid(b"");
    assert_eq!(empty_masked, "<empty-uuid>");

    // 2. Public key pseudonymization contract
    let raw_pk = [0x5au8; 32];
    let masked_pk = pseudonymize_pk(raw_pk);
    assert!(masked_pk.starts_with("pk#"));
    assert_eq!(masked_pk.len(), 11); // "pk#" (3) + 8 hex chars

    // 3. IP masking contract
    let ipv4 = "192.168.1.100";
    let masked_v4 = mask_ip_str(ipv4);
    assert_eq!(masked_v4, "192.168.1.***");

    let ipv6 = "2001:db8:85a3::8a2e:370:7334";
    let masked_v6 = mask_ip_str(ipv6);
    assert!(masked_v6.contains("***"));
}

#[test]
fn test_trust002_runtime_console_authentication_contracts() {
    let expected_token = "production-auth-token-98765";

    // Non-matching, missing, or malformed credentials must fail closed
    assert_eq!(verify_console_auth("", expected_token), None);
    assert_eq!(verify_console_auth("status", expected_token), None);
    assert_eq!(
        verify_console_auth("wrong-token status", expected_token),
        None
    );
    assert_eq!(
        verify_console_auth("AUTH wrong-token status", expected_token),
        None
    );

    // Exact constant-time matching credentials succeed
    assert_eq!(
        verify_console_auth("AUTH production-auth-token-98765 status", expected_token),
        Some("status")
    );
    assert_eq!(
        verify_console_auth("production-auth-token-98765 help", expected_token),
        Some("help")
    );
    assert_eq!(
        verify_console_auth("auth production-auth-token-98765\nmetrics", expected_token),
        Some("metrics")
    );
}

#[test]
fn test_deploy002_healthcheck_cli_readiness_and_sqlite_contracts() {
    let utils_bin = env!("CARGO_BIN_EXE_camellia-remote-utils");

    // 1. Unreachable port fails closed
    let output = Command::new(utils_bin)
        .args(["healthcheck", "127.0.0.1:1"])
        .output()
        .expect("failed to run healthcheck on unreachable port");
    assert!(!output.status.success());

    // 2. Reachable TCP port succeeds
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    let output = Command::new(utils_bin)
        .args(["healthcheck", &format!("127.0.0.1:{}", port)])
        .output()
        .expect("failed to run healthcheck on bound port");
    assert!(output.status.success());
    drop(listener);

    // 3. SQLite liveness probe on valid database
    let temp_dir = std::env::temp_dir().join(format!("batch75_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let db_path = temp_dir.join("test_liveness.sqlite3");

    // Create a real SQLite database file using SQLite header format
    // Or run sqlx in current thread / touch via sqlite
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let opt = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true);
        let mut conn = sqlx::SqliteConnection::connect_with(&opt)
            .await
            .expect("connect");
        sqlx::query("CREATE TABLE probe (id INT);")
            .execute(&mut conn)
            .await
            .expect("query");
    });

    let output = Command::new(utils_bin)
        .args(["healthcheck", "--sqlite", db_path.to_str().unwrap()])
        .output()
        .expect("run sqlite healthcheck");
    assert!(output.status.success());

    // 4. Corrupted SQLite file fails closed
    let corrupt_path = temp_dir.join("corrupt.sqlite3");
    fs::write(&corrupt_path, b"corrupted non-sqlite contents").expect("write corrupt");
    let output = Command::new(utils_bin)
        .args(["healthcheck", "--sqlite", corrupt_path.to_str().unwrap()])
        .output()
        .expect("run corrupt sqlite healthcheck");
    assert!(!output.status.success());

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
