use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use camellia_remote_protocol::{
    anyhow::{anyhow, Context as _},
    bail,
    crypto::sign,
    tokio, ResultType,
};
use dns_lookup::{lookup_addr, lookup_host};
use sqlx::Connection as _;
use std::{
    env,
    net::{IpAddr, TcpStream, ToSocketAddrs as _},
    process,
    str::{self, FromStr as _},
    time::{Duration, Instant},
};

const HEALTHCHECK_TOTAL_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTHCHECK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const HEALTHCHECK_MAX_ENDPOINTS: usize = 8;
const DOCTOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

fn print_help() {
    println!(
        "Usage:
    camellia-remote-utils [command]\n
Available Commands:
    genkeypair                                   Generate a new keypair
    validatekeypair [public key] [secret key]    Validate an existing keypair
    doctor [remote-server]                       Check for server connection problems
    healthcheck [options] [host:port]            Verify server reachability and business readiness\n
Options for healthcheck:
    --readiness                                  Verify rendezvous control channel responsiveness (handshake + Hc)
    --sqlite <path|url>                          Verify SQLite read liveness (SELECT 1)
    --timeout <seconds>                          Set probe timeout in seconds (default 3)"
    );
}

fn error_then_help(msg: &str) -> ! {
    eprintln!("ERROR: {msg}\n");
    print_help();
    process::exit(2);
}

fn gen_keypair() {
    let (pk, sk) = sign::gen_keypair();
    let public_key = BASE64.encode(pk);
    let secret_key = BASE64.encode(sk);
    println!("Public Key:  {public_key}");
    println!("Secret Key:  {secret_key}");
}

fn validate_keypair(pk: &str, sk: &str) -> ResultType<()> {
    let secret_key_bytes = BASE64.decode(sk).context("Invalid secret key encoding")?;
    let secret_key = sign::SecretKey::from_slice(&secret_key_bytes)
        .ok_or_else(|| anyhow!("Invalid secret key length"))?;
    let public_key_bytes = BASE64.decode(pk).context("Invalid public key encoding")?;
    let public_key = sign::PublicKey::from_slice(&public_key_bytes)
        .ok_or_else(|| anyhow!("Invalid public key length"))?;

    let random_data_to_test = b"This is meh.";
    let signed_data = sign::sign(random_data_to_test, &secret_key);
    let verified_data =
        sign::verify(&signed_data, &public_key).map_err(|_| anyhow!("Key pair is INVALID"))?;

    if random_data_to_test != &verified_data[..] {
        bail!("Key pair is INVALID");
    }

    Ok(())
}

fn doctor_tcp(address: IpAddr, port: u16, description: &str) -> bool {
    let start = std::time::Instant::now();
    let endpoint = std::net::SocketAddr::new(address, port);
    match TcpStream::connect_timeout(&endpoint, DOCTOR_CONNECT_TIMEOUT) {
        Ok(_) => {
            println!(
                "TCP Port {} ({}): OK in {} ms",
                port,
                description,
                start.elapsed().as_millis()
            );
            true
        }
        Err(err) => {
            println!("TCP Port {port} ({description}): ERROR ({err})");
            false
        }
    }
}

fn doctor_ip(server_ip_address: IpAddr, server_address: Option<&str>) -> bool {
    println!("\nChecking IP address: {server_ip_address}");
    println!("Is IPV4: {}", server_ip_address.is_ipv4());
    println!("Is IPV6: {}", server_ip_address.is_ipv6());

    // reverse dns lookup
    // TODO: (check) doesn't seem to do reverse lookup on OSX...
    match lookup_addr(&server_ip_address) {
        Ok(reverse) => {
            if let Some(server_address) = server_address {
                if reverse == server_address {
                    println!("Reverse DNS lookup: '{reverse}' MATCHES server address");
                } else {
                    println!(
                        "Reverse DNS lookup: '{reverse}' DOESN'T MATCH server address '{server_address}'"
                    );
                }
            }
        }
        Err(err) => println!("Reverse DNS lookup: unavailable ({err})"),
    }

    let checks = [
        (21115, "identity NAT test"),
        (21116, "identity rendezvous"),
        (21117, "relay"),
        (21118, "identity WebSocket"),
        (21119, "relay WebSocket"),
    ];
    let mut healthy = true;
    for (port, description) in checks {
        healthy &= doctor_tcp(server_ip_address, port, description);
    }
    println!("UDP Port 21116 (identity rendezvous): not actively probed");
    healthy
}

fn doctor(server_address_unclean: &str) -> ResultType<()> {
    let server_address3 = server_address_unclean.trim();
    let server_address2 = server_address3.to_lowercase();
    let server_address = server_address2.as_str();
    println!("Checking server:  {server_address}\n");
    if let Ok(server_ipaddr) = server_address.parse::<IpAddr>() {
        // user requested an ip address
        if !doctor_ip(server_ipaddr, None) {
            bail!("One or more Camellia server TCP listeners are unreachable");
        }
    } else {
        // the passed string is not an ip address
        let ips: Vec<std::net::IpAddr> = lookup_host(server_address)?.collect();
        if ips.is_empty() {
            bail!("No IP addresses resolved for {server_address}");
        }
        println!("Found {} IP addresses: ", ips.len());

        ips.iter().for_each(|ip| println!(" - {ip}"));

        let mut healthy = true;
        for ip in ips {
            healthy &= doctor_ip(ip, Some(server_address));
        }
        if !healthy {
            bail!("One or more Camellia server TCP listeners are unreachable");
        }
    }
    Ok(())
}

pub async fn check_sqlite_liveness(path_or_url: &str, timeout_dur: Duration) -> ResultType<()> {
    use sqlx::Row;
    let opt = if path_or_url.starts_with("sqlite:") {
        sqlx::sqlite::SqliteConnectOptions::from_str(path_or_url)?
    } else {
        sqlx::sqlite::SqliteConnectOptions::new().filename(path_or_url)
    };
    let opt = opt
        .create_if_missing(false)
        .read_only(true)
        .busy_timeout(timeout_dur);

    let mut conn = tokio::time::timeout(timeout_dur, sqlx::SqliteConnection::connect_with(&opt))
        .await
        .map_err(|_| anyhow!("SQLite connection timed out"))?
        .with_context(|| format!("Failed to connect to SQLite at {path_or_url}"))?;

    let row = tokio::time::timeout(timeout_dur, sqlx::query("SELECT 1;").fetch_one(&mut conn))
        .await
        .map_err(|_| anyhow!("SQLite query timed out"))?
        .with_context(|| format!("Failed to execute read probe on SQLite at {path_or_url}"))?;

    let val: i32 = row.try_get(0).context("Invalid column 0 in query result")?;
    if val != 1 {
        bail!("Unexpected SQLite probe result: {val}");
    }
    Ok(())
}

pub async fn probe_rendezvous_channel(endpoint: &str, timeout_dur: Duration) -> ResultType<()> {
    let endpoints: Vec<std::net::SocketAddr> = endpoint
        .to_socket_addrs()
        .with_context(|| format!("Invalid rendezvous endpoint: {endpoint}"))?
        .collect();
    if endpoints.is_empty() {
        bail!("No socket addresses resolved for {endpoint}");
    }

    let mut last_err = anyhow!("Could not connect to any resolved address for {endpoint}");
    for addr in endpoints {
        match probe_single_rendezvous_channel(addr, timeout_dur).await {
            Ok(()) => return Ok(()),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

async fn probe_single_rendezvous_channel(
    addr: std::net::SocketAddr,
    timeout_dur: Duration,
) -> ResultType<()> {
    use camellia_remote_protocol::{
        crypto::{box_, secretbox, sign},
        protobuf::{Enum as _, Message as _},
        rendezvous_proto::{
            register_pk_response, rendezvous_message, HealthCheck, KeyExchange, RendezvousMessage,
        },
        tcp::{CipherRole, Encrypt, FramedStream},
    };

    tokio::time::timeout(timeout_dur, async {
        let tcp_stream = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect failed to {addr}"))?;
        let mut stream = FramedStream::from(tcp_stream, addr);

        // 1. Await KeyExchange from server
        let bytes = stream
            .next_timeout(timeout_dur.as_millis() as u64)
            .await
            .ok_or_else(|| anyhow!("Timed out waiting for rendezvous server key exchange"))?
            .map_err(|e| anyhow!("Failed to read server key exchange: {e}"))?;
        let server_msg = RendezvousMessage::parse_from_bytes(&bytes)
            .map_err(|e| anyhow!("Invalid server rendezvous message: {e}"))?;
        let Some(rendezvous_message::Union::KeyExchange(server_ke)) = server_msg.union else {
            bail!("Expected KeyExchange from rendezvous server");
        };
        if server_ke.keys.is_empty() {
            bail!("Empty KeyExchange keys received from rendezvous server");
        }
        let server_signed_pk = &server_ke.keys[0];
        if server_signed_pk.len() < sign::SIGNATUREBYTES + box_::PUBLICKEYBYTES {
            bail!(
                "Server signed public key too short ({} bytes)",
                server_signed_pk.len()
            );
        }
        let server_box_pk_bytes =
            &server_signed_pk[sign::SIGNATUREBYTES..sign::SIGNATUREBYTES + box_::PUBLICKEYBYTES];
        let server_box_pk = box_::PublicKey::from_slice(server_box_pk_bytes)
            .ok_or_else(|| anyhow!("Invalid server box public key"))?;

        // 2. Build and send client KeyExchange response
        let (client_tmp_pk, client_tmp_sk) = box_::gen_keypair();
        let session_key = secretbox::gen_key();
        let envelope = Encrypt::encode_session_key(&session_key);
        let sealed = box_::seal(
            &envelope,
            &box_::Nonce([0; box_::NONCEBYTES]),
            &server_box_pk,
            &client_tmp_sk,
        )
        .map_err(|_| anyhow!("Failed to seal session key envelope"))?;

        let mut ke_msg = RendezvousMessage::new();
        ke_msg.set_key_exchange(KeyExchange {
            keys: vec![client_tmp_pk.0.to_vec().into(), sealed.into()],
            ..Default::default()
        });
        stream
            .send(&ke_msg)
            .await
            .map_err(|e| anyhow!("Failed to send client key exchange: {e}"))?;

        // 3. Set encrypted mode
        stream.set_key(session_key, CipherRole::Initiator);

        // 4. Send HealthCheck (Hc) probe
        let mut hc_msg = RendezvousMessage::new();
        let mut hc = HealthCheck::new();
        hc.token = "healthcheck-readiness-probe".to_string();
        hc_msg.set_hc(hc);
        stream
            .send(&hc_msg)
            .await
            .map_err(|e| anyhow!("Failed to send Hc probe: {e}"))?;

        // 5. Await response and verify OK
        let resp_bytes = stream
            .next_timeout(timeout_dur.as_millis() as u64)
            .await
            .ok_or_else(|| anyhow!("Timed out waiting for rendezvous Hc response"))?
            .map_err(|e| anyhow!("Failed to read rendezvous Hc response: {e}"))?;
        let resp_msg = RendezvousMessage::parse_from_bytes(&resp_bytes)
            .map_err(|e| anyhow!("Invalid rendezvous response: {e}"))?;
        match resp_msg.union {
            Some(rendezvous_message::Union::RegisterPkResponse(rpr)) => {
                if rpr.result.value() == register_pk_response::Result::OK.value() {
                    Ok(())
                } else {
                    bail!("Rendezvous probe returned non-OK result: {:?}", rpr.result)
                }
            }
            other => bail!("Unexpected rendezvous probe response: {:?}", other),
        }
    })
    .await
    .map_err(|_| anyhow!("Rendezvous channel probe timed out for {addr}"))?
}

#[derive(Default, Debug, Clone)]
pub struct HealthcheckConfig {
    pub endpoint: Option<String>,
    pub readiness: bool,
    pub sqlite: Option<String>,
    pub timeout: Duration,
}

pub fn healthcheck_with_config(config: &HealthcheckConfig) -> ResultType<()> {
    let timeout = if config.timeout.is_zero() {
        HEALTHCHECK_TOTAL_TIMEOUT
    } else {
        config.timeout
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to initialize async runtime")?;

    rt.block_on(async {
        if let Some(sqlite_path) = &config.sqlite {
            check_sqlite_liveness(sqlite_path, timeout).await?;
        }

        if let Some(endpoint) = &config.endpoint {
            if config.readiness {
                probe_rendezvous_channel(endpoint, timeout).await?;
            } else {
                healthcheck(endpoint)?;
            }
        } else if config.sqlite.is_none() {
            bail!("healthcheck requires either a host:port endpoint or --sqlite");
        }
        Ok(())
    })
}

pub fn healthcheck(endpoint: &str) -> ResultType<()> {
    let endpoints = endpoint
        .to_socket_addrs()
        .with_context(|| format!("Invalid healthcheck endpoint: {endpoint}"))?;
    let started_at = Instant::now();
    for endpoint in endpoints.take(HEALTHCHECK_MAX_ENDPOINTS) {
        let Some(remaining) = HEALTHCHECK_TOTAL_TIMEOUT.checked_sub(started_at.elapsed()) else {
            break;
        };
        if TcpStream::connect_timeout(&endpoint, remaining.min(HEALTHCHECK_ATTEMPT_TIMEOUT)).is_ok()
        {
            return Ok(());
        }
    }
    bail!("TCP healthcheck failed: {endpoint}");
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 1 {
        print_help();
        return;
    }

    let command = args[1].to_lowercase();
    match command.as_str() {
        "help" | "-h" | "--help" => print_help(),
        "-v" | "--version" => println!("camellia-remote-utils {}", env!("CARGO_PKG_VERSION")),
        "genkeypair" => gen_keypair(),
        "validatekeypair" => {
            if args.len() <= 3 {
                error_then_help("You must supply both the public and the secret key");
            }
            let res = validate_keypair(args[2].as_str(), args[3].as_str());
            if let Err(e) = res {
                println!("{e}");
                process::exit(0x0001);
            }
            println!("Key pair is VALID");
        }
        "doctor" => {
            if args.len() <= 2 {
                error_then_help("You must supply the Camellia Remote server address");
            }
            if let Err(err) = doctor(args[2].as_str()) {
                eprintln!("{err}");
                process::exit(0x0001);
            }
        }
        "healthcheck" => {
            let mut cfg = HealthcheckConfig::default();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--readiness" => {
                        cfg.readiness = true;
                    }
                    "--sqlite" => {
                        i += 1;
                        if i >= args.len() {
                            error_then_help("--sqlite requires a path or URL argument");
                        }
                        cfg.sqlite = Some(args[i].clone());
                    }
                    "--timeout" => {
                        i += 1;
                        if i >= args.len() {
                            error_then_help("--timeout requires a number in seconds");
                        }
                        let secs = args[i].parse::<u64>().unwrap_or_else(|_| {
                            error_then_help("Invalid --timeout number");
                        });
                        cfg.timeout = Duration::from_secs(secs);
                    }
                    other if !other.starts_with('-') => {
                        if cfg.endpoint.is_some() {
                            error_then_help("Multiple endpoints provided");
                        }
                        cfg.endpoint = Some(other.to_string());
                    }
                    unknown => {
                        error_then_help(&format!("Unknown healthcheck option: {unknown}"));
                    }
                }
                i += 1;
            }
            if cfg.endpoint.is_none() && cfg.sqlite.is_none() {
                error_then_help("You must supply a host:port endpoint or --sqlite");
            }
            if let Err(err) = healthcheck_with_config(&cfg) {
                eprintln!("{err:#}");
                process::exit(0x0001);
            }
            println!("Healthcheck: OK");
        }
        _ => error_then_help("Unknown command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camellia_remote_protocol::{
        crypto::{box_, sign},
        protobuf::Message as _,
        rendezvous_proto::{
            register_pk_response, rendezvous_message, KeyExchange, RegisterPkResponse,
            RendezvousMessage,
        },
        tcp::{CipherRole, Encrypt, FramedStream},
    };
    use std::net::TcpListener;

    #[test]
    fn healthcheck_accepts_reachable_tcp_endpoint() -> ResultType<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = listener.local_addr()?.to_string();

        healthcheck(&endpoint)
    }

    #[test]
    fn healthcheck_rejects_invalid_endpoint() {
        assert!(healthcheck("127.0.0.1:not-a-port").is_err());
    }

    #[tokio::test]
    async fn sqlite_liveness_check_succeeds_on_valid_database() -> ResultType<()> {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("test_sqlite_{}.db", std::process::id()));
        let url = format!("sqlite://{}?mode=rwc", db_path.display());
        let opt = sqlx::sqlite::SqliteConnectOptions::from_str(&url)?.create_if_missing(true);
        let mut conn = sqlx::SqliteConnection::connect_with(&opt).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY);")
            .execute(&mut conn)
            .await?;
        drop(conn);

        check_sqlite_liveness(db_path.to_str().unwrap(), Duration::from_secs(2)).await?;
        let _ = std::fs::remove_file(&db_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_liveness_check_fails_on_corrupt_file() {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("corrupt_sqlite_{}.db", std::process::id()));
        std::fs::write(&db_path, b"not a valid sqlite header").unwrap();

        let res = check_sqlite_liveness(db_path.to_str().unwrap(), Duration::from_secs(1)).await;
        let _ = std::fs::remove_file(&db_path);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn probe_rendezvous_channel_succeeds_with_responsive_handshake_and_hc() -> ResultType<()>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let (_server_pk, server_sk) = sign::gen_keypair();

        tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let mut stream = FramedStream::from(stream, peer_addr);

            // Send server KeyExchange
            let (server_tmp_pk, server_tmp_sk) = box_::gen_keypair();
            let signed_pk = sign::sign(&server_tmp_pk.0, &server_sk);
            let mut ke_msg = RendezvousMessage::new();
            ke_msg.set_key_exchange(KeyExchange {
                keys: vec![signed_pk.into()],
                ..Default::default()
            });
            stream.send(&ke_msg).await.unwrap();

            // Await client KeyExchange
            let bytes = stream.next_timeout(2000).await.unwrap().unwrap();
            let client_msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            let Some(rendezvous_message::Union::KeyExchange(client_ke)) = client_msg.union else {
                panic!("Expected client KeyExchange");
            };
            let client_tmp_pk_bytes = &client_ke.keys[0];
            let client_ciphertext = &client_ke.keys[1];
            let key =
                Encrypt::decode(client_ciphertext, client_tmp_pk_bytes, &server_tmp_sk).unwrap();
            stream.set_key(key, CipherRole::Responder);

            // Await client Hc
            let bytes = stream.next_timeout(2000).await.unwrap().unwrap();
            let hc_msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            assert!(matches!(
                hc_msg.union,
                Some(rendezvous_message::Union::Hc(_))
            ));

            // Send RegisterPkResponse(OK)
            let mut resp = RendezvousMessage::new();
            resp.set_register_pk_response(RegisterPkResponse {
                result: register_pk_response::Result::OK.into(),
                keep_alive: 120,
                ..Default::default()
            });
            stream.send(&resp).await.unwrap();
        });

        probe_rendezvous_channel(&addr.to_string(), Duration::from_secs(3)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn probe_rendezvous_channel_fails_on_broken_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(b"not a valid handshake").await;
        });

        let res = probe_rendezvous_channel(&addr.to_string(), Duration::from_millis(500)).await;
        assert!(res.is_err());
    }
}
