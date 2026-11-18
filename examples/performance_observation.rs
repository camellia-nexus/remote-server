use std::{
    env,
    fs::OpenOptions,
    hint::black_box,
    io::{BufWriter, Write},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::{Duration, Instant},
};

use camellia_remote_protocol::serde_json::{json, to_writer};
use camellia_remote_server::common::TrustedProxyConfig;
use tungstenite::http::{HeaderMap, HeaderValue};

const BATCH_ITERATIONS: usize = 50_000;
const DEFAULT_ITERATIONS: usize = 500_000;
const SCENARIO: &str = "server-trusted-proxy-v1";

fn requested_work_duration() -> Result<Option<Duration>, Box<dyn std::error::Error>> {
    let Some(raw) = env::var_os("CAMELLIA_PERFORMANCE_WORK_SECONDS") else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .ok_or("CAMELLIA_PERFORMANCE_WORK_SECONDS must be UTF-8")?;
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| "CAMELLIA_PERFORMANCE_WORK_SECONDS must be an integer")?;
    if raw != seconds.to_string() || !(1..=60).contains(&seconds) {
        return Err(
            "CAMELLIA_PERFORMANCE_WORK_SECONDS must be a canonical integer in 1..60".into(),
        );
    }
    Ok(Some(Duration::from_secs(seconds)))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        env::var_os("CAMELLIA_PERFORMANCE_OBSERVATION_FILE")
            .ok_or("CAMELLIA_PERFORMANCE_OBSERVATION_FILE is required")?,
    );
    if !output.is_absolute() {
        return Err("performance observation path must be absolute".into());
    }

    let proxies = TrustedProxyConfig::parse(true, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.42, 172.16.0.2, 10.0.0.3"),
    );
    let tcp_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));

    let requested_duration = requested_work_duration()?;
    let started = Instant::now();
    let mut iterations = 0usize;
    loop {
        let remaining =
            requested_duration.map_or(DEFAULT_ITERATIONS - iterations, |_| BATCH_ITERATIONS);
        for _ in 0..remaining.min(BATCH_ITERATIONS) {
            let resolved =
                black_box(&proxies).resolve_client_ip(black_box(tcp_peer), black_box(&headers))?;
            if resolved != expected {
                return Err("trusted proxy resolution changed semantics".into());
            }
            black_box(resolved);
        }
        iterations += remaining.min(BATCH_ITERATIONS);
        if requested_duration.is_some_and(|duration| started.elapsed() >= duration)
            || (requested_duration.is_none() && iterations >= DEFAULT_ITERATIONS)
        {
            break;
        }
    }
    let resolve_ns = started.elapsed().as_nanos() as f64 / iterations as f64;
    if !resolve_ns.is_finite() || resolve_ns <= 0.0 {
        return Err("trusted proxy timing is not finite and positive".into());
    }

    let document = json!({
        "metrics": {
            "trusted_proxy_resolve_ns": {
                "direction": "lower",
                "unit": "ns",
                "value": resolve_ns,
            },
        },
        "scenario": SCENARIO,
        "schema": "camellia-performance-observation-v1",
    });
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut writer = BufWriter::new(file);
    to_writer(&mut writer, &document)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}
