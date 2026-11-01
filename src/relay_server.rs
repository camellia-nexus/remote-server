use async_speed_limit::Limiter;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use camellia_remote_protocol::{
    allow_err,
    anyhow::Context as _,
    bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    crypto::sign,
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore},
        time::{interval, Duration},
    },
    ResultType,
};
use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    io::Error,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

type Usage = (usize, usize, usize, usize);

lazy_static::lazy_static! {
    static ref PEERS: Mutex<HashMap<String, PendingRelay>> = Default::default();
    static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
    static ref SHARED_IP_LIMITERS: std::sync::Mutex<HashMap<IpAddr, (Limiter, usize)>> = Default::default();
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

pub(crate) fn is_ip_in_set(set: &HashSet<String>, ip: IpAddr) -> bool {
    let canon = canonical_ip(ip);
    set.contains(&canon.to_string()) || set.contains(&ip.to_string())
}

#[derive(Debug)]
pub(crate) struct IpLimiterGuard {
    ip: IpAddr,
    limiter: Limiter,
}

impl IpLimiterGuard {
    pub(crate) fn acquire(ip: IpAddr) -> Self {
        let canon = canonical_ip(ip);
        let mut map = SHARED_IP_LIMITERS.lock().unwrap();
        let entry = map.entry(canon).or_insert_with(|| {
            let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
            (Limiter::new(sb), 0)
        });
        entry.1 += 1;
        Self {
            ip: canon,
            limiter: entry.0.clone(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn limiter(&self) -> &Limiter {
        &self.limiter
    }
}

impl Drop for IpLimiterGuard {
    fn drop(&mut self) {
        let mut map = SHARED_IP_LIMITERS.lock().unwrap();
        if let Some(entry) = map.get_mut(&self.ip) {
            entry.1 = entry.1.saturating_sub(1);
            if entry.1 == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct AcceptedSocketGuard;

impl AcceptedSocketGuard {
    pub(crate) fn new() -> Self {
        ACCEPTED_SOCKETS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for AcceptedSocketGuard {
    fn drop(&mut self) {
        ACCEPTED_SOCKETS.fetch_sub(1, Ordering::Relaxed);
    }
}

struct PendingRelay {
    stream: Box<dyn StreamTrait>,
    source_ip: IpAddr,
    generation: u64,
    _permit: OwnedSemaphorePermit,
    _socket_guard: AcceptedSocketGuard,
}

static ACCEPTED_SOCKETS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_PAIRS: AtomicUsize = AtomicUsize::new(0);

#[inline]
#[allow(dead_code)]
pub fn accepted_sockets() -> usize {
    ACCEPTED_SOCKETS.load(Ordering::Relaxed)
}

#[inline]
#[allow(dead_code)]
pub fn active_pairs() -> usize {
    ACTIVE_PAIRS.load(Ordering::Relaxed)
}

#[inline]
#[allow(dead_code)]
pub async fn pending_endpoints() -> usize {
    PEERS.lock().await.len()
}

#[derive(Clone)]
struct RelayContext {
    limiter: Limiter,
    key: Arc<str>,
    trust_proxy_headers: bool,
    runtime_console: bool,
    connection_slots: Arc<Semaphore>,
    memory_budget: Arc<crate::common::MemoryBudget>,
}

const DOWNGRADE_THRESHOLD_SCALE: usize = 1_000_000;
static DOWNGRADE_THRESHOLD_SCALED: AtomicUsize = AtomicUsize::new(660_000); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s
static NEXT_PENDING_GENERATION: AtomicU64 = AtomicU64::new(1);
const DEFAULT_MAX_RELAY_CONNECTIONS: usize = 8_192;
const DEFAULT_MAX_RELAY_IN_FLIGHT_BYTES: usize = 256 * 1024 * 1024;
const MAX_PENDING_RELAYS: usize = 4_096;
const MAX_PENDING_RELAYS_PER_IP: usize = 32;
const RELAY_CONTROL_FRAME_MAX: usize = 64 * 1024;
const RELAY_WEBSOCKET_FRAME_MAX: usize = 4 * 1024 * 1024;
const WEBSOCKET_UPGRADE_TIMEOUT_MS: u64 = 10_000;

pub(crate) fn validate_relay_startup_params(
    max_connections: usize,
    max_in_flight_bytes: usize,
) -> ResultType<()> {
    if max_connections < 2 {
        bail!("MAX_RELAY_CONNECTIONS ({max_connections}) must be at least 2");
    }
    if max_in_flight_bytes < RELAY_WEBSOCKET_FRAME_MAX {
        bail!(
            "MAX_RELAY_IN_FLIGHT_BYTES ({max_in_flight_bytes}) must be at least RELAY_WEBSOCKET_FRAME_MAX ({RELAY_WEBSOCKET_FRAME_MAX})"
        );
    }
    Ok(())
}
const RELAY_UUID_MIN_LEN: usize = 8;
const RELAY_UUID_MAX_LEN: usize = 128;
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";
const MAX_IP_LIST_BYTES: usize = 1024 * 1024;
const MAX_IP_LIST_ENTRIES: usize = 65_536;

fn parse_ip_values(value: &str) -> ResultType<Vec<String>> {
    let mut ips = Vec::new();
    for raw_ip in value.split('|') {
        let ip = raw_ip
            .trim()
            .parse::<IpAddr>()
            .with_context(|| format!("Invalid IP address: {raw_ip}"))?;
        let canon = canonical_ip(ip).to_string();
        ips.push(canon);
        if ips.len() > 64 {
            bail!("Too many IP addresses in one command");
        }
    }
    Ok(ips)
}

fn load_ip_list(path: &str) -> ResultType<HashSet<String>> {
    let path = std::path::Path::new(path);
    if matches!(
        std::fs::symlink_metadata(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
    ) {
        return Ok(HashSet::new());
    }
    let contents =
        crate::common::read_bounded_regular_file(path, MAX_IP_LIST_BYTES, "Relay IP list")?;
    let contents = std::str::from_utf8(&contents)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    let mut ips = HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let value = line
            .split_once('#')
            .map_or(line, |(value, _)| value)
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if value.is_empty() {
            continue;
        }
        let ip = value.parse::<IpAddr>().with_context(|| {
            format!(
                "Invalid IP address in {} at line {}",
                path.display(),
                line_index + 1
            )
        })?;
        ips.insert(canonical_ip(ip).to_string());
        if ips.len() > MAX_IP_LIST_ENTRIES {
            bail!("{} contains too many entries", path.display());
        }
    }
    Ok(ips)
}

#[tokio::main(flavor = "multi_thread")]
pub async fn start_with_bind(
    bind_addr: Option<IpAddr>,
    port: &str,
    key: &str,
    trust_proxy_headers: bool,
) -> ResultType<()> {
    let key = get_server_sk(key)?;
    let runtime_console = crate::common::get_yes_no_arg("ENABLE_RUNTIME_CONSOLE", false)?;
    if runtime_console {
        log::warn!("Unauthenticated loopback runtime console is enabled");
    }
    log::info!("trust_proxy_headers: {}", trust_proxy_headers);
    *BLACKLIST.write().await = load_ip_list(BLACKLIST_FILE)?;
    log::info!(
        "#blacklist({}): {}",
        BLACKLIST_FILE,
        BLACKLIST.read().await.len()
    );
    *BLOCKLIST.write().await = load_ip_list(BLOCKLIST_FILE)?;
    log::info!(
        "#blocklist({}): {}",
        BLOCKLIST_FILE,
        BLOCKLIST.read().await.len()
    );
    let port: u16 = port.parse()?;
    if !(1..=65_533).contains(&port) {
        bail!("Port must be between 1 and 65533");
    }
    let max_connections = crate::common::get_bounded_usize_arg(
        "MAX_RELAY_CONNECTIONS",
        DEFAULT_MAX_RELAY_CONNECTIONS,
        2,
        65_536,
    )?;
    let max_in_flight_bytes = crate::common::get_bounded_usize_arg(
        "MAX_RELAY_IN_FLIGHT_BYTES",
        DEFAULT_MAX_RELAY_IN_FLIGHT_BYTES,
        4 * 1024 * 1024,
        16 * 1024 * 1024 * 1024,
    )?;
    validate_relay_startup_params(max_connections, max_in_flight_bytes)?;
    let connection_slots = Arc::new(Semaphore::new(max_connections));
    let memory_budget = Arc::new(crate::common::MemoryBudget::new(max_in_flight_bytes));
    log::info!("MAX_RELAY_CONNECTIONS={max_connections}");
    log::info!("MAX_RELAY_IN_FLIGHT_BYTES={max_in_flight_bytes}");
    check_params()?;
    let context = RelayContext {
        limiter: <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _),
        key: Arc::from(key.as_str()),
        trust_proxy_headers,
        runtime_console,
        connection_slots,
        memory_budget,
    };
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(
                crate::common::listen_tcp(bind_addr, port).await?,
                crate::common::listen_tcp(bind_addr, port2).await?,
                if runtime_console {
                    crate::common::listen_console(bind_addr, port).await?
                } else {
                    None
                },
                context.clone(),
            )
            .await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}

fn parse_downgrade_threshold(value: &str) -> ResultType<usize> {
    let value = value.parse::<f64>()?;
    if !(value.is_finite() && 0.0 < value && value <= 1.0) {
        bail!("DOWNGRADE_THRESHOLD must be greater than 0 and at most 1");
    }
    let scaled = (value * DOWNGRADE_THRESHOLD_SCALE as f64).round() as usize;
    if scaled == 0 {
        bail!("DOWNGRADE_THRESHOLD must be at least 0.000001");
    }
    Ok(scaled)
}

fn parse_downgrade_start(value: &str) -> ResultType<usize> {
    let seconds = value.parse::<usize>()?;
    if seconds == 0 {
        bail!("DOWNGRADE_START_CHECK must be greater than 0");
    }
    seconds.checked_mul(1_000).ok_or_else(|| {
        camellia_remote_protocol::anyhow::anyhow!("DOWNGRADE_START_CHECK is too large")
    })
}

fn parse_bandwidth(name: &str, raw_value: &str) -> ResultType<usize> {
    let raw = raw_value.trim();
    if raw.is_empty() {
        bail!("{name} must not be empty");
    }

    let unit_index = raw
        .find(|c: char| c.is_alphabetic() || c == '/')
        .unwrap_or(raw.len());
    let (num_part, unit_part) = raw.split_at(unit_index);
    let num_str = num_part.trim();
    let unit_str = unit_part.trim();

    let num = num_str.parse::<f64>()?;
    if !num.is_finite() || num <= 0.0 {
        bail!("{name} must be a positive bandwidth supported by this architecture");
    }

    let multiplier: f64 = match unit_str {
        "" => 1024.0 * 1024.0, // default Mb/s
        // Explicit byte units (case-sensitive or byte words)
        "B" | "B/s" | "Bps" | "bytes" | "byte/s" => 8.0,
        "KB" | "KB/s" | "KBps" | "kB" | "kB/s" => 8.0 * 1024.0,
        "MB" | "MB/s" | "MBps" => 8.0 * 1024.0 * 1024.0,
        "GB" | "GB/s" | "GBps" => 8.0 * 1024.0 * 1024.0 * 1024.0,
        u if u.eq_ignore_ascii_case("kib")
            || u.eq_ignore_ascii_case("kib/s")
            || u.eq_ignore_ascii_case("kbyte")
            || u.eq_ignore_ascii_case("kbytes") =>
        {
            8.0 * 1024.0
        }
        u if u.eq_ignore_ascii_case("mib")
            || u.eq_ignore_ascii_case("mib/s")
            || u.eq_ignore_ascii_case("mbyte")
            || u.eq_ignore_ascii_case("mbytes") =>
        {
            8.0 * 1024.0 * 1024.0
        }
        u if u.eq_ignore_ascii_case("gib")
            || u.eq_ignore_ascii_case("gib/s")
            || u.eq_ignore_ascii_case("gbyte")
            || u.eq_ignore_ascii_case("gbytes") =>
        {
            8.0 * 1024.0 * 1024.0 * 1024.0
        }
        // Bit units (case-insensitive)
        u if u.eq_ignore_ascii_case("b/s")
            || u.eq_ignore_ascii_case("bps")
            || u.eq_ignore_ascii_case("bit/s")
            || u.eq_ignore_ascii_case("bits/s") =>
        {
            1.0
        }
        u if u.eq_ignore_ascii_case("k")
            || u.eq_ignore_ascii_case("kb")
            || u.eq_ignore_ascii_case("kbps")
            || u.eq_ignore_ascii_case("kbit")
            || u.eq_ignore_ascii_case("kb/s")
            || u.eq_ignore_ascii_case("kbit/s") =>
        {
            1024.0
        }
        u if u.eq_ignore_ascii_case("m")
            || u.eq_ignore_ascii_case("mb")
            || u.eq_ignore_ascii_case("mbps")
            || u.eq_ignore_ascii_case("mbit")
            || u.eq_ignore_ascii_case("mb/s")
            || u.eq_ignore_ascii_case("mbit/s") =>
        {
            1024.0 * 1024.0
        }
        u if u.eq_ignore_ascii_case("g")
            || u.eq_ignore_ascii_case("gb")
            || u.eq_ignore_ascii_case("gbps")
            || u.eq_ignore_ascii_case("gbit")
            || u.eq_ignore_ascii_case("gb/s")
            || u.eq_ignore_ascii_case("gbit/s") =>
        {
            1024.0 * 1024.0 * 1024.0
        }
        _ => bail!("Unknown bandwidth unit '{unit_str}' in {name}"),
    };

    let bits = num * multiplier;
    if !bits.is_finite() || bits <= 0.0 || bits > usize::MAX as f64 {
        bail!("{name} must be a positive bandwidth supported by this architecture");
    }
    Ok(bits.round() as usize)
}

fn check_params() -> ResultType<()> {
    let downgrade_threshold = match crate::common::get_arg_opt("DOWNGRADE_THRESHOLD")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => parse_downgrade_threshold(&value)?,
        None => DOWNGRADE_THRESHOLD_SCALED.load(Ordering::SeqCst),
    };
    let downgrade_start = match crate::common::get_arg_opt("DOWNGRADE_START_CHECK")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => parse_downgrade_start(&value)?,
        None => DOWNGRADE_START_CHECK.load(Ordering::SeqCst),
    };
    let limit_speed =
        match crate::common::get_arg_opt("LIMIT_SPEED").filter(|value| !value.trim().is_empty()) {
            Some(value) => parse_bandwidth("LIMIT_SPEED", &value)?,
            None => LIMIT_SPEED.load(Ordering::SeqCst),
        };
    let total_bandwidth = match crate::common::get_arg_opt("TOTAL_BANDWIDTH")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => parse_bandwidth("TOTAL_BANDWIDTH", &value)?,
        None => TOTAL_BANDWIDTH.load(Ordering::SeqCst),
    };
    let single_bandwidth = match crate::common::get_arg_opt("SINGLE_BANDWIDTH")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => parse_bandwidth("SINGLE_BANDWIDTH", &value)?,
        None => SINGLE_BANDWIDTH.load(Ordering::SeqCst),
    };
    if limit_speed > single_bandwidth {
        bail!("LIMIT_SPEED must not exceed SINGLE_BANDWIDTH");
    }

    DOWNGRADE_THRESHOLD_SCALED.store(downgrade_threshold, Ordering::SeqCst);
    DOWNGRADE_START_CHECK.store(downgrade_start, Ordering::SeqCst);
    LIMIT_SPEED.store(limit_speed, Ordering::SeqCst);
    TOTAL_BANDWIDTH.store(total_bandwidth, Ordering::SeqCst);
    SINGLE_BANDWIDTH.store(single_bandwidth, Ordering::SeqCst);

    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_SCALED.load(Ordering::SeqCst) as f64 / DOWNGRADE_THRESHOLD_SCALE as f64
    );
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000
    );
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    Ok(())
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = "".to_owned();
    let mut fds = cmd.trim().split(' ');
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                match parse_ip_values(ip) {
                    Ok(ips) => {
                        let mut blacklist = BLACKLIST.write().await;
                        let additions = ips.iter().filter(|ip| !blacklist.contains(*ip)).count();
                        if blacklist.len().saturating_add(additions) > MAX_IP_LIST_ENTRIES {
                            res = "Blacklist entry limit reached\n".to_owned();
                        } else {
                            blacklist.extend(ips);
                        }
                    }
                    Err(err) => res = format!("{err}\n"),
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.write().await.clear();
                } else {
                    match parse_ip_values(ip) {
                        Ok(ips) => {
                            let mut blacklist = BLACKLIST.write().await;
                            for ip in ips {
                                blacklist.remove(&ip);
                            }
                        }
                        Err(err) => res = format!("{err}\n"),
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                match ip.parse::<IpAddr>() {
                    Ok(ip) => {
                        res = format!("{}\n", is_ip_in_set(&*BLACKLIST.read().await, ip));
                    }
                    Err(_) => res = format!("Invalid IP address: {ip}\n"),
                }
            } else {
                for ip in BLACKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                match parse_ip_values(ip) {
                    Ok(ips) => {
                        let mut blocklist = BLOCKLIST.write().await;
                        let additions = ips.iter().filter(|ip| !blocklist.contains(*ip)).count();
                        if blocklist.len().saturating_add(additions) > MAX_IP_LIST_ENTRIES {
                            res = "Blocklist entry limit reached\n".to_owned();
                        } else {
                            blocklist.extend(ips);
                        }
                    }
                    Err(err) => res = format!("{err}\n"),
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.write().await.clear();
                } else {
                    match parse_ip_values(ip) {
                        Ok(ips) => {
                            let mut blocklist = BLOCKLIST.write().await;
                            for ip in ips {
                                blocklist.remove(&ip);
                            }
                        }
                        Err(err) => res = format!("{err}\n"),
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                match ip.parse::<IpAddr>() {
                    Ok(ip) => {
                        res = format!("{}\n", is_ip_in_set(&*BLOCKLIST.read().await, ip));
                    }
                    Err(_) => res = format!("Invalid IP address: {ip}\n"),
                }
            } else {
                for ip in BLOCKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                match parse_downgrade_threshold(v) {
                    Ok(value) => DOWNGRADE_THRESHOLD_SCALED.store(value, Ordering::SeqCst),
                    Err(err) => res = format!("Invalid downgrade threshold: {err}\n"),
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_SCALED.load(Ordering::SeqCst) as f64
                        / DOWNGRADE_THRESHOLD_SCALE as f64
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                match parse_downgrade_start(v) {
                    Ok(value) => DOWNGRADE_START_CHECK.store(value, Ordering::SeqCst),
                    Err(err) => res = format!("Invalid downgrade start: {err}\n"),
                }
            } else {
                res = format!("{}s\n", DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000);
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                match parse_bandwidth("LIMIT_SPEED", v) {
                    Ok(value) => {
                        if value > SINGLE_BANDWIDTH.load(Ordering::SeqCst) {
                            res = "LIMIT_SPEED must not exceed SINGLE_BANDWIDTH\n".to_owned();
                        } else {
                            LIMIT_SPEED.store(value, Ordering::SeqCst);
                        }
                    }
                    Err(err) => res = format!("Invalid limit speed: {err}\n"),
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                match parse_bandwidth("TOTAL_BANDWIDTH", v) {
                    Ok(value) => {
                        TOTAL_BANDWIDTH.store(value, Ordering::SeqCst);
                        limiter.set_speed_limit(value as _);
                    }
                    Err(err) => res = format!("Invalid total bandwidth: {err}\n"),
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                match parse_bandwidth("SINGLE_BANDWIDTH", v) {
                    Ok(value) => {
                        if value < LIMIT_SPEED.load(Ordering::SeqCst) {
                            res = "SINGLE_BANDWIDTH must not be below LIMIT_SPEED\n".to_owned();
                        } else {
                            SINGLE_BANDWIDTH.store(value, Ordering::SeqCst);
                        }
                    }
                    Err(err) => res = format!("Invalid single bandwidth: {err}\n"),
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .read()
                .await
                .iter()
                .map(|x| (x.0.clone(), *x.1))
                .collect();
            tmp.sort_by_key(|(_, usage)| Reverse(usage.1));
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}kb/s {}kb/s {}kb/s",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(
    listener: TcpListener,
    listener2: TcpListener,
    listener_console: Option<TcpListener>,
    context: RelayContext,
) {
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, false, &context).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, true, &context).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = crate::common::accept_or_pending(listener_console.as_ref()) => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        // The console listener never speaks WebSocket, so proxy
                        // headers are never consulted for it.
                        handle_connection(stream, addr, false, &context).await;
                    }
                    Err(err) => {
                       log::error!("console listener.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

async fn handle_connection(stream: TcpStream, addr: SocketAddr, ws: bool, context: &RelayContext) {
    let Ok(permit) = context.connection_slots.clone().try_acquire_owned() else {
        log::warn!("Relay connection limit reached; rejected {}", addr);
        return;
    };
    let socket_guard = AcceptedSocketGuard::new();
    let ip = camellia_remote_protocol::try_into_v4(addr).ip();
    if context.runtime_console && !ws && ip.is_loopback() {
        let limiter = context.limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _socket_guard = socket_guard;
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    stream.write_all(res.as_bytes()).await.ok();
                }
            }
        });
        return;
    }
    if is_ip_in_set(&*BLOCKLIST.read().await, ip) {
        log::info!("{} blocked", ip);
        return;
    }
    let context = context.clone();
    tokio::spawn(async move {
        let res = make_pair(stream, addr, ws, context, permit, socket_guard).await;
        allow_err!(res);
    });
}

// Tungstenite requires its server callback to return a full HTTP response on
// failure; that external API fixes the otherwise-large error representation.
#[allow(clippy::result_large_err)]
async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    ws: bool,
    context: RelayContext,
    permit: OwnedSemaphorePermit,
    socket_guard: AcceptedSocketGuard,
) -> ResultType<()> {
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let trust_proxy_headers = context.trust_proxy_headers;
        let callback = move |req: &Request, response: Response| {
            if trust_proxy_headers {
                // Only consulted when the operator opts in with --trust-proxy-headers.
                // These headers are NOT verifiable: anyone able to reach this port
                // directly can spoof an arbitrary IP, bypassing IP-based rate limiting
                // and corrupting logged addresses. Enable it only when the WebSocket
                // port is reachable exclusively through a reverse proxy that overwrites
                // them. Reference upstream issue #634.
                let headers = req.headers();
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok())
                    .and_then(|value| value.split(',').next())
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty());
                if let Some(ip) = real_ip {
                    if let Ok(real_ip_addr) = ip.parse::<IpAddr>() {
                        // Keep the accepted TCP source port so concurrent websocket
                        // clients behind one public IP stay distinguishable.
                        addr = SocketAddr::new(real_ip_addr, addr.port());
                    }
                }
            }
            Ok(response)
        };
        let websocket_config = tungstenite::protocol::WebSocketConfig::default()
            .read_buffer_size(32 * 1024)
            .write_buffer_size(32 * 1024)
            .max_write_buffer_size(RELAY_WEBSOCKET_FRAME_MAX)
            .max_message_size(Some(RELAY_WEBSOCKET_FRAME_MAX))
            .max_frame_size(Some(RELAY_WEBSOCKET_FRAME_MAX));
        let ws_stream = match timeout(
            WEBSOCKET_UPGRADE_TIMEOUT_MS,
            tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                callback,
                Some(websocket_config),
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => bail!("Relay WebSocket upgrade timed out"),
        };
        if is_ip_in_set(&*BLOCKLIST.read().await, addr.ip()) {
            log::info!("{} blocked after websocket upgrade", addr.ip());
            return Ok(());
        }
        make_pair_(ws_stream, addr, &context, permit, socket_guard).await;
    } else {
        let mut stream = FramedStream::from(stream, addr);
        *stream.codec_mut() = BytesCodec::with_max_packet_length(RELAY_CONTROL_FRAME_MAX);
        make_pair_(stream, addr, &context, permit, socket_guard).await;
    }
    Ok(())
}

async fn make_pair_(
    stream: impl StreamTrait,
    addr: SocketAddr,
    context: &RelayContext,
    permit: OwnedSemaphorePermit,
    socket_guard: AcceptedSocketGuard,
) {
    let mut stream = stream;
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        let Some(_frame_permit) = context.memory_budget.try_acquire(bytes.len()) else {
            log::warn!("Relay memory budget exceeded for handshake from {}", addr);
            return;
        };
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !context.key.is_empty() && rf.licence_key != *context.key {
                    log::warn!("Relay authentication failed from {} - invalid key", addr);
                    return;
                }
                if valid_relay_uuid(&rf.uuid) && rf.licence_key.len() <= 128 {
                    let mut pending = {
                        let mut peers = PEERS.lock().await;
                        if let Some(pending) = peers.remove(&rf.uuid) {
                            pending
                        } else {
                            let pending_for_ip = peers
                                .values()
                                .filter(|pending| pending.source_ip == addr.ip())
                                .count();
                            if peers.len() >= MAX_PENDING_RELAYS
                                || pending_for_ip >= MAX_PENDING_RELAYS_PER_IP
                            {
                                log::warn!(
                                    "Relay pending limit reached; rejected {} from {}",
                                    rf.uuid,
                                    addr
                                );
                                return;
                            }
                            log::info!("New relay request {} from {}", rf.uuid, addr);
                            let generation =
                                NEXT_PENDING_GENERATION.fetch_add(1, Ordering::Relaxed);
                            peers.insert(
                                rf.uuid.clone(),
                                PendingRelay {
                                    stream: Box::new(stream),
                                    source_ip: addr.ip(),
                                    generation,
                                    _permit: permit,
                                    _socket_guard: socket_guard,
                                },
                            );
                            drop(peers);
                            sleep(30.).await;
                            remove_pending_if_generation(&rf.uuid, generation).await;
                            return;
                        }
                    };
                    log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                    let id = format!("{}:{}", addr.ip(), addr.port());
                    USAGE.write().await.insert(id.clone(), Default::default());
                    if !stream.is_ws() && !pending.stream.is_ws() {
                        pending.stream.set_raw();
                        stream.set_raw();
                        log::info!("Both are raw");
                    }
                    ACTIVE_PAIRS.fetch_add(1, Ordering::Relaxed);
                    let ip1 = pending.source_ip;
                    let ip2 = addr.ip();

                    {
                        let blocklist = BLOCKLIST.read().await;
                        if is_ip_in_set(&blocklist, ip1) || is_ip_in_set(&blocklist, ip2) {
                            log::info!(
                                "Relay pair between {} and {} rejected by blocklist",
                                ip1,
                                ip2
                            );
                            return;
                        }
                    }

                    let blacked = {
                        let blacklist = BLACKLIST.read().await;
                        is_ip_in_set(&blacklist, ip1) || is_ip_in_set(&blacklist, ip2)
                    };

                    log::info!(
                        "Relayrequest {} from {} got paired with {}",
                        rf.uuid,
                        addr,
                        ip1
                    );
                    let id = format!("{}:{}", addr.ip(), addr.port());
                    USAGE.write().await.insert(id.clone(), Default::default());
                    if !stream.is_ws() && !pending.stream.is_ws() {
                        pending.stream.set_raw();
                        stream.set_raw();
                        log::info!("Both are raw");
                    }
                    ACTIVE_PAIRS.fetch_add(1, Ordering::Relaxed);
                    let session_params = RelaySessionParams {
                        ip1,
                        ip2,
                        addr,
                        id: id.clone(),
                        blacked,
                    };
                    let relay_res = relay(
                        session_params,
                        &mut stream,
                        &mut pending.stream,
                        context.limiter.clone(),
                        context.memory_budget.clone(),
                    )
                    .await;
                    ACTIVE_PAIRS.fetch_sub(1, Ordering::Relaxed);
                    if let Err(err) = relay_res {
                        log::info!("Relay of {} closed: {}", addr, err);
                    } else {
                        log::info!("Relay of {} closed", addr);
                    }
                    USAGE.write().await.remove(&id);
                    drop(pending);
                    drop(permit);
                    drop(socket_guard);
                } else {
                    log::warn!("Rejected malformed relay request from {}", addr);
                }
            }
        }
    }
}

fn valid_relay_uuid(uuid: &str) -> bool {
    (RELAY_UUID_MIN_LEN..=RELAY_UUID_MAX_LEN).contains(&uuid.len())
        && uuid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

async fn remove_pending_if_generation(uuid: &str, generation: u64) -> bool {
    let mut peers = PEERS.lock().await;
    if peers
        .get(uuid)
        .is_some_and(|pending| pending.generation == generation)
    {
        peers.remove(uuid);
        true
    } else {
        false
    }
}

struct RelaySessionParams {
    ip1: IpAddr,
    ip2: IpAddr,
    addr: SocketAddr,
    id: String,
    blacked: bool,
}

async fn relay(
    params: RelaySessionParams,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    memory_budget: Arc<crate::common::MemoryBudget>,
) -> ResultType<()> {
    let RelaySessionParams {
        ip1,
        ip2,
        addr,
        id,
        mut blacked,
    } = params;
    let ip1_guard = IpLimiterGuard::acquire(ip1);
    let ip2_guard = if canonical_ip(ip1) != canonical_ip(ip2) {
        Some(IpLimiterGuard::acquire(ip2))
    } else {
        None
    };
    let pair_limiter = <Limiter>::new(SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as f64);
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let downgrade_threshold =
        DOWNGRADE_THRESHOLD_SCALED.load(Ordering::SeqCst) as f64 / DOWNGRADE_THRESHOLD_SCALE as f64;
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    let Some(_mem_permit) = memory_budget.try_acquire(bytes.len()) else {
                        log::warn!("Relay memory budget exceeded for data from peer {}", addr);
                        bail!("Relay memory budget exceeded");
                    };
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    ip1_guard.limiter.consume(nb).await;
                    if let Some(ref g2) = ip2_guard {
                        g2.limiter.consume(nb).await;
                    }
                    pair_limiter.consume(nb).await;
                    total_limiter.consume(nb).await;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    }
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    let Some(_mem_permit) = memory_budget.try_acquire(bytes.len()) else {
                        log::warn!("Relay memory budget exceeded for data from stream {}", addr);
                        bail!("Relay memory budget exceeded");
                    };
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    ip1_guard.limiter.consume(nb).await;
                    if let Some(ref g2) = ip2_guard {
                        g2.limiter.consume(nb).await;
                    }
                    pair_limiter.consume(nb).await;
                    total_limiter.consume(nb).await;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    }
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            {
                let blocklist = BLOCKLIST.read().await;
                if is_ip_in_set(&blocklist, ip1) || is_ip_in_set(&blocklist, ip2) {
                    log::info!("Relay between {} and {} terminated by blocklist", ip1, ip2);
                    break;
                }
            }
            {
                let blacklist = BLACKLIST.read().await;
                blacked = is_ip_in_set(&blacklist, ip1) || is_ip_in_set(&blacklist, ip2);
            }
            tm = std::time::Instant::now();
            let speed = total_s / n;
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total as f64 > elapsed as f64 * sb / 1_000. * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceeded {:.6} of single bandwidth over {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}

fn get_server_sk(key: &str) -> ResultType<String> {
    let key = key.trim();
    if key.is_empty() || key == "-" || key == "_" {
        return crate::common::gen_sk(300).map(|(public_key, _)| public_key);
    }

    if key.len() > 128 {
        bail!("The relay key is too large");
    }
    let decoded = BASE64.decode(key).map_err(|_| {
        camellia_remote_protocol::anyhow::anyhow!("The relay key must be base64 encoded")
    })?;
    let public_key = match decoded.len() {
        sign::PUBLICKEYBYTES => sign::PublicKey::from_slice(&decoded).ok_or_else(|| {
            camellia_remote_protocol::anyhow::anyhow!("The relay public key is invalid")
        })?,
        sign::SECRETKEYBYTES => {
            crate::common::parse_private_key(key, "The relay key")?.public_key()
        }
        _ => {
            bail!(
                "The relay key must be a {}-byte public or {}-byte private Ed25519 key",
                sign::PUBLICKEYBYTES,
                sign::SECRETKEYBYTES
            )
        }
    };
    let encoded_public_key = BASE64.encode(public_key);
    log::info!("Relay public key loaded: {}", encoded_public_key);
    Ok(encoded_public_key)
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        tungstenite::Message::Close(_) => {
                            log::debug!("Relay websocket close frame received");
                            None
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::other(err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self.send(tungstenite::Message::Binary(bytes)).await?)
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FakeStream;

    struct TestFile(PathBuf);

    impl TestFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "camellia-relay-list-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[async_trait]
    impl StreamTrait for FakeStream {
        async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
            None
        }

        async fn send_raw(&mut self, _bytes: Bytes) -> ResultType<()> {
            Ok(())
        }

        fn is_ws(&self) -> bool {
            false
        }

        fn set_raw(&mut self) {}
    }

    #[test]
    fn relay_uuid_is_bounded_and_canonical() {
        for uuid in [
            "12345678",
            "019fa1f1-99ab-7892-9000-311653875491",
            "relay_session_01",
        ] {
            assert!(valid_relay_uuid(uuid), "{uuid}");
        }
        for uuid in ["", "short", "relay/session", "中继会话000001"] {
            assert!(!valid_relay_uuid(uuid), "{uuid}");
        }
    }

    #[test]
    fn relay_tuning_rejects_invalid_or_overflowing_values() {
        assert_eq!(parse_downgrade_threshold("0.66").unwrap(), 660_000);
        assert_eq!(parse_downgrade_start("1800").unwrap(), 1_800_000);
        assert_eq!(
            parse_bandwidth("LIMIT_SPEED", "32").unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("LIMIT_SPEED", "32Mb").unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("LIMIT_SPEED", "32Mbps").unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("LIMIT_SPEED", "4MB").unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("LIMIT_SPEED", "4MB/s").unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("TOTAL_BANDWIDTH", "1Gb").unwrap(),
            1024 * 1024 * 1024
        );
        assert_eq!(
            parse_bandwidth("TOTAL_BANDWIDTH", "1024Mb").unwrap(),
            1024 * 1024 * 1024
        );

        for value in ["0", "0.0000001", "-1", "1.01", "NaN", "infinity"] {
            assert!(parse_downgrade_threshold(value).is_err(), "{value}");
        }
        for value in ["0", "-1", "not-a-number", "32invalid", ""] {
            assert!(parse_downgrade_start(value).is_err(), "{value}");
            assert!(parse_bandwidth("LIMIT_SPEED", value).is_err(), "{value}");
        }
    }

    #[test]
    fn canonical_ip_and_set_matching_works() {
        let v4 = "192.0.2.1".parse::<IpAddr>().unwrap();
        let v6_mapped = "::ffff:192.0.2.1".parse::<IpAddr>().unwrap();
        let v6_regular = "2001:db8::1".parse::<IpAddr>().unwrap();

        assert_eq!(canonical_ip(v4), v4);
        assert_eq!(canonical_ip(v6_mapped), v4);
        assert_eq!(canonical_ip(v6_regular), v6_regular);

        let mut set = HashSet::new();
        set.insert("192.0.2.1".to_owned());
        set.insert("2001:db8::1".to_owned());

        assert!(is_ip_in_set(&set, v4));
        assert!(is_ip_in_set(&set, v6_mapped));
        assert!(is_ip_in_set(&set, v6_regular));
        assert!(!is_ip_in_set(&set, "192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn ip_limiter_guard_lifecycle_and_refcounting() {
        let ip = "198.51.100.5".parse::<IpAddr>().unwrap();
        {
            let _guard1 = IpLimiterGuard::acquire(ip);
            {
                let _guard2 = IpLimiterGuard::acquire(ip);
                let map = SHARED_IP_LIMITERS.lock().unwrap();
                assert_eq!(map.get(&ip).unwrap().1, 2);
            }
            let map = SHARED_IP_LIMITERS.lock().unwrap();
            assert_eq!(map.get(&ip).unwrap().1, 1);
        }
        let map = SHARED_IP_LIMITERS.lock().unwrap();
        assert!(!map.contains_key(&ip));
    }

    #[test]
    fn relay_key_accepts_only_valid_public_or_private_material() {
        let (public_key, private_key) = sign::gen_keypair();
        let encoded_public = BASE64.encode(public_key.as_ref());
        let encoded_private = BASE64.encode(private_key.as_ref());
        assert_eq!(get_server_sk(&encoded_public).unwrap(), encoded_public);
        assert_eq!(get_server_sk(&encoded_private).unwrap(), encoded_public);

        let mut inconsistent = private_key.as_ref().to_vec();
        inconsistent[sign::SECRETKEYBYTES - 1] ^= 1;
        assert!(get_server_sk(&BASE64.encode(inconsistent)).is_err());
        assert!(get_server_sk("not-base64").is_err());
        assert!(get_server_sk(&BASE64.encode([0u8; 16])).is_err());
    }

    #[test]
    fn relay_ip_lists_are_canonical_and_fail_on_invalid_lines() {
        let file = TestFile::new(
            "\n# comment\n192.0.2.1 optional-note\n2001:0db8::1 # comment\n192.0.2.1\n",
        );
        let values = load_ip_list(file.0.to_str().unwrap()).unwrap();
        assert_eq!(
            values,
            HashSet::from(["192.0.2.1".to_owned(), "2001:db8::1".to_owned()])
        );
        assert_eq!(
            parse_ip_values("192.0.2.1|2001:0db8::1").unwrap(),
            ["192.0.2.1", "2001:db8::1"]
        );

        let invalid = TestFile::new("192.0.2.1\nnot-an-ip\n");
        assert!(load_ip_list(invalid.0.to_str().unwrap()).is_err());
        assert!(parse_ip_values("192.0.2.1|not-an-ip").is_err());
    }

    #[camellia_remote_protocol::tokio::test]
    async fn stale_timeout_cannot_remove_reused_uuid() {
        let initial_sockets = accepted_sockets();
        let uuid = format!("test-{}", uuid::Uuid::new_v4());
        let semaphore = Arc::new(Semaphore::new(10));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let guard = AcceptedSocketGuard::new();
        assert_eq!(semaphore.available_permits(), 9);
        assert_eq!(accepted_sockets(), initial_sockets + 1);

        PEERS.lock().await.insert(
            uuid.clone(),
            PendingRelay {
                stream: Box::new(FakeStream),
                source_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                generation: 2,
                _permit: permit,
                _socket_guard: guard,
            },
        );

        assert!(!remove_pending_if_generation(&uuid, 1).await);
        assert!(PEERS.lock().await.contains_key(&uuid));
        assert_eq!(semaphore.available_permits(), 9);
        assert_eq!(accepted_sockets(), initial_sockets + 1);

        assert!(remove_pending_if_generation(&uuid, 2).await);
        assert!(!PEERS.lock().await.contains_key(&uuid));
        // RES-004: Removing pending relay returns permit and decrements socket count
        assert_eq!(semaphore.available_permits(), 10);
        assert_eq!(accepted_sockets(), initial_sockets);
    }

    #[camellia_remote_protocol::tokio::test]
    async fn relay_pairing_holds_both_connection_permits_across_lifecycle() {
        let initial_sockets = accepted_sockets();

        // RES-004: Exactly 2 slots available
        let semaphore = Arc::new(Semaphore::new(2));
        let permit1 = semaphore.clone().try_acquire_owned().unwrap();
        let guard1 = AcceptedSocketGuard::new();
        assert_eq!(semaphore.available_permits(), 1);
        assert_eq!(accepted_sockets(), initial_sockets + 1);

        let uuid = format!("pair-{}", uuid::Uuid::new_v4());
        PEERS.lock().await.insert(
            uuid.clone(),
            PendingRelay {
                stream: Box::new(FakeStream),
                source_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                generation: 1,
                _permit: permit1,
                _socket_guard: guard1,
            },
        );

        // Second connection arrives and acquires second permit
        let permit2 = semaphore.clone().try_acquire_owned().unwrap();
        let guard2 = AcceptedSocketGuard::new();
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(accepted_sockets(), initial_sockets + 2);

        // A third connection attempt must fail because all 2 slots are occupied
        assert!(semaphore.clone().try_acquire_owned().is_err());

        // Pairing takes pending relay (with permit 1 and guard 1)
        let pending = PEERS.lock().await.remove(&uuid).unwrap();
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(accepted_sockets(), initial_sockets + 2);

        // Both permits and socket guards remain held while pair is active
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(accepted_sockets(), initial_sockets + 2);

        // When relay session closes, both permits and guards are dropped
        drop(pending);
        assert_eq!(semaphore.available_permits(), 1);
        assert_eq!(accepted_sockets(), initial_sockets + 1);
        drop(permit2);
        drop(guard2);
        assert_eq!(semaphore.available_permits(), 2);
        assert_eq!(accepted_sockets(), initial_sockets);
    }

    #[test]
    fn relay_memory_budget_enforces_ceiling_and_raii_return() {
        let budget = crate::common::MemoryBudget::new(1024 * 1024);
        assert_eq!(budget.max_bytes(), 1024 * 1024);
        assert_eq!(budget.used_bytes(), 0);

        let p1 = budget.try_acquire(600 * 1024).expect("acquire 600 KiB");
        assert_eq!(budget.used_bytes(), 600 * 1024);
        assert!(budget.try_acquire(500 * 1024).is_none());

        drop(p1);
        assert_eq!(budget.used_bytes(), 0);
        let p2 = budget.try_acquire(500 * 1024).expect("acquire 500 KiB");
        assert_eq!(budget.used_bytes(), 500 * 1024);
        drop(p2);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn relay_startup_validation_enforces_minimums() {
        assert!(validate_relay_startup_params(1, 256 * 1024 * 1024).is_err());
        assert!(validate_relay_startup_params(2, 2 * 1024 * 1024).is_err());
        assert!(validate_relay_startup_params(2, RELAY_WEBSOCKET_FRAME_MAX).is_ok());
        assert!(validate_relay_startup_params(8192, 256 * 1024 * 1024).is_ok());
    }
}
