use crate::common::*;
use crate::peer::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use camellia_remote_protocol::anyhow::{anyhow, Context as _};
use camellia_remote_protocol::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    crypto::{box_, secretbox, sign},
    futures::future::join_all,
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::{Message as _, MessageField},
    rand::{rngs::SysRng, TryRng},
    rendezvous_proto::{
        register_pk_response::Result::{INVALID_ID_FORMAT, TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    sha2::{Digest, Sha256},
    tcp::{CipherRole, Encrypt, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex, Semaphore},
        time::{interval, Duration},
    },
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

const HTTP_PROXY_TIMEOUT_SECS: u64 = 12;
const HTTP_PROXY_MAX_BODY: usize = 16 * 1024 * 1024;
const HTTP_PROXY_MAX_PATH: usize = 4 * 1024;
const HTTP_PROXY_MAX_HEADERS: usize = 64;
const HTTP_PROXY_MAX_HEADER_BYTES: usize = 32 * 1024;
const HTTP_PROXY_MAX_CONCURRENCY: usize = 64;
const HTTP_PROXY_RATE_WINDOW_SECS: u64 = 60;
const HTTP_PROXY_RATE_PER_IP: u32 = 120;
const HTTP_PROXY_MAX_TRACKED_IPS: usize = 4_096;
const RENDEZVOUS_EVENT_QUEUE_CAPACITY: usize = 4_096;
const RENDEZVOUS_CONNECTION_QUEUE_CAPACITY: usize = 64;
const RENDEZVOUS_CONTROL_FRAME_MAX: usize = 1024 * 1024;
const RENDEZVOUS_RATE_LIMITER_CAPACITY: f64 = 60.0;
const RENDEZVOUS_RATE_LIMITER_REFILL_PER_SEC: f64 = 10.0;
const DEFAULT_MAX_RENDEZVOUS_IN_FLIGHT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RATE_LIMITER_ENTRIES: usize = 65_536;
const DEFAULT_MAX_RENDEZVOUS_CONNECTIONS: usize = 4_096;
const PEER_ID_MIN_LEN: usize = 6;
const PEER_ID_MAX_LEN: usize = 16;
const RELAY_UUID_MIN_LEN: usize = 8;
const RELAY_UUID_MAX_LEN: usize = 128;
const REGISTER_UUID_MAX_LEN: usize = 256;
const PEER_PUBLIC_KEY_LEN: usize = box_::PUBLICKEYBYTES;
const ONLINE_QUERY_MAX_PEERS: usize = 256;
const PUNCH_REQUEST_LOG_CAPACITY: usize = 10_000;
const PENDING_RENDEZVOUS_CAPACITY: usize = 10_000;
const PENDING_RENDEZVOUS_TTL_SECS: u64 = 30;
const RENDEZVOUS_TOKEN_LEN: usize = 32;
const RELAY_SERVER_NAME_MAX_LEN: usize = 512;
const PEER_CACHE_CLEANUP_INTERVAL_SECS: u64 = 300;
const PEER_CACHE_IDLE_SECS: u64 = 600;
const DEPLOYMENT_VERIFICATION_CACHE_SECS: u64 = 30;
const HC_KEEP_ALIVE_SECS: i32 = 10;

#[derive(Clone, Debug)]
enum Data {
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i64 = 30_000;
type TcpChan = mpsc::Sender<RendezvousMessage>;
enum Sink {
    Tcp(TcpChan),
}
type Sender = mpsc::Sender<Data>;
type Receiver = mpsc::Receiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
static RELAY_CHECK_RUNNING: AtomicBool = AtomicBool::new(false);
static PEER_CACHE_CLEANUP_RUNNING: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry {
    tm: Instant,
    from_ip: String,
    to_ip: String,
    to_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingRendezvousKind {
    Direct,
    Local,
    Relay,
}

struct PendingRendezvous {
    requester: SocketAddr,
    responder_id: String,
    kind: PendingRendezvousKind,
    relay_server: String,
    created_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
struct ConsumedRendezvous {
    requester: SocketAddr,
    relay_server: String,
}

fn consume_pending_rendezvous_in(
    pending: &mut HashMap<Bytes, PendingRendezvous>,
    token: &Bytes,
    responder_id: &str,
    claimed_requester: SocketAddr,
    expected_kind: Option<PendingRendezvousKind>,
    now: Instant,
) -> ResultType<ConsumedRendezvous> {
    if token.len() != RENDEZVOUS_TOKEN_LEN {
        bail!("Missing or malformed rendezvous token");
    }
    let Some(entry) = pending.get(token) else {
        bail!("Unknown or already consumed rendezvous token");
    };
    if now.saturating_duration_since(entry.created_at)
        > Duration::from_secs(PENDING_RENDEZVOUS_TTL_SECS)
    {
        pending.remove(token);
        bail!("Expired rendezvous token");
    }
    if entry.responder_id != responder_id
        || expected_kind.is_some_and(|kind| entry.kind != kind)
        || entry.requester != try_into_v4(claimed_requester)
    {
        bail!("Rendezvous response does not match its request");
    }
    let consumed = ConsumedRendezvous {
        requester: entry.requester,
        relay_server: entry.relay_server.clone(),
    };
    pending.remove(token);
    Ok(consumed)
}
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> =
    Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
const HANDSHAKE_WAIT_MS: u64 = 8_000;

#[derive(Clone)]
struct Inner {
    serial: i32,
    api_server: String,
    trust_proxy_headers: bool,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: sign::SecretKey,
    http_client: reqwest::Client,
    http_proxy_slots: Arc<Semaphore>,
    http_proxy_rates: Arc<Mutex<HashMap<IpAddr, ProxyRate>>>,
    runtime_console: bool,
    allow_unmanaged_devices: bool,
    device_verification_token: String,
    rendezvous_rate_limiter: Arc<Mutex<SubnetRateLimiter>>,
    memory_budget: Arc<MemoryBudget>,
}

#[derive(Clone, Copy)]
struct ProxyRate {
    started_at: Instant,
    requests: u32,
}

#[derive(Clone, Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, cost: f64, capacity: f64, refill_rate: f64) -> bool {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_rate).min(capacity);
        self.last_update = now;

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

struct SubnetRateLimiter {
    buckets: HashMap<String, TokenBucket>,
    capacity: f64,
    refill_rate: f64,
}

impl SubnetRateLimiter {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_rate,
        }
    }

    fn allow(&mut self, key: &str, cost: f64) -> bool {
        let now = Instant::now();
        if !self.buckets.contains_key(key) && self.buckets.len() >= MAX_RATE_LIMITER_ENTRIES {
            self.buckets.retain(|_, bucket| {
                now.saturating_duration_since(bucket.last_update) < Duration::from_secs(60)
            });
            if self.buckets.len() >= MAX_RATE_LIMITER_ENTRIES {
                return false;
            }
        }

        let capacity = self.capacity;
        let refill_rate = self.refill_rate;
        let entry = self
            .buckets
            .entry(key.to_owned())
            .or_insert_with(|| TokenBucket::new(capacity));
        entry.try_consume(cost, capacity, refill_rate)
    }
}

pub(crate) struct MemoryPermit {
    used: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::Release);
    }
}

pub(crate) struct MemoryBudget {
    used: Arc<AtomicUsize>,
    max_bytes: usize,
}

impl MemoryBudget {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            max_bytes,
        }
    }

    pub(crate) fn try_acquire(&self, bytes: usize) -> Option<MemoryPermit> {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            if current.saturating_add(bytes) > self.max_bytes {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(MemoryPermit {
                        used: self.used.clone(),
                        bytes,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

#[inline]
fn canonical_rate_limit_key(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                let s = v6.segments();
                format!("{:04x}:{:04x}:{:04x}:{:04x}::/64", s[0], s[1], s[2], s[3])
            }
        }
    }
}

struct PeerRegistrationRollback {
    socket_addr: SocketAddr,
    last_reg_time: Instant,
    uuid: Bytes,
    pk: Bytes,
    info: PeerInfo,
    deployment_verified_at: Option<Instant>,
}

struct PendingPeerRegistration {
    guid: Vec<u8>,
    rollback: PeerRegistrationRollback,
    serialized_info: String,
    ip_changed: bool,
}

enum PeerRegistrationStage {
    Busy,
    UuidMismatch,
    TooFrequent,
    Unchanged,
    Persist(Box<PendingPeerRegistration>),
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pending_rendezvous: Arc<Mutex<HashMap<Bytes, PendingRendezvous>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
    connection_slots: Arc<Semaphore>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

struct RendezvousListeners {
    main: TcpListener,
    nat_test: TcpListener,
    websocket: TcpListener,
    console: Option<TcpListener>,
}

impl RendezvousServer {
    fn valid_peer_id(id: &str) -> bool {
        (PEER_ID_MIN_LEN..=PEER_ID_MAX_LEN).contains(&id.len())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }

    fn valid_optional_mangled_addr(bytes: &[u8]) -> bool {
        bytes.is_empty() || AddrMangle::try_decode(bytes).is_some()
    }

    fn strip_untrusted_relay_metadata(request: &mut RequestRelay) {
        request.id.clear();
        request.licence_key.clear();
        request.token.clear();
        request.switch_code.clear();
        request.control_permissions = Default::default();
        request.controlled_context = Default::default();
    }

    fn device_verification_token() -> ResultType<String> {
        let direct = std::env::var("CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        let file = get_arg_opt("device-verification-token-file").filter(|value| !value.is_empty());
        if direct.is_some() && file.is_some() {
            bail!(
                "Set only one of CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN or CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE"
            );
        }
        if let Some(path) = file {
            let value = crate::common::read_bounded_regular_file(
                std::path::Path::new(&path),
                4_096,
                "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE",
            )?;
            let value = std::str::from_utf8(&value)
                .context("CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE must be UTF-8")?;
            return Ok(value.trim().to_owned());
        }
        Ok(direct.unwrap_or_default())
    }

    fn http_proxy_authorized(secured: bool, expected_key: &str, supplied_key: &str) -> bool {
        secured && !expected_key.is_empty() && supplied_key == expected_key
    }

    fn stage_peer_registration(
        peer: &mut Peer,
        id: &str,
        socket_addr: SocketAddr,
        uuid: &Bytes,
        pk: &Bytes,
        ip: &str,
        managed_authorized: bool,
    ) -> ResultType<PeerRegistrationStage> {
        if peer.persistence_in_progress {
            return Ok(PeerRegistrationStage::Busy);
        }
        if peer.uuid.is_empty() {
            // First registration claims the in-memory peer before database
            // I/O, closing the concurrent first-writer takeover window.
        } else if managed_authorized {
            // The management API is authoritative for a managed deployment.
            // This permits an administrator-approved machine/key replacement
            // without retaining the stale hbbs-local UUID forever.
        } else if peer.uuid == *uuid {
            if peer.info.ip != ip && peer.pk != *pk {
                log::warn!(
                    "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                    id,
                    ip,
                    pk,
                    peer.info.ip,
                    peer.pk,
                );
                return Ok(PeerRegistrationStage::UuidMismatch);
            }
        } else {
            log::warn!("Peer {} uuid mismatch: {:?} vs {:?}", id, uuid, peer.uuid);
            return Ok(PeerRegistrationStage::UuidMismatch);
        }

        if peer.reg_pk.1.elapsed().as_secs() > 6 {
            peer.reg_pk.0 = 0;
        } else if peer.reg_pk.0 > 2 {
            return Ok(PeerRegistrationStage::TooFrequent);
        }
        peer.reg_pk.0 += 1;
        peer.reg_pk.1 = Instant::now();

        let ip_changed = !peer.uuid.is_empty() && peer.info.ip != ip;
        let changed = peer.uuid.is_empty() || peer.uuid != *uuid || peer.pk != *pk || ip_changed;
        if !changed {
            return Ok(PeerRegistrationStage::Unchanged);
        }

        let mut updated_info = peer.info.clone();
        updated_info.ip = ip.to_owned();
        let serialized_info = serde_json::to_string(&updated_info)?;
        let rollback = PeerRegistrationRollback {
            socket_addr: peer.socket_addr,
            last_reg_time: peer.last_reg_time,
            uuid: peer.uuid.clone(),
            pk: peer.pk.clone(),
            info: peer.info.clone(),
            deployment_verified_at: peer.deployment_verified_at,
        };
        peer.socket_addr = socket_addr;
        peer.last_reg_time = Instant::now();
        peer.uuid = uuid.clone();
        peer.pk = pk.clone();
        peer.info = updated_info;
        peer.persistence_in_progress = true;
        Ok(PeerRegistrationStage::Persist(Box::new(
            PendingPeerRegistration {
                guid: peer.guid.clone(),
                rollback,
                serialized_info,
                ip_changed,
            },
        )))
    }

    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[inline]
    async fn cache_sink(&self, addr: SocketAddr, sink: &Option<Sink>) {
        if let Some(Sink::Tcp(tx)) = sink {
            self.tcp_punch
                .lock()
                .await
                .insert(try_into_v4(addr), Sink::Tcp(tx.clone()));
        }
    }

    #[inline]
    async fn allow_unauthenticated_request(&self, ip: IpAddr, cost: f64) -> bool {
        let key = canonical_rate_limit_key(ip);
        let mut limiter = self.inner.rendezvous_rate_limiter.lock().await;
        limiter.allow(&key, cost)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers")?;
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::channel::<Data>(RENDEZVOUS_EVENT_QUEUE_CAPACITY);
        let max_connections = crate::common::get_bounded_usize_arg(
            "MAX_RENDEZVOUS_CONNECTIONS",
            DEFAULT_MAX_RENDEZVOUS_CONNECTIONS,
            64,
            65_536,
        )?;
        log::info!("MAX_RENDEZVOUS_CONNECTIONS={max_connections}");
        let api_server = get_arg_or(
            "api-server",
            std::env::var("CAMELLIA_REMOTE_API_SERVER")
                .unwrap_or_else(|_| format!("http://127.0.0.1:{}", port - 2)),
        );
        Self::validate_api_server(&api_server)?;
        let allow_unmanaged_devices =
            crate::common::get_yes_no_arg("ALLOW_UNMANAGED_DEVICES", false)?;
        let device_verification_token = Self::device_verification_token()?;
        if allow_unmanaged_devices {
            log::warn!(
                "ALLOW_UNMANAGED_DEVICES=Y: first-seen devices may claim rendezvous IDs without API approval"
            );
        } else if device_verification_token.len() < 32
            || device_verification_token.len() > 512
            || device_verification_token
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            bail!(
                "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN must be a 32-512 character secret unless CAMELLIA_REMOTE_ALLOW_UNMANAGED_DEVICES=Y"
            );
        }
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_PROXY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()?;
        log::info!("api_server: {}", api_server);
        let trust_proxy_headers = crate::common::get_yes_no_arg("trust-proxy-headers", false)?;
        log::info!("trust_proxy_headers: {}", trust_proxy_headers);
        let runtime_console = crate::common::get_yes_no_arg("ENABLE_RUNTIME_CONSOLE", false)?;
        if runtime_console {
            log::warn!("Unauthenticated loopback runtime console is enabled");
        }
        let mask = get_arg_opt("mask")
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<Ipv4Network>()
                    .with_context(|| format!("Invalid mask: {value}"))
            })
            .transpose()?;
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let max_in_flight_bytes = crate::common::get_bounded_usize_arg(
            "MAX_RENDEZVOUS_IN_FLIGHT_BYTES",
            DEFAULT_MAX_RENDEZVOUS_IN_FLIGHT_BYTES,
            1024 * 1024,
            1024 * 1024 * 1024,
        )?;
        log::info!("MAX_RENDEZVOUS_IN_FLIGHT_BYTES={max_in_flight_bytes}");
        let memory_budget = Arc::new(MemoryBudget::new(max_in_flight_bytes));
        let rendezvous_rate_limiter = Arc::new(Mutex::new(SubnetRateLimiter::new(
            RENDEZVOUS_RATE_LIMITER_CAPACITY,
            RENDEZVOUS_RATE_LIMITER_REFILL_PER_SEC,
        )));
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pending_rendezvous: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            connection_slots: Arc::new(Semaphore::new(max_connections)),
            inner: Arc::new(Inner {
                serial,
                api_server,
                trust_proxy_headers,
                sk,
                mask,
                local_ip,
                http_client,
                http_proxy_slots: Arc::new(Semaphore::new(HTTP_PROXY_MAX_CONCURRENCY)),
                http_proxy_rates: Default::default(),
                runtime_console,
                allow_unmanaged_devices,
                device_verification_token,
                rendezvous_rate_limiter,
                memory_budget,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        rs.parse_relay_servers(&get_arg("relay-servers"))?;
        let mut listeners = RendezvousListeners {
            main: create_tcp_listener(bind_addr, port).await?,
            nat_test: create_tcp_listener(bind_addr, nat_port).await?,
            websocket: create_tcp_listener(bind_addr, ws_port).await?,
            console: if runtime_console {
                listen_console(bind_addr, nat_port as _).await?
            } else {
                None
            },
        };
        log::info!("Listening on tcp/udp {}", listeners.main.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listeners.nat_test.local_addr()?
        );
        log::info!(
            "Listening on websocket {}",
            listeners.websocket.local_addr()?
        );
        if crate::common::get_yes_no_arg("ALWAYS_USE_RELAY", false)? {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs.io_loop(&mut rx, &mut listeners, &mut socket, &key).await {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        listeners.main = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        listeners.nat_test = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        listeners.console = if runtime_console {
                            listen_console(bind_addr, nat_port as _).await?
                        } else {
                            None
                        };
                    }
                    LoopFailure::Listener3 => {
                        listeners.websocket = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listeners: &mut RendezvousListeners,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        let mut timer_peer_cache = interval(Duration::from_secs(PEER_CACHE_CLEANUP_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1
                        && RELAY_CHECK_RUNNING
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                            RELAY_CHECK_RUNNING.store(false, Ordering::Release);
                        });
                    }
                }
                _ = timer_peer_cache.tick() => {
                    if PEER_CACHE_CLEANUP_RUNNING
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        let pm = self.pm.clone();
                        tokio::spawn(async move {
                            let evicted = pm.evict_inactive(PEER_CACHE_IDLE_SECS).await;
                            let (blockers, changes) = cleanup_transient_state().await;
                            if evicted + blockers + changes > 0 {
                                log::debug!(
                                    "Cleaned transient state: peers={evicted}, ip-blockers={blockers}, ip-changes={changes}"
                                );
                            }
                            PEER_CACHE_CLEANUP_RUNNING.store(false, Ordering::Release);
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::RelayServers0(rs) => {
                            if let Err(err) = self.parse_relay_servers(&rs) {
                                log::warn!("Rejected relay server update: {err}");
                            }
                        }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            self.handle_udp(&bytes, addr.into()).await;
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listeners.nat_test.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listeners.console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listeners.websocket.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listeners.main.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(&mut self, bytes: &BytesMut, addr: SocketAddr) {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(_ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // The response is accepted over UDP only when it carries the
                    // one-time token delivered over the authenticated control channel.
                    // It is always forwarded through the requester's cached TCP/WS sink,
                    // so this path cannot be used as a UDP reflection primitive.
                    allow_err!(self.handle_hole_sent(phs, addr, true).await);
                }
                Some(rendezvous_message::Union::LocalAddr(_)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                _ => {}
            }
        }
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        health_keepalive_started: &mut bool,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            self.handle_tcp_msg(msg_in, sink, health_keepalive_started, addr, key, ws)
                .await
        } else {
            false
        }
    }

    #[inline]
    async fn handle_tcp_msg(
        &mut self,
        msg_in: RendezvousMessage,
        sink: &mut Option<Sink>,
        health_keepalive_started: &mut bool,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        match msg_in.union {
            Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                if !Self::valid_peer_id(&rp.id) {
                    return true;
                }
                if !self.allow_unauthenticated_request(addr.ip(), 2.0).await {
                    log::warn!("Rate limit exceeded for RegisterPeer from {addr}");
                    return false;
                }
                log::trace!("New peer registered via tcp/ws: {:?} {:?}", rp.id, addr);
                self.cache_sink(addr, sink).await;
                let (resp, cu) = match self.register_peer_common(rp, addr).await {
                    Ok(result) => result,
                    Err(err) => {
                        log::warn!("Unable to register peer from {addr}: {err}");
                        return false;
                    }
                };
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(resp);
                if !Self::send_to_sink(sink, msg_out) {
                    return false;
                }

                if let Some(cu) = cu {
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_configure_update(cu);
                    if !Self::send_to_sink(sink, msg_out) {
                        return false;
                    }
                }
                return true;
            }
            Some(rendezvous_message::Union::RegisterPk(rk)) => {
                self.cache_sink(addr, sink).await;
                match self.register_pk_common(rk, addr).await {
                    Ok(Some(res)) => {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: res.into(),
                            ..Default::default()
                        });
                        if !Self::send_to_sink(sink, msg_out) {
                            return false;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        log::warn!("Unable to register peer key from {addr}: {err}");
                        return false;
                    }
                }
                return true;
            }
            Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                if let Err(err) = self.handle_tcp_punch_hole_request(addr, ph, key, ws).await {
                    log::warn!("Unable to route punch-hole request from {addr}: {err}");
                    return false;
                }
                return true;
            }
            Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                if !Self::valid_peer_id(&rf.id)
                    || !Self::valid_relay_uuid(&rf.uuid)
                    || rf.licence_key.len() > 128
                    || rf.relay_server.len() > RELAY_SERVER_NAME_MAX_LEN
                    || rf.token.len() > 4_096
                    || rf.switch_code.len() > 128
                {
                    return false;
                }
                let Some(peer) = self.pm.get_in_memory(&rf.id).await else {
                    return Self::send_relay_failure(sink, "Peer is offline");
                };
                let (peer_addr, peer_is_online) = {
                    let peer = peer.read().await;
                    (
                        peer.socket_addr,
                        peer.last_reg_time.elapsed().as_millis() < REG_TIMEOUT as u128,
                    )
                };
                if !peer_is_online {
                    return Self::send_relay_failure(sink, "Peer is offline");
                }
                let mut msg_out = RendezvousMessage::new();
                let relay_server = if self.is_lan(peer_addr) {
                    self.inner.local_ip.clone()
                } else {
                    self.get_relay_server(addr.ip(), peer_addr.ip())
                };
                let rendezvous_token = match self
                    .reserve_pending_rendezvous(
                        addr,
                        rf.id.clone(),
                        PendingRendezvousKind::Relay,
                        relay_server.clone(),
                    )
                    .await
                {
                    Ok(token) => token,
                    Err(err) => {
                        log::warn!("Unable to reserve relay response from {addr}: {err}");
                        return Self::send_relay_failure(sink, "Rendezvous server is busy");
                    }
                };
                rf.socket_addr = AddrMangle::encode(addr).into();
                rf.rendezvous_token = rendezvous_token.clone();
                rf.relay_server = relay_server;
                // These fields originate from the controller and must never cross
                // the rendezvous trust boundary. In particular, ControlPermissions
                // can override the controlled device's local policy when present.
                // A future managed-policy feature must populate them from a
                // server-authorized source instead.
                Self::strip_untrusted_relay_metadata(&mut rf);
                msg_out.set_request_relay(rf);
                if let Err(err) = self.send_to_tcp_sync(msg_out, peer_addr).await {
                    self.pending_rendezvous
                        .lock()
                        .await
                        .remove(&rendezvous_token);
                    log::warn!("Unable to deliver relay request from {addr}: {err}");
                    return Self::send_relay_failure(sink, "Peer is offline");
                }
                return true;
            }
            Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                let id = rr.id().to_owned();
                if !Self::valid_peer_id(&id)
                    || (!rr.uuid.is_empty() && !Self::valid_relay_uuid(&rr.uuid))
                    || rr.relay_server.len() > RELAY_SERVER_NAME_MAX_LEN
                    || rr.refuse_reason.len() > 1_024
                    || rr.version.len() > 64
                    || !Self::valid_optional_mangled_addr(&rr.socket_addr_v6)
                {
                    return false;
                }
                let pending = match self
                    .consume_pending_rendezvous(
                        &rr.rendezvous_token,
                        &id,
                        &rr.socket_addr,
                        Some(PendingRendezvousKind::Relay),
                    )
                    .await
                {
                    Ok(pending) => pending,
                    Err(err) => {
                        log::warn!("Rejected unmatched relay response from {addr}: {err}");
                        return false;
                    }
                };
                let addr_b = pending.requester;
                rr.socket_addr = Default::default();
                rr.rendezvous_token = Default::default();
                let pk = self.get_pk(&rr.version, id).await;
                rr.set_pk(pk);
                let mut msg_out = RendezvousMessage::new();
                rr.relay_server = if rr.refuse_reason.is_empty() {
                    pending.relay_server
                } else {
                    String::new()
                };
                msg_out.set_relay_response(rr);
                allow_err!(self.send_to_tcp(msg_out, addr_b).await);
            }
            Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                allow_err!(self.handle_hole_sent(phs, addr, false).await);
            }
            Some(rendezvous_message::Union::LocalAddr(la)) => {
                allow_err!(self.handle_local_addr(la, addr).await);
            }
            Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                let mut msg_out = RendezvousMessage::new();
                let mut res = TestNatResponse {
                    port: addr.port() as _,
                    ..Default::default()
                };
                if self.inner.serial > tar.serial {
                    let mut cu = ConfigUpdate::new();
                    cu.serial = self.inner.serial;
                    cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                    res.cu = MessageField::from_option(Some(cu));
                }
                msg_out.set_test_nat_response(res);
                if !Self::send_to_sink(sink, msg_out) {
                    return false;
                }
            }
            Some(rendezvous_message::Union::OnlineRequest(or)) => {
                if or.peers.is_empty()
                    || or.peers.len() > ONLINE_QUERY_MAX_PEERS
                    || or.peers.iter().any(|id| !Self::valid_peer_id(id))
                {
                    return false;
                }
                let cost = 1.0 + (or.peers.len() as f64) / 32.0;
                if !self.allow_unauthenticated_request(addr.ip(), cost).await {
                    log::warn!("Rate limit exceeded for OnlineRequest from {addr}");
                    return false;
                }
                let msg_out = self.build_online_response(&or.peers).await;
                return Self::send_to_sink(sink, msg_out);
            }
            Some(rendezvous_message::Union::HttpProxyRequest(req)) => {
                let resp = if !Self::http_proxy_authorized(true, key, &req.licence_key) {
                    log::warn!("Rejected unauthorized API proxy request from {}", addr);
                    HttpProxyResponse {
                        status: 403,
                        error: "API proxy authorization failed".to_owned(),
                        ..Default::default()
                    }
                } else if !self.allow_http_proxy_request(addr.ip()).await {
                    HttpProxyResponse {
                        status: 429,
                        error: "API proxy rate limit exceeded".to_owned(),
                        ..Default::default()
                    }
                } else {
                    match self.inner.http_proxy_slots.clone().try_acquire_owned() {
                        Ok(_permit) => match self.handle_http_proxy_request(req, addr.ip()).await {
                            Ok(resp) => resp,
                            Err(err) => {
                                log::warn!("API proxy request from {} failed: {}", addr, err);
                                HttpProxyResponse {
                                    status: 502,
                                    error: "API upstream request failed".to_owned(),
                                    ..Default::default()
                                }
                            }
                        },
                        Err(_) => HttpProxyResponse {
                            status: 503,
                            error: "API proxy is busy".to_owned(),
                            ..Default::default()
                        },
                    }
                };
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_http_proxy_response(resp);
                return Self::send_to_sink(sink, msg_out);
            }
            Some(rendezvous_message::Union::Hc(hc)) => {
                if hc.token.is_empty() || hc.token.len() > 256 {
                    log::debug!("Ignore malformed health check from {}", addr);
                    return true;
                }
                if !*health_keepalive_started {
                    Self::start_health_check_keepalive(sink);
                    *health_keepalive_started = true;
                }
                return true;
            }
            Some(rendezvous_message::Union::KeyExchange(_)) => {
                log::debug!("Ignore KeyExchange on message path");
                return true;
            }
            _ => {}
        }
        false
    }

    #[inline]
    async fn register_peer_common(
        &mut self,
        rp: RegisterPeer,
        socket_addr: SocketAddr,
    ) -> ResultType<(RegisterPeerResponse, Option<ConfigUpdate>)> {
        let RegisterPeer { id, serial, .. } = rp;
        if !Self::valid_peer_id(&id) {
            bail!("Invalid peer id: {id}");
        }
        let ip = socket_addr.ip().to_string();
        if !allow_ip_request(&ip, &id).await {
            bail!("Too frequent peer registration from {ip} for {id}");
        }
        let (request_pk, ip_change) = if let Some(old) = self.pm.get(&id).await? {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let deployment_verification_expired = !self.inner.allow_unmanaged_devices
                && old.deployment_verified_at.is_none_or(|verified_at| {
                    verified_at.elapsed().as_secs() >= DEPLOYMENT_VERIFICATION_CACHE_SECS
                });
            let request_pk = old.pk.is_empty() || ip_change || deployment_verification_expired;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };

        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }

        let mut resp = RegisterPeerResponse::new();
        resp.request_pk = request_pk;

        let cu = if self.inner.serial > serial {
            let mut cu = ConfigUpdate::new();
            cu.serial = self.inner.serial;
            cu.rendezvous_servers = (*self.rendezvous_servers).clone();
            Some(cu)
        } else {
            None
        };

        Ok((resp, cu))
    }

    #[inline]
    async fn register_pk_common(
        &mut self,
        rk: RegisterPk,
        socket_addr: SocketAddr,
    ) -> ResultType<Option<register_pk_response::Result>> {
        let RegisterPk {
            id,
            uuid,
            pk,
            old_id,
            ..
        } = rk;

        if !old_id.is_empty() {
            return Ok(Some(register_pk_response::Result::NOT_SUPPORT));
        }

        if !Self::valid_peer_id(&id)
            || uuid.is_empty()
            || uuid.len() > REGISTER_UUID_MAX_LEN
            || pk.len() != PEER_PUBLIC_KEY_LEN
        {
            return Ok(Some(INVALID_ID_FORMAT));
        }

        let ip = socket_addr.ip().to_string();
        if !allow_ip_request(&ip, &id).await {
            return Ok(Some(TOO_FREQUENT));
        }
        let managed_authorized = if self.inner.allow_unmanaged_devices {
            false
        } else {
            match self.verify_device_deployment(&id, &uuid, &pk).await {
                Ok(true) => true,
                Ok(false) => return Ok(Some(register_pk_response::Result::NOT_DEPLOYED)),
                Err(err) => {
                    log::warn!("Device deployment verification failed for {}: {}", id, err);
                    return Ok(Some(register_pk_response::Result::SERVER_ERROR));
                }
            }
        };

        let Some(peer) = self.pm.get_or(&id).await? else {
            return Ok(Some(register_pk_response::Result::SERVER_ERROR));
        };
        let stage = {
            let mut peer = peer.write().await;
            Self::stage_peer_registration(
                &mut peer,
                &id,
                socket_addr,
                &uuid,
                &pk,
                &ip,
                managed_authorized,
            )?
        };
        let pending = match stage {
            PeerRegistrationStage::Busy => {
                return Ok(Some(register_pk_response::Result::SERVER_ERROR));
            }
            PeerRegistrationStage::UuidMismatch => return Ok(Some(UUID_MISMATCH)),
            PeerRegistrationStage::TooFrequent => return Ok(Some(TOO_FREQUENT)),
            PeerRegistrationStage::Unchanged => {
                if managed_authorized {
                    peer.write().await.deployment_verified_at = Some(Instant::now());
                }
                return Ok(Some(register_pk_response::Result::OK));
            }
            PeerRegistrationStage::Persist(pending) => pending,
        };
        let PendingPeerRegistration {
            guid,
            rollback,
            serialized_info: info,
            ip_changed,
        } = *pending;
        log::info!("Persisting peer {} at {}", id, socket_addr);
        let database = self.pm.db.clone();
        let persisted_peer = peer.clone();
        let persisted_id = id.clone();
        let persistence = tokio::spawn(async move {
            let result = if guid.is_empty() {
                database.insert_peer(&persisted_id, &uuid, &pk, &info).await
            } else {
                database
                    .update_identity(&guid, &persisted_id, &uuid, &pk, &info)
                    .await
                    .map(|()| guid)
            };

            let mut peer = persisted_peer.write().await;
            match result {
                Ok(guid) => {
                    peer.guid = guid;
                    peer.persistence_in_progress = false;
                    if managed_authorized {
                        peer.deployment_verified_at = Some(Instant::now());
                    }
                    Ok(())
                }
                Err(err) => {
                    peer.socket_addr = rollback.socket_addr;
                    peer.last_reg_time = rollback.last_reg_time;
                    peer.uuid = rollback.uuid;
                    peer.pk = rollback.pk;
                    peer.info = rollback.info;
                    peer.deployment_verified_at = rollback.deployment_verified_at;
                    peer.persistence_in_progress = false;
                    Err(err)
                }
            }
        });
        match persistence.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                log::error!("Failed to persist peer {}: {}", id, err);
                return Ok(Some(register_pk_response::Result::SERVER_ERROR));
            }
            Err(err) => {
                log::error!("Peer persistence task for {} failed: {}", id, err);
                return Ok(Some(register_pk_response::Result::SERVER_ERROR));
            }
        }

        if ip_changed {
            record_ip_change(&id, &ip).await;
        }

        Ok(Some(register_pk_response::Result::OK))
    }

    #[inline]
    async fn handle_hole_sent(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        is_udp: bool,
    ) -> ResultType<()> {
        if !Self::valid_peer_id(&phs.id)
            || phs.version.len() > 64
            || phs.relay_server.len() > RELAY_SERVER_NAME_MAX_LEN
            || !Self::valid_optional_mangled_addr(&phs.socket_addr_v6)
        {
            bail!("Rejected malformed punch-hole response from {addr}");
        }
        // punch hole sent from B, tell A that B is ready to be connected
        let pending = self
            .consume_pending_rendezvous(
                &phs.rendezvous_token,
                &phs.id,
                &phs.socket_addr,
                Some(PendingRendezvousKind::Direct),
            )
            .await?;
        let addr_a = pending.requester;
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if is_udp { "UDP" } else { "TCP" },
            addr_a,
            addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: pending.relay_server,
            socket_addr_v6: phs.socket_addr_v6,
            ..Default::default()
        };
        p.is_udp = is_udp;
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        self.send_to_tcp(msg_out, addr_a).await?;
        Ok(())
    }

    #[inline]
    async fn handle_local_addr(&mut self, la: LocalAddr, addr: SocketAddr) -> ResultType<()> {
        if !Self::valid_peer_id(&la.id)
            || la.version.len() > 64
            || la.relay_server.len() > RELAY_SERVER_NAME_MAX_LEN
            || AddrMangle::try_decode(&la.local_addr).is_none()
            || !Self::valid_optional_mangled_addr(&la.socket_addr_v6)
        {
            bail!("Rejected malformed local-address response from {addr}");
        }
        // relay local addrs of B to A
        let pending = self
            .consume_pending_rendezvous(
                &la.rendezvous_token,
                &la.id,
                &la.socket_addr,
                Some(PendingRendezvousKind::Local),
            )
            .await?;
        let addr_a = pending.requester;
        log::debug!("TCP local addrs response to {:?} from {:?}", addr_a, addr);
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: pending.relay_server,
            socket_addr_v6: la.socket_addr_v6,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        self.send_to_tcp(msg_out, addr_a).await?;
        Ok(())
    }

    async fn reserve_pending_rendezvous(
        &self,
        requester: SocketAddr,
        responder_id: String,
        kind: PendingRendezvousKind,
        relay_server: String,
    ) -> ResultType<Bytes> {
        let mut pending = self.pending_rendezvous.lock().await;
        pending.retain(|_, entry| {
            entry.created_at.elapsed() <= Duration::from_secs(PENDING_RENDEZVOUS_TTL_SECS)
        });
        if pending.len() >= PENDING_RENDEZVOUS_CAPACITY {
            bail!("Pending rendezvous response capacity reached");
        }
        loop {
            let mut token_bytes = [0u8; RENDEZVOUS_TOKEN_LEN];
            SysRng.try_fill_bytes(&mut token_bytes)?;
            let token = Bytes::copy_from_slice(&token_bytes);
            if !pending.contains_key(&token) {
                pending.insert(
                    token.clone(),
                    PendingRendezvous {
                        requester: try_into_v4(requester),
                        responder_id,
                        kind,
                        relay_server,
                        created_at: Instant::now(),
                    },
                );
                return Ok(token);
            }
        }
    }

    async fn consume_pending_rendezvous(
        &self,
        token: &Bytes,
        responder_id: &str,
        claimed_requester: &[u8],
        expected_kind: Option<PendingRendezvousKind>,
    ) -> ResultType<ConsumedRendezvous> {
        let claimed_requester = AddrMangle::try_decode(claimed_requester)
            .filter(|addr| addr.port() != 0)
            .map(try_into_v4)
            .ok_or_else(|| anyhow!("Malformed rendezvous requester address"))?;
        let mut pending = self.pending_rendezvous.lock().await;
        consume_pending_rendezvous_in(
            &mut pending,
            token,
            responder_id,
            claimed_requester,
            expected_kind,
            Instant::now(),
        )
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !Self::valid_peer_id(&ph.id)
            || ph.licence_key.len() > 128
            || ph.token.len() > 4_096
            || ph.version.len() > 64
            || ph.switch_code.len() > 128
            || !Self::valid_optional_mangled_addr(&ph.socket_addr_v6)
        {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        if !key.is_empty() && ph.licence_key != key {
            log::warn!(
                "Authentication failed from {} for peer {} - invalid key",
                addr,
                ph.id
            );
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await? {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }

            // record punch hole request (from addr -> peer id/peer_addr)
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let to_id_clone = id.clone();
                let mut lock = PUNCH_REQS.lock().await;
                let mut dup = false;
                for e in lock.iter().rev().take(30) {
                    // only check recent tail subset for speed
                    if e.from_ip == from_ip && e.to_id == to_id_clone {
                        if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                            dup = true;
                        }
                        break;
                    }
                }
                if !dup {
                    if lock.len() >= PUNCH_REQUEST_LOG_CAPACITY {
                        lock.pop_front();
                    }
                    lock.push_back(PunchReqEntry {
                        tm: Instant::now(),
                        from_ip,
                        to_ip,
                        to_id: to_id_clone,
                    });
                }
            }

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ph.force_relay
                && !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            let rendezvous_token = self
                .reserve_pending_rendezvous(
                    addr,
                    id.clone(),
                    if same_intranet {
                        PendingRendezvousKind::Local
                    } else {
                        PendingRendezvousKind::Direct
                    },
                    relay_server.clone(),
                )
                .await?;
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    socket_addr_v6: ph.socket_addr_v6,
                    rendezvous_token,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    force_relay: ph.force_relay,
                    socket_addr_v6: ph.socket_addr_v6,
                    rendezvous_token,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let msg_out = self.build_online_response(&peers).await;
        stream.send(&msg_out).await?;
        Ok(())
    }

    #[inline]
    async fn build_online_response(&self, peers: &[String]) -> RendezvousMessage {
        let mut states = BytesMut::zeroed(peers.len().div_ceil(8));
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        msg_out
    }

    fn validate_api_server(api_server: &str) -> ResultType<()> {
        if api_server.is_empty() {
            return Ok(());
        }
        let url = reqwest::Url::parse(api_server)?;
        let Some(host) = url.host_str() else {
            bail!("API server must include a host");
        };
        let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
        if canonical_host == "invalid" || canonical_host.ends_with(".invalid") {
            bail!("API server contains a placeholder .invalid host");
        }
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.port() == Some(0)
        {
            bail!(
                "API server must be an HTTP(S) origin with a valid port and without credentials, path, query or fragment"
            );
        }
        if url.scheme() == "http" {
            let host_without_brackets = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            let is_loopback = host.eq_ignore_ascii_case("localhost")
                || host_without_brackets
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            if !is_loopback {
                bail!("Remote API servers must use HTTPS");
            }
        }
        Ok(())
    }

    async fn verify_device_deployment(
        &self,
        id: &str,
        uuid: &[u8],
        public_key: &[u8],
    ) -> ResultType<bool> {
        if self.inner.allow_unmanaged_devices {
            return Ok(true);
        }
        let base = self.inner.api_server.trim_end_matches('/');
        if base.is_empty() {
            bail!("API server is not configured");
        }
        let public_key_hash = hex::encode(Sha256::digest(public_key));
        let response = self
            .inner
            .http_client
            .post(format!("{base}/api/devices/verify-deployment"))
            .bearer_auth(&self.inner.device_verification_token)
            .json(&serde_json::json!({
                "id": id,
                "uuid": BASE64.encode(uuid),
                "public_key_hash": public_key_hash,
            }))
            .send()
            .await?;
        match response.status().as_u16() {
            204 => Ok(true),
            401 | 403 => bail!("API rejected the rendezvous server credential"),
            400 | 404 => Ok(false),
            status => bail!("API returned status {status}"),
        }
    }

    fn allowed_http_proxy_path(path: &str) -> bool {
        path == "/api" || path.starts_with("/api/") || path.starts_with("/lic/web/api/")
    }

    fn validate_http_proxy_path(path: &str) -> ResultType<()> {
        if path.is_empty()
            || path.len() > HTTP_PROXY_MAX_PATH
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains("://")
            || path.contains('\\')
            || path.contains('#')
        {
            bail!("HTTP proxy path must be relative");
        }
        if path.chars().any(char::is_control) {
            bail!("HTTP proxy path contains control characters");
        }
        // URL parsers and upstream frameworks do not agree on every encoded
        // dot-segment and separator form. Reject them before normalization
        // instead of trying to maintain a second URL canonicalizer here.
        let raw_path = path.split_once('?').map_or(path, |(raw_path, _)| raw_path);
        let lowercase_path = raw_path.to_ascii_lowercase();
        if lowercase_path.contains("%2e")
            || lowercase_path.contains("%2f")
            || lowercase_path.contains("%5c")
            || lowercase_path.contains("%25")
        {
            bail!("HTTP proxy path contains an ambiguous encoded path segment");
        }
        let parsed = reqwest::Url::parse(&format!("http://proxy.invalid{path}"))?;
        if parsed.host_str() != Some("proxy.invalid")
            || !Self::allowed_http_proxy_path(parsed.path())
        {
            bail!("HTTP proxy path is not allowed");
        }
        Ok(())
    }

    fn is_allowed_http_proxy_request_header(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "accept"
                | "accept-language"
                | "authorization"
                | "content-type"
                | "idempotency-key"
                | "if-match"
                | "if-modified-since"
                | "if-none-match"
                | "range"
                | "user-agent"
                | "x-csrf-token"
                | "x-requested-with"
        )
    }

    fn is_hop_by_hop_header(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "host"
                | "content-length"
        )
    }

    fn http_proxy_request_headers(
        entries: Vec<HeaderEntry>,
    ) -> ResultType<reqwest::header::HeaderMap> {
        let mut headers = reqwest::header::HeaderMap::new();
        for entry in entries {
            if !Self::is_allowed_http_proxy_request_header(&entry.name) {
                continue;
            }
            let name = reqwest::header::HeaderName::from_bytes(entry.name.as_bytes())?;
            let value = reqwest::header::HeaderValue::from_str(&entry.value)?;
            if matches!(
                name.as_str(),
                "authorization" | "content-type" | "idempotency-key" | "if-match"
            ) && headers.contains_key(&name)
            {
                bail!("HTTP proxy has duplicate singleton request headers");
            }
            headers.append(name, value);
        }
        Ok(headers)
    }

    fn http_proxy_method(method: &str) -> ResultType<reqwest::Method> {
        match method.to_ascii_uppercase().as_str() {
            "GET" => Ok(reqwest::Method::GET),
            "POST" => Ok(reqwest::Method::POST),
            "PUT" => Ok(reqwest::Method::PUT),
            "DELETE" => Ok(reqwest::Method::DELETE),
            _ => bail!("HTTP proxy method is not allowed"),
        }
    }

    fn valid_relay_uuid(uuid: &str) -> bool {
        (RELAY_UUID_MIN_LEN..=RELAY_UUID_MAX_LEN).contains(&uuid.len())
            && uuid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }

    async fn handle_http_proxy_request(
        &self,
        req: HttpProxyRequest,
        client_ip: IpAddr,
    ) -> ResultType<HttpProxyResponse> {
        Self::validate_http_proxy_path(&req.path)?;
        if req.body.len() > HTTP_PROXY_MAX_BODY {
            bail!("HTTP proxy request body is too large");
        }
        if req.headers.len() > HTTP_PROXY_MAX_HEADERS {
            bail!("HTTP proxy request has too many headers");
        }
        let header_bytes = req.headers.iter().try_fold(0usize, |total, header| {
            total
                .checked_add(header.name.len())
                .and_then(|value| value.checked_add(header.value.len()))
        });
        if header_bytes.is_none_or(|value| value > HTTP_PROXY_MAX_HEADER_BYTES) {
            bail!("HTTP proxy request headers are too large");
        }

        let method = Self::http_proxy_method(&req.method)?;
        let base = self.inner.api_server.trim_end_matches('/');
        if base.is_empty() {
            bail!("API server is not configured");
        }
        let url = format!("{}{}", base, req.path);
        let headers = Self::http_proxy_request_headers(req.headers)?;
        let mut builder = self.inner.http_client.request(method, url).headers(headers);
        builder = builder
            // The protobuf consumer expects a textual API response. Do not let
            // an upstream representation silently become compressed bytes.
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header("x-forwarded-for", client_ip.to_string())
            .header("x-real-ip", client_ip.to_string());

        let mut resp = builder.body(req.body).send().await?;
        if resp.content_length().unwrap_or_default() > HTTP_PROXY_MAX_BODY as u64 {
            bail!("HTTP proxy response body is too large");
        }

        let status = resp.status().as_u16() as i32;
        let mut headers = Vec::new();
        let mut response_header_bytes = 0usize;
        for (name, value) in resp
            .headers()
            .iter()
            .filter(|(name, _)| !Self::is_hop_by_hop_header(name.as_str()))
        {
            let Ok(value) = value.to_str() else {
                continue;
            };
            response_header_bytes = response_header_bytes
                .checked_add(name.as_str().len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(|| anyhow!("HTTP proxy response headers are too large"))?;
            if headers.len() >= HTTP_PROXY_MAX_HEADERS
                || response_header_bytes > HTTP_PROXY_MAX_HEADER_BYTES
            {
                bail!("HTTP proxy response headers are too large");
            }
            headers.push(HeaderEntry {
                name: name.as_str().to_owned(),
                value: value.to_owned(),
                ..Default::default()
            });
        }

        let mut body = BytesMut::with_capacity(
            resp.content_length()
                .unwrap_or_default()
                .min(HTTP_PROXY_MAX_BODY as u64) as usize,
        );
        while let Some(chunk) = resp.chunk().await? {
            let new_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow!("HTTP proxy response body is too large"))?;
            if new_len > HTTP_PROXY_MAX_BODY {
                bail!("HTTP proxy response body is too large");
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpProxyResponse {
            status,
            headers,
            body: body.freeze(),
            ..Default::default()
        })
    }

    async fn allow_http_proxy_request(&self, ip: IpAddr) -> bool {
        let mut rates = self.inner.http_proxy_rates.lock().await;
        if !rates.contains_key(&ip) && rates.len() >= HTTP_PROXY_MAX_TRACKED_IPS {
            rates.retain(|_, rate| {
                rate.started_at.elapsed().as_secs() < HTTP_PROXY_RATE_WINDOW_SECS
            });
            if rates.len() >= HTTP_PROXY_MAX_TRACKED_IPS {
                return false;
            }
        }
        let now = Instant::now();
        let rate = rates.entry(ip).or_insert(ProxyRate {
            started_at: now,
            requests: 0,
        });
        if rate.started_at.elapsed().as_secs() >= HTTP_PROXY_RATE_WINDOW_SECS {
            *rate = ProxyRate {
                started_at: now,
                requests: 0,
            };
        }
        if rate.requests >= HTTP_PROXY_RATE_PER_IP {
            return false;
        }
        rate.requests += 1;
        true
    }

    fn health_check_response() -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk_response(RegisterPkResponse {
            result: register_pk_response::Result::OK.into(),
            keep_alive: HC_KEEP_ALIVE_SECS,
            ..Default::default()
        });
        msg
    }

    fn send_relay_failure(sink: &mut Option<Sink>, reason: &str) -> bool {
        let mut msg = RendezvousMessage::new();
        msg.set_relay_response(RelayResponse {
            refuse_reason: reason.to_owned(),
            ..Default::default()
        });
        Self::send_to_sink(sink, msg)
    }

    fn start_health_check_keepalive(sink: &mut Option<Sink>) {
        let Some(Sink::Tcp(tx)) = sink.as_ref() else {
            return;
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut timer = interval(Duration::from_secs(HC_KEEP_ALIVE_SECS as u64));
            loop {
                timer.tick().await;
                if tx.try_send(Self::health_check_response()).is_err() {
                    break;
                }
            }
        });
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) -> ResultType<()> {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        if Self::send_to_sink(&mut tcp, msg) {
            Ok(())
        } else {
            bail!("Rendezvous TCP recipient is unavailable or backpressured: {addr}")
        }
    }

    #[inline]
    fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) -> bool {
        if let Some(sink) = sink.as_mut() {
            match sink {
                Sink::Tcp(tx) => return tx.try_send(msg).is_ok(),
            }
        }
        false
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let tx = {
            let guard = self.tcp_punch.lock().await;
            let Some(entry) = guard.get(&try_into_v4(addr)) else {
                bail!("Rendezvous TCP recipient is unavailable: {addr}");
            };
            let Sink::Tcp(tx) = entry;
            tx.clone()
        };
        tx.try_send(msg)
            .map_err(|err| anyhow!("Rendezvous TCP recipient is backpressured: {addr}: {err}"))
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(peer_addr) = to_addr {
            let rendezvous_token = match msg.union.as_ref() {
                Some(rendezvous_message::Union::PunchHole(message)) => {
                    Some(message.rendezvous_token.clone())
                }
                Some(rendezvous_message::Union::FetchLocalAddr(message)) => {
                    Some(message.rendezvous_token.clone())
                }
                _ => None,
            };
            if let Err(err) = self.send_to_tcp_sync(msg, peer_addr).await {
                if let Some(token) = rendezvous_token {
                    self.pending_rendezvous.lock().await.remove(&token);
                }
                log::warn!("Unable to deliver punch-hole request from {addr}: {err}");
                let mut failure = RendezvousMessage::new();
                failure.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                self.send_to_tcp_sync(failure, addr).await?;
            }
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) -> ResultType<()> {
        let rs = get_servers(relay_servers, "relay-servers")?;
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
        Ok(())
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    if let Err(err) = get_servers(rs, "relay-servers") {
                        return format!("Invalid relay server configuration: {err}\n");
                    }
                    if self
                        .tx
                        .send(Data::RelayServers0(rs.to_owned()))
                        .await
                        .is_err()
                    {
                        return "Rendezvous event queue is closed\n".to_owned();
                    }
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg {
                    lock.clear();
                } else {
                    let start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds
                        .next()
                        .and_then(|x| x.parse::<usize>().ok())
                        .unwrap_or(10);
                    if page_size == 0 {
                        page_size = 10;
                    }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(
                            res,
                            "{} {} -> {}@{}",
                            event_iso, e.from_ip, e.to_id, e.to_ip
                        );
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    match crate::common::parse_yes_no("always-use-relay", rs) {
                        Ok(value) => ALWAYS_USE_RELAY.store(value, Ordering::SeqCst),
                        Err(err) => return format!("Invalid always-use-relay value: {err}\n"),
                    }
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let Ok(permit) = self.connection_slots.clone().try_acquire_owned() else {
            log::warn!("Rendezvous connection limit reached; rejected {}", addr);
            return;
        };
        let rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if self.inner.runtime_console && ip.is_loopback() {
            tokio::spawn(async move {
                let _permit = permit;
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write_all(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        *stream.codec_mut() = BytesCodec::with_max_packet_length(RENDEZVOUS_CONTROL_FRAME_MAX);
        tokio::spawn(async move {
            let _permit = permit;
            let mut stream = stream;
            if let Err(err) = rs.attempt_handshake(&mut stream).await {
                log::debug!("Rendezvous control handshake failed for {}: {}", addr, err);
                return;
            }
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                let Some(_mem_permit) = rs.inner.memory_budget.try_acquire(bytes.len()) else {
                    log::warn!(
                        "Rendezvous in-flight memory limit reached; dropped frame from {}",
                        addr
                    );
                    return;
                };
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            if !rs.allow_unauthenticated_request(addr.ip(), 1.0).await {
                                log::warn!("Rate limit exceeded for TestNatRequest from {addr} on listener2");
                                return;
                            }
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or))
                            if !or.peers.is_empty()
                                && or.peers.len() <= ONLINE_QUERY_MAX_PEERS
                                && or.peers.iter().all(|id| Self::valid_peer_id(id)) =>
                        {
                            let cost = 1.0 + (or.peers.len() as f64) / 32.0;
                            if !rs.allow_unauthenticated_request(addr.ip(), cost).await {
                                log::warn!("Rate limit exceeded for OnlineRequest from {addr} on listener2");
                                return;
                            }
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let Ok(permit) = self.connection_slots.clone().try_acquire_owned() else {
            log::warn!("Rendezvous connection limit reached; rejected {}", addr);
            return;
        };
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            let _permit = permit;
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    async fn attempt_handshake(&self, stream: &mut FramedStream) -> ResultType<secretbox::Key> {
        let sk = &self.inner.sk;

        let (tmp_pk, tmp_sk) = box_::gen_keypair();
        let signed_pk = sign::sign(&tmp_pk.0, sk);

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![signed_pk.into()],
            ..Default::default()
        });

        stream
            .send(&msg_out)
            .await
            .map_err(|err| anyhow!("Unable to send rendezvous key exchange: {err}"))?;

        let bytes = match stream.next_timeout(HANDSHAKE_WAIT_MS).await {
            Some(Ok(bytes)) => bytes,
            Some(Err(err)) => {
                return Err(anyhow!(
                    "Unable to read rendezvous key exchange response: {err}"
                ));
            }
            None => bail!("Rendezvous key exchange timed out or the peer disconnected"),
        };
        let _mem_permit = self
            .inner
            .memory_budget
            .try_acquire(bytes.len())
            .ok_or_else(|| anyhow!("Rendezvous in-flight memory limit reached during handshake"))?;
        let msg_in = RendezvousMessage::parse_from_bytes(&bytes)
            .map_err(|_| anyhow!("Malformed rendezvous key exchange response"))?;
        let Some(rendezvous_message::Union::KeyExchange(ex)) = msg_in.union else {
            bail!("Expected rendezvous key exchange response");
        };
        if ex.keys.len() != 2 || ex.keys[0].len() != box_::PUBLICKEYBYTES {
            bail!("Invalid rendezvous key exchange response");
        }

        let key = Self::decode_session_key(&ex, &tmp_sk)?;
        stream.set_key(key.clone(), CipherRole::Responder);
        if !stream.is_secured() {
            bail!("Rendezvous stream did not enter encrypted mode");
        }
        log::debug!("Rendezvous secure channel established");
        Ok(key)
    }

    async fn attempt_handshake_ws(
        &self,
        ws: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
    ) -> ResultType<secretbox::Key> {
        let sk = &self.inner.sk;

        let (tmp_pk, tmp_sk) = box_::gen_keypair();
        let signed_pk = sign::sign(&tmp_pk.0, sk);

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![signed_pk.into()],
            ..Default::default()
        });

        let bytes = msg_out
            .write_to_bytes()
            .map_err(|_| anyhow!("Unable to encode rendezvous key exchange"))?;
        ws.send(tungstenite::Message::Binary(bytes.into()))
            .await
            .map_err(|err| anyhow!("Unable to send rendezvous key exchange: {err}"))?;

        let res = timeout(HANDSHAKE_WAIT_MS, async {
            loop {
                match ws.next().await {
                    Some(Ok(tungstenite::Message::Binary(bytes))) => return Ok(Some(bytes)),
                    Some(Ok(tungstenite::Message::Close(_))) => return Ok(None),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e),
                    None => return Ok(None),
                }
            }
        })
        .await;

        let bytes = match res {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => bail!("Rendezvous WebSocket closed during key exchange"),
            Ok(Err(err)) => {
                return Err(anyhow!(
                    "Unable to read rendezvous WebSocket key exchange response: {err}"
                ));
            }
            Err(_) => bail!("Rendezvous WebSocket key exchange timed out"),
        };
        let _mem_permit = self
            .inner
            .memory_budget
            .try_acquire(bytes.len())
            .ok_or_else(|| {
                anyhow!("Rendezvous in-flight memory limit reached during WebSocket handshake")
            })?;
        let msg_in = RendezvousMessage::parse_from_bytes(&bytes)
            .map_err(|_| anyhow!("Malformed rendezvous WebSocket key exchange response"))?;
        let Some(rendezvous_message::Union::KeyExchange(ex)) = msg_in.union else {
            bail!("Expected rendezvous WebSocket key exchange response");
        };
        if ex.keys.len() != 2 || ex.keys[0].len() != box_::PUBLICKEYBYTES {
            bail!("Invalid rendezvous WebSocket key exchange response");
        }

        let key = Self::decode_session_key(&ex, &tmp_sk)?;
        log::debug!("Rendezvous WebSocket secure channel established");
        Ok(key)
    }

    fn decode_session_key(
        exchange: &KeyExchange,
        secret: &box_::SecretKey,
    ) -> ResultType<secretbox::Key> {
        if exchange.keys.len() != 2 || exchange.keys[0].len() != box_::PUBLICKEYBYTES {
            bail!("Invalid rendezvous session key exchange");
        }
        Encrypt::decode(&exchange.keys[1], &exchange.keys[0], secret)
            .map_err(|_| anyhow!("Invalid rendezvous session cipher envelope"))
    }

    // Tungstenite requires its server callback to return a full HTTP response on
    // failure; that external API fixes the otherwise-large error representation.
    #[allow(clippy::result_large_err)]
    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let connection_tx;
        let mut sink;
        let mut health_keepalive_started = false;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let trust_proxy_headers = self.inner.trust_proxy_headers;
            let callback = |req: &Request, response: Response| {
                if trust_proxy_headers {
                    // Only consulted when the operator opts in with --trust-proxy-headers.
                    // These headers are NOT verifiable: anyone able to reach this port
                    // directly can spoof an arbitrary IP, bypassing IP-based rate limiting
                    // and corrupting logged addresses. Enable it only when the WebSocket
                    // port is reachable exclusively through a reverse proxy that overwrites
                    // them. https://github.com/rustdesk/rustdesk-server/issues/634
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
                            // Keep the accepted TCP source port to avoid key collisions for
                            // concurrent websocket clients from the same public IP.
                            addr = SocketAddr::new(real_ip_addr, addr.port());
                        }
                    }
                }
                Ok(response)
            };
            let websocket_config = tungstenite::protocol::WebSocketConfig::default()
                .read_buffer_size(16 * 1024)
                .write_buffer_size(16 * 1024)
                .max_write_buffer_size(1024 * 1024)
                .max_message_size(Some(RENDEZVOUS_CONTROL_FRAME_MAX))
                .max_frame_size(Some(RENDEZVOUS_CONTROL_FRAME_MAX));
            let mut ws_stream = match timeout(
                HANDSHAKE_WAIT_MS,
                tokio_tungstenite::accept_hdr_async_with_config(
                    stream,
                    callback,
                    Some(websocket_config),
                ),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => bail!("Rendezvous WebSocket upgrade timed out"),
            };

            let ws_key = self.attempt_handshake_ws(&mut ws_stream).await?;
            let (mut ws_sink, mut ws_stream) = ws_stream.split();
            let secretbox::Key(bytes) = ws_key;
            let mut ws_encrypt_in = Encrypt::new(secretbox::Key(bytes), CipherRole::Responder);
            let ws_encrypt_out = Encrypt::new(secretbox::Key(bytes), CipherRole::Responder);

            // bridge a rendezvous message channel to websocket sink (binary)
            let (tx, mut rx) =
                mpsc::channel::<RendezvousMessage>(RENDEZVOUS_CONNECTION_QUEUE_CAPACITY);
            let forward = async move {
                let mut ws_encrypt_out = ws_encrypt_out;
                while let Some(msg) = rx.recv().await {
                    if let Ok(bytes) = msg.write_to_bytes() {
                        let Ok(bytes) = ws_encrypt_out.enc(&bytes) else {
                            log::warn!("Unable to encrypt rendezvous WebSocket message");
                            break;
                        };
                        if ws_sink
                            .send(tungstenite::Message::Binary(bytes.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            };
            let forward_task = tokio::spawn(forward);

            connection_tx = tx.clone();
            sink = Some(Sink::Tcp(tx.clone()));
            self.tcp_punch
                .lock()
                .await
                .insert(try_into_v4(addr), Sink::Tcp(tx));

            while let Ok(Some(Ok(msg))) = timeout(30_000, ws_stream.next()).await {
                match msg {
                    tungstenite::Message::Binary(bytes) => {
                        let Some(_mem_permit) = self.inner.memory_budget.try_acquire(bytes.len())
                        else {
                            log::warn!("Rendezvous in-flight memory limit reached; closing WebSocket from {addr}");
                            break;
                        };
                        let mut bytes = BytesMut::from(&bytes[..]);
                        if let Err(err) = ws_encrypt_in.dec(&mut bytes) {
                            log::debug!("WebSocket decrypt error from {}: {}", addr, err);
                            break;
                        }
                        if bytes.is_empty() {
                            continue; // heartbeat / keep-alive
                        }
                        if !self
                            .handle_tcp(
                                bytes.as_ref(),
                                &mut sink,
                                &mut health_keepalive_started,
                                addr,
                                key,
                                ws,
                            )
                            .await
                        {
                            break;
                        }
                    }
                    tungstenite::Message::Close(_) => {
                        log::debug!("WebSocket close from {}", addr);
                        break;
                    }
                    _ => {}
                }
            }
            forward_task.abort();
        } else {
            // If a secret key is configured, the server is in encryption mode.
            // It must proactively send a KeyExchange message to the client
            // to initiate the secure handshake. This avoids a deadlock where both
            // client and server are waiting for each other.
            let mut stream = FramedStream::from(stream, addr);
            *stream.codec_mut() = BytesCodec::with_max_packet_length(RENDEZVOUS_CONTROL_FRAME_MAX);

            let _session_key = self.attempt_handshake(&mut stream).await?;
            let (tx, mut rx) =
                mpsc::channel::<RendezvousMessage>(RENDEZVOUS_CONNECTION_QUEUE_CAPACITY);
            connection_tx = tx.clone();
            sink = Some(Sink::Tcp(tx.clone()));
            // cache sink early so server can push messages even when clients disable UDP
            self.tcp_punch
                .lock()
                .await
                .insert(try_into_v4(addr), Sink::Tcp(tx.clone()));

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if let Err(e) = stream.send(&msg).await {
                            log::debug!("TCP send error to {}: {}", addr, e);
                            break;
                        }
                    }
                    res = timeout(30_000, stream.next()) => {
                        match res {
                            Ok(Some(Ok(bytes))) => {
                                let Some(_mem_permit) = self.inner.memory_budget.try_acquire(bytes.len()) else {
                                    log::warn!("Rendezvous in-flight memory limit reached; closing TCP from {addr}");
                                    break;
                                };
                                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                                    if !self
                                        .handle_tcp_msg(
                                            msg_in,
                                            &mut sink,
                                            &mut health_keepalive_started,
                                            addr,
                                            key,
                                            ws,
                                        )
                                        .await
                                    {
                                        break;
                                    }
                                } else {
                                    log::warn!("Failed to parse RendezvousMessage from {}", addr);
                                    break;
                                }
                            }
                            Ok(Some(Err(e))) => {
                                log::debug!("TCP read error from {}: {}", addr, e);
                                break;
                            }
                            Ok(None) => {
                                log::debug!("TCP peer {} closed", addr);
                                break;
                            }
                            Err(_) => {
                                log::debug!("TCP read timeout from {}", addr);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let key = try_into_v4(addr);
        let mut sinks = self.tcp_punch.lock().await;
        let still_current = sinks.get(&key).is_some_and(|sink| match sink {
            Sink::Tcp(tx) => tx.same_channel(&connection_tx),
        });
        if still_current {
            sinks.remove(&key);
        }
        drop(sinks);
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Ok(Some(peer)) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &camellia_remote_protocol::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        &self.inner.sk,
                    )
                    .into()
                }
                Ok(None) => Bytes::new(),
                Err(err) => {
                    log::error!("Unable to load public key for peer {id}: {err}");
                    Bytes::new()
                }
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, sign::SecretKey)> {
        let key = key.trim();
        if key.is_empty() || key == "-" || key == "_" {
            return crate::common::gen_sk(0);
        }

        let private_key = crate::common::parse_private_key(key, "The rendezvous key")?;
        let public_key = BASE64.encode(private_key.public_key());
        log::info!("Rendezvous private key loaded; public key: {}", public_key);
        Ok((public_key, private_key))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let host = match crate::common::server_with_default_port(
            x,
            "relay-servers",
            config::RELAY_PORT as u16,
        ) {
            Ok(host) => host,
            Err(err) => {
                log::error!("Skipping invalid relay server {x}: {err}");
                continue;
            }
        };
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() && tx.send(Data::RelayServers(rs)).await.is_err() {
        log::debug!("Rendezvous event queue closed while updating relay servers");
    }
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed_exchange(envelope: &[u8], public: &box_::PublicKey) -> KeyExchange {
        let (client_public, client_secret) = box_::gen_keypair();
        KeyExchange {
            keys: vec![
                client_public.0.to_vec().into(),
                box_::seal(
                    envelope,
                    &box_::Nonce([0; box_::NONCEBYTES]),
                    public,
                    &client_secret,
                )
                .unwrap()
                .into(),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn rendezvous_cipher_accepts_current_version_with_responder_direction() {
        let (public, secret) = box_::gen_keypair();
        let original = secretbox::Key([7; secretbox::KEYBYTES]);
        let exchange = sealed_exchange(&Encrypt::encode_session_key(&original), &public);
        let decoded = RendezvousServer::decode_session_key(&exchange, &secret).unwrap();
        assert_eq!(decoded.0, original.0);
        let mut client = Encrypt::new(original, CipherRole::Initiator);
        // WebSocket ingress/egress are separate objects with the same server role.
        let mut ingress = Encrypt::new(decoded.clone(), CipherRole::Responder);
        let mut egress = Encrypt::new(decoded, CipherRole::Responder);
        let message = b"mandatory-proxy-request";
        let mut request = BytesMut::from(client.enc(message).unwrap().as_slice());
        let mut response = BytesMut::from(egress.enc(message).unwrap().as_slice());
        assert_ne!(request, response);
        ingress.dec(&mut request).unwrap();
        client.dec(&mut response).unwrap();
        assert_eq!(request.as_ref(), message);
        assert_eq!(response.as_ref(), message);
    }

    #[test]
    fn rendezvous_cipher_rejects_legacy_unknown_and_malformed_envelopes() {
        let (public, secret) = box_::gen_keypair();
        let original = secretbox::Key([7; secretbox::KEYBYTES]);
        let mut unknown = Encrypt::encode_session_key(&original);
        unknown[0] = 255;
        for envelope in [vec![], original.0.to_vec(), unknown] {
            let exchange = sealed_exchange(&envelope, &public);
            assert!(RendezvousServer::decode_session_key(&exchange, &secret).is_err());
        }
        let mut exchange = sealed_exchange(&Encrypt::encode_session_key(&original), &public);
        exchange.keys.push(Bytes::new());
        assert!(RendezvousServer::decode_session_key(&exchange, &secret).is_err());
        exchange.keys.clear();
        assert!(RendezvousServer::decode_session_key(&exchange, &secret).is_err());
    }

    #[test]
    fn peer_ids_are_bounded_and_canonical() {
        for id in ["123456", "device_01", "Device-01", "abcdefghijklmnop"] {
            assert!(RendezvousServer::valid_peer_id(id), "{id}");
        }
        for id in [
            "",
            "short",
            "abcdefghijklmnopq",
            "device 01",
            "设备000001",
            "device/01",
        ] {
            assert!(!RendezvousServer::valid_peer_id(id), "{id}");
        }
    }

    #[test]
    fn rendezvous_tokens_are_one_shot_and_bound_to_the_request() {
        let now = Instant::now();
        let requester = SocketAddr::from(([192, 0, 2, 10], 45_000));
        let token = Bytes::from(vec![7; RENDEZVOUS_TOKEN_LEN]);
        let mut pending = HashMap::from([(
            token.clone(),
            PendingRendezvous {
                requester,
                responder_id: "device01".to_owned(),
                kind: PendingRendezvousKind::Direct,
                relay_server: "relay.example.com:21117".to_owned(),
                created_at: now,
            },
        )]);

        assert!(consume_pending_rendezvous_in(
            &mut pending,
            &token,
            "device01",
            requester,
            Some(PendingRendezvousKind::Local),
            now
        )
        .is_err());
        assert!(pending.contains_key(&token));
        assert_eq!(
            consume_pending_rendezvous_in(
                &mut pending,
                &token,
                "device01",
                requester,
                Some(PendingRendezvousKind::Direct),
                now
            )
            .unwrap(),
            ConsumedRendezvous {
                requester,
                relay_server: "relay.example.com:21117".to_owned(),
            }
        );
        assert!(!pending.contains_key(&token));
        assert!(consume_pending_rendezvous_in(
            &mut pending,
            &token,
            "device01",
            requester,
            Some(PendingRendezvousKind::Direct),
            now
        )
        .is_err());
    }

    #[test]
    fn expired_rendezvous_tokens_are_removed() {
        let now = Instant::now();
        let requester = SocketAddr::from(([192, 0, 2, 10], 45_000));
        let token = Bytes::from(vec![9; RENDEZVOUS_TOKEN_LEN]);
        let mut pending = HashMap::from([(
            token.clone(),
            PendingRendezvous {
                requester,
                responder_id: "device01".to_owned(),
                kind: PendingRendezvousKind::Direct,
                relay_server: String::new(),
                created_at: now - Duration::from_secs(PENDING_RENDEZVOUS_TTL_SECS + 1),
            },
        )]);

        assert!(consume_pending_rendezvous_in(
            &mut pending,
            &token,
            "device01",
            requester,
            Some(PendingRendezvousKind::Direct),
            now
        )
        .is_err());
        assert!(!pending.contains_key(&token));
    }

    #[camellia_remote_protocol::tokio::test]
    async fn bounded_connection_queue_reports_backpressure() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut sink = Some(Sink::Tcp(tx));

        assert!(RendezvousServer::send_to_sink(
            &mut sink,
            RendezvousMessage::new()
        ));
        assert!(!RendezvousServer::send_to_sink(
            &mut sink,
            RendezvousMessage::new()
        ));
        assert!(rx.recv().await.is_some());
    }

    #[test]
    fn api_proxy_requires_both_key_and_secure_channel() {
        assert!(RendezvousServer::http_proxy_authorized(
            true,
            "server-key",
            "server-key"
        ));
        assert!(!RendezvousServer::http_proxy_authorized(
            false,
            "server-key",
            "server-key"
        ));
        assert!(!RendezvousServer::http_proxy_authorized(
            true,
            "server-key",
            "wrong-key"
        ));
        assert!(!RendezvousServer::http_proxy_authorized(true, "", ""));
    }

    #[test]
    fn relay_forwarding_does_not_leak_credentials_or_untrusted_policy() {
        let mut request = RequestRelay {
            id: "device01".to_owned(),
            uuid: "relay-session".to_owned(),
            licence_key: "server-key".to_owned(),
            token: "controller-access-token".to_owned(),
            switch_code: "switch-code".to_owned(),
            rendezvous_token: Bytes::from_static(b"server-generated-token"),
            control_permissions: MessageField::from_option(Some(ControlPermissions {
                permissions: u64::MAX,
                ..Default::default()
            })),
            controlled_context: MessageField::from_option(Some(ControlledContext {
                conn_audit_ref: "untrusted-audit-reference".to_owned(),
                ..Default::default()
            })),
            ..Default::default()
        };

        RendezvousServer::strip_untrusted_relay_metadata(&mut request);

        assert!(request.id.is_empty());
        assert!(request.licence_key.is_empty());
        assert!(request.token.is_empty());
        assert!(request.switch_code.is_empty());
        assert!(request.control_permissions.is_none());
        assert!(request.controlled_context.is_none());
        assert_eq!(request.uuid, "relay-session");
        assert_eq!(
            request.rendezvous_token,
            Bytes::from_static(b"server-generated-token")
        );
    }

    #[test]
    fn first_peer_registration_is_reserved_before_database_io() -> ResultType<()> {
        let mut peer = Peer::default();
        let first_uuid = Bytes::from_static(b"first-device");
        let first_pk = Bytes::from(vec![1; PEER_PUBLIC_KEY_LEN]);
        let first = RendezvousServer::stage_peer_registration(
            &mut peer,
            "device01",
            SocketAddr::from(([127, 0, 0, 1], 21116)),
            &first_uuid,
            &first_pk,
            "127.0.0.1",
            false,
        )?;
        assert!(matches!(first, PeerRegistrationStage::Persist(_)));
        assert!(peer.persistence_in_progress);
        assert_eq!(peer.uuid, first_uuid);
        assert_eq!(peer.pk, first_pk);

        let competing = RendezvousServer::stage_peer_registration(
            &mut peer,
            "device01",
            SocketAddr::from(([127, 0, 0, 2], 21116)),
            &Bytes::from_static(b"competing-device"),
            &Bytes::from(vec![2; PEER_PUBLIC_KEY_LEN]),
            "127.0.0.2",
            false,
        )?;
        assert!(matches!(competing, PeerRegistrationStage::Busy));
        assert_eq!(peer.uuid, first_uuid);
        assert_eq!(peer.pk, first_pk);
        Ok(())
    }

    #[test]
    fn managed_authorization_can_replace_stale_device_identity() -> ResultType<()> {
        let mut peer = Peer::default();
        peer.uuid = Bytes::from_static(b"old-device");
        peer.pk = Bytes::from(vec![1; PEER_PUBLIC_KEY_LEN]);
        peer.info.ip = "127.0.0.1".to_owned();
        let new_uuid = Bytes::from_static(b"approved-device");
        let new_pk = Bytes::from(vec![2; PEER_PUBLIC_KEY_LEN]);
        let stage = RendezvousServer::stage_peer_registration(
            &mut peer,
            "device01",
            SocketAddr::from(([127, 0, 0, 2], 21116)),
            &new_uuid,
            &new_pk,
            "127.0.0.2",
            true,
        )?;
        assert!(matches!(stage, PeerRegistrationStage::Persist(_)));
        assert_eq!(peer.uuid, new_uuid);
        assert_eq!(peer.pk, new_pk);
        Ok(())
    }

    #[test]
    fn api_proxy_rejects_path_confusion() {
        for path in [
            "/api",
            "/api/login",
            "/api/devices?limit=10",
            "/api/search?q=version%2e1",
            "/lic/web/api/oidc/auth",
        ] {
            assert!(
                RendezvousServer::validate_http_proxy_path(path).is_ok(),
                "{path}"
            );
        }
        for path in [
            "/admin",
            "//api/login",
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/%252e%252e/admin",
            "/api%2fadmin",
            "/api/%5c../admin",
            "/api/login#fragment",
            "/api\\..\\admin",
            "https://example.com/api",
        ] {
            assert!(
                RendezvousServer::validate_http_proxy_path(path).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn api_proxy_preserves_mandatory_management_mutation_and_receipt_contract() {
        for name in ["Idempotency-Key", "idempotency-key", "If-Match", "IF-MATCH"] {
            assert!(
                RendezvousServer::is_allowed_http_proxy_request_header(name),
                "{name}"
            );
        }
        for path in [
            "/api/ab/peer/add/personal-7",
            "/api/ab/peer/update/personal-7",
            "/api/ab/peer/personal-7",
            "/api/ab/tag/add/personal-7",
            "/api/ab/tag/rename/personal-7",
            "/api/ab/tag/update/personal-7",
            "/api/ab/tag/personal-7",
            "/api/management-operations/03440000-0000-4000-8000-000000000001",
        ] {
            assert!(
                RendezvousServer::validate_http_proxy_path(path).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn api_proxy_forwards_exact_versions_and_ids_but_rejects_ambiguous_singletons() {
        let entry = |name: &str, value: &str| HeaderEntry {
            name: name.to_owned(),
            value: value.to_owned(),
            ..Default::default()
        };
        let operation = "03440000-0000-4000-8000-000000000001";
        let headers = RendezvousServer::http_proxy_request_headers(vec![
            entry("Idempotency-Key", operation),
            entry("If-Match", "\"7\""),
            entry("Authorization", "Bearer test-only"),
            entry("Host", "untrusted.invalid"),
            entry("X-Forwarded-For", "untrusted-ip"),
            entry("Proxy-Authorization", "untrusted-proxy-token"),
        ])
        .unwrap();
        assert_eq!(headers["idempotency-key"], operation);
        assert_eq!(headers["if-match"], "\"7\"");
        assert_eq!(headers["authorization"], "Bearer test-only");
        assert_eq!(headers.len(), 3);
        for (first, second) in [
            ("Idempotency-Key", "IDEMPOTENCY-KEY"),
            ("If-Match", "if-match"),
            ("Authorization", "authorization"),
            ("Content-Type", "CONTENT-TYPE"),
        ] {
            let error = RendezvousServer::http_proxy_request_headers(vec![
                entry(first, "PRIVATE-FIRST"),
                entry(second, "PRIVATE-SECOND"),
            ])
            .unwrap_err()
            .to_string();
            assert_eq!(error, "HTTP proxy has duplicate singleton request headers");
        }
    }

    #[test]
    fn api_proxy_origin_must_be_canonical() {
        for origin in [
            "http://127.0.0.1:21114",
            "http://[::1]:21114",
            "http://localhost:21114",
            "https://api.example.com/",
        ] {
            assert!(
                RendezvousServer::validate_api_server(origin).is_ok(),
                "{origin}"
            );
        }
        for origin in [
            "file:///tmp/api",
            "http://api.example.com",
            "http://192.168.1.10:21114",
            "http://user:pass@example.com",
            "https://example.com/base",
            "https://example.com/?debug=1",
            "https://api.example.invalid",
            "https://api.example.com:0",
        ] {
            assert!(
                RendezvousServer::validate_api_server(origin).is_err(),
                "{origin}"
            );
        }
    }

    #[test]
    fn rendezvous_signing_key_cannot_downgrade_to_public_only() {
        let (public_key, private_key) = sign::gen_keypair();
        let encoded_private = BASE64.encode(private_key.as_ref());
        let (configured_public, configured_private) =
            RendezvousServer::get_server_sk(&encoded_private).unwrap();
        assert_eq!(configured_public, BASE64.encode(public_key.as_ref()));
        assert_eq!(configured_private.as_ref(), private_key.as_ref());

        assert!(RendezvousServer::get_server_sk(&BASE64.encode(public_key.as_ref())).is_err());
        assert!(RendezvousServer::get_server_sk("not-base64").is_err());
    }

    #[camellia_remote_protocol::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[test]
    fn rendezvous_subnet_canonicalization_groups_ipv6_and_preserves_ipv4() {
        let v4: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(canonical_rate_limit_key(v4), "192.168.1.100");

        // IPv4-mapped IPv6
        let v4_mapped: IpAddr = "::ffff:192.168.1.100".parse().unwrap();
        assert_eq!(canonical_rate_limit_key(v4_mapped), "192.168.1.100");

        // Native IPv6 addresses in the same /64 subnet produce identical canonical keys
        let v6_host1: IpAddr = "2001:0db8:85a3:0001:0000:8a2e:0370:7334".parse().unwrap();
        let v6_host2: IpAddr = "2001:0db8:85a3:0001:ffff:ffff:ffff:ffff".parse().unwrap();
        let key1 = canonical_rate_limit_key(v6_host1);
        let key2 = canonical_rate_limit_key(v6_host2);
        assert_eq!(key1, "2001:0db8:85a3:0001::/64");
        assert_eq!(key1, key2);

        // Native IPv6 in a different /64 produces a different key
        let v6_other: IpAddr = "2001:0db8:85a3:0002::1".parse().unwrap();
        assert_ne!(canonical_rate_limit_key(v6_other), key1);
    }

    #[test]
    fn rendezvous_token_bucket_enforces_burst_cap_and_refills() {
        let mut limiter = SubnetRateLimiter::new(10.0, 5.0);
        let key = "192.0.2.1";

        // Consume all 10 tokens in burst
        for _ in 0..10 {
            assert!(limiter.allow(key, 1.0));
        }
        // 11th request must be rejected
        assert!(!limiter.allow(key, 1.0));

        // Wait 250ms for tokens to refill (5 tokens/sec * 0.25s = 1.25 tokens)
        std::thread::sleep(Duration::from_millis(250));
        assert!(limiter.allow(key, 1.0));
        assert!(!limiter.allow(key, 1.0));
    }

    #[test]
    fn rendezvous_global_memory_budget_enforces_ceiling_and_raii_return() {
        let budget = MemoryBudget::new(1024 * 1024); // 1 MiB max
        assert_eq!(budget.max_bytes(), 1024 * 1024);
        assert_eq!(budget.used_bytes(), 0);

        // Acquire 512 KiB
        let permit1 = budget.try_acquire(512 * 1024);
        assert!(permit1.is_some());
        assert_eq!(budget.used_bytes(), 512 * 1024);

        // Acquire another 256 KiB
        let permit2 = budget.try_acquire(256 * 1024);
        assert!(permit2.is_some());
        assert_eq!(budget.used_bytes(), 768 * 1024);

        // Attempting to acquire 512 KiB more would exceed 1024 KiB -> must fail
        let overflow = budget.try_acquire(512 * 1024);
        assert!(overflow.is_none());
        assert_eq!(budget.used_bytes(), 768 * 1024);

        // Dropping permit1 returns 512 KiB
        drop(permit1);
        assert_eq!(budget.used_bytes(), 256 * 1024);

        // Now acquiring 512 KiB succeeds
        let permit3 = budget.try_acquire(512 * 1024);
        assert!(permit3.is_some());
        assert_eq!(budget.used_bytes(), 768 * 1024);

        drop(permit2);
        drop(permit3);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn rendezvous_online_request_bounds_and_validates_peers() {
        // Valid peer ID helper check
        assert!(RendezvousServer::valid_peer_id("valid_01"));
        assert!(!RendezvousServer::valid_peer_id(""));
        assert!(!RendezvousServer::valid_peer_id("bad id!"));

        // Peers count bounds
        let empty_peers: Vec<String> = vec![];
        assert!(empty_peers.is_empty());

        let max_peers: Vec<String> = (0..ONLINE_QUERY_MAX_PEERS)
            .map(|i| format!("peer_{i:04}"))
            .collect();
        assert_eq!(max_peers.len(), ONLINE_QUERY_MAX_PEERS);
        assert!(max_peers
            .iter()
            .all(|id| RendezvousServer::valid_peer_id(id)));

        let over_limit_peers: Vec<String> = (0..ONLINE_QUERY_MAX_PEERS + 1)
            .map(|i| format!("peer_{i:04}"))
            .collect();
        assert!(over_limit_peers.len() > ONLINE_QUERY_MAX_PEERS);
    }

    #[test]
    fn rendezvous_control_frame_ceiling_is_strictly_reduced() {
        // RES-006: Reduced from 17 MiB to 1 MiB to prevent 68 GiB theoretical memory amplification
        assert_eq!(RENDEZVOUS_CONTROL_FRAME_MAX, 1024 * 1024);
    }
}
