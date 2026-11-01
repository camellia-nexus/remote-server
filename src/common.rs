use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use camellia_remote_protocol::{
    anyhow::{Context, Result},
    crypto::sign,
    log, ResultType,
};
use clap::{Arg, Command};
use ini::Ini;
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Instant, SystemTime},
};

#[allow(dead_code)]
pub struct MemoryPermit {
    used: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::Release);
    }
}

#[allow(dead_code)]
pub struct MemoryBudget {
    used: Arc<AtomicUsize>,
    max_bytes: usize,
}

#[allow(dead_code)]
impl MemoryBudget {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            max_bytes,
        }
    }

    pub fn try_acquire(&self, bytes: usize) -> Option<MemoryPermit> {
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
    pub fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    #[inline]
    #[allow(dead_code)]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

pub fn parse_bind_address(value: &str) -> Result<Option<IpAddr>> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        value
            .parse()
            .with_context(|| format!("Invalid bind address: {value}"))
            .map(Some)
    }
}

pub async fn listen_tcp(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<camellia_remote_protocol::tokio::net::TcpListener> {
    if let Some(bind_addr) = bind_addr {
        camellia_remote_protocol::tcp::new_listener(SocketAddr::new(bind_addr, port), true).await
    } else {
        camellia_remote_protocol::tcp::listen_any(port).await
    }
}

pub fn console_addr(bind_addr: Option<IpAddr>, port: u16) -> Option<SocketAddr> {
    let bind_addr = bind_addr?;
    if bind_addr.is_unspecified() || bind_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

// The runtime console (check_cmd) is reached via 127.0.0.1, so when the bind
// address does not already accept connections to 127.0.0.1 (it is neither the
// any-address nor 127.0.0.1 itself), the console gets a dedicated listener
// there; it is never bound to the external bind address.
pub async fn listen_console(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<Option<camellia_remote_protocol::tokio::net::TcpListener>> {
    match console_addr(bind_addr, port) {
        Some(addr) => {
            let listener = camellia_remote_protocol::tcp::new_listener(addr, true).await?;
            log::info!("Listening on tcp {} for the console", addr);
            Ok(Some(listener))
        }
        None => Ok(None),
    }
}

pub async fn accept_or_pending(
    listener: Option<&camellia_remote_protocol::tokio::net::TcpListener>,
) -> std::io::Result<(camellia_remote_protocol::tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

#[allow(dead_code)]
pub(crate) fn get_expired_time() -> Instant {
    let now = Instant::now();
    now.checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(now)
}

#[allow(dead_code)]
pub(crate) fn get_servers(value: &str, name: &str) -> ResultType<Vec<String>> {
    const MAX_SERVER_LIST_BYTES: usize = 4 * 1024;
    const MAX_SERVER_COUNT: usize = 64;
    const MAX_SERVER_BYTES: usize = 512;

    if value.len() > MAX_SERVER_LIST_BYTES {
        camellia_remote_protocol::bail!("{name} is too large");
    }
    if value.trim().is_empty() {
        log::info!("{}=[]", name);
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut servers = Vec::new();
    for raw_server in value.split(',') {
        let server = raw_server.trim();
        if server.is_empty() {
            camellia_remote_protocol::bail!("{name} contains an empty server entry");
        }
        if server.len() > MAX_SERVER_BYTES || server.chars().any(char::is_control) {
            camellia_remote_protocol::bail!("{name} contains an invalid server");
        }
        let parsed = reqwest::Url::parse(&format!("tcp://{server}"))
            .with_context(|| format!("{name} contains an invalid server: {server}"))?;
        let host = parsed
            .host_str()
            .with_context(|| format!("{name} server has no host: {server}"))?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.port() == Some(0)
        {
            camellia_remote_protocol::bail!("{name} must contain only host or host:port values");
        }
        let canonical_host = host.trim_end_matches('.').to_ascii_lowercase();
        if canonical_host == "invalid" || canonical_host.ends_with(".invalid") {
            camellia_remote_protocol::bail!("{name} contains a placeholder .invalid host");
        }
        if seen.insert(server.to_owned()) {
            servers.push(server.to_owned());
            if servers.len() > MAX_SERVER_COUNT {
                camellia_remote_protocol::bail!("{name} contains too many servers");
            }
        }
    }
    log::info!("{}={:?}", name, servers);
    Ok(servers)
}

#[allow(dead_code)]
pub(crate) fn server_with_default_port(
    server: &str,
    name: &str,
    default_port: u16,
) -> ResultType<String> {
    let parsed = reqwest::Url::parse(&format!("tcp://{server}"))
        .with_context(|| format!("{name} contains an invalid server: {server}"))?;
    if parsed.port().is_some() {
        return Ok(server.to_owned());
    }
    let host = parsed
        .host_str()
        .with_context(|| format!("{name} server has no host: {server}"))?;
    Ok(format!("{host}:{default_port}"))
}

#[allow(dead_code)]
#[inline]
fn arg_name(name: &str) -> String {
    let normalized = name.trim().to_ascii_uppercase().replace('-', "_");
    if normalized.starts_with("CAMELLIA_REMOTE_") {
        normalized
    } else {
        format!("CAMELLIA_REMOTE_{normalized}")
    }
}

#[allow(dead_code)]
#[inline]
pub fn set_arg(name: &str, value: &str) {
    std::env::set_var(arg_name(name), value);
}

pub fn load_arg_file(path: &Path) -> ResultType<()> {
    const MAX_CONFIG_BYTES: usize = 1024 * 1024;
    let mut file = open_readonly_no_follow(path)
        .with_context(|| format!("Unable to open configuration file: {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = file
            .metadata()
            .with_context(|| format!("Unable to inspect configuration file: {}", path.display()))?;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            camellia_remote_protocol::bail!(
                "Configuration file must not be group- or world-writable: {} (mode: {:04o})",
                path.display(),
                mode & 0o7777
            );
        }
        let file_uid = metadata.uid();
        let current_euid = unsafe { libc::geteuid() };
        if file_uid != 0 && file_uid != current_euid {
            camellia_remote_protocol::bail!(
                "Configuration file must be owned by root or running UID: {} (file UID: {}, current UID: {})",
                path.display(),
                file_uid,
                current_euid
            );
        }
    }
    let contents = read_bounded_open_file(&mut file, path, MAX_CONFIG_BYTES, "Configuration file")?;
    let contents = std::str::from_utf8(&contents)
        .with_context(|| format!("Configuration file is not UTF-8: {}", path.display()))?;
    let values = Ini::load_from_str(contents)
        .with_context(|| format!("Unable to parse configuration file: {}", path.display()))?;
    if let Some(section) = values.section(None::<String>) {
        for (key, value) in section.iter() {
            if arg_name(key) != key {
                camellia_remote_protocol::bail!(
                    "Configuration keys must use the CAMELLIA_REMOTE_ prefix: {key}"
                );
            }
            if std::env::var_os(key).is_none() {
                std::env::set_var(key, value);
            }
        }
    }
    log::info!("Loaded configuration from {}", path.display());
    Ok(())
}

fn open_readonly_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn read_bounded_open_file(
    file: &mut File,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> ResultType<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("Unable to inspect {label}: {}", path.display()))?;
    if !metadata.is_file() {
        camellia_remote_protocol::bail!("{label} path is not a regular file: {}", path.display());
    }
    if metadata.len() > max_bytes as u64 {
        camellia_remote_protocol::bail!(
            "{label} exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("Unable to read {label}: {}", path.display()))?;
    if contents.len() > max_bytes {
        camellia_remote_protocol::bail!(
            "{label} exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    Ok(contents)
}

pub(crate) fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> ResultType<Vec<u8>> {
    let mut file = open_readonly_no_follow(path)
        .with_context(|| format!("Unable to open {label}: {}", path.display()))?;
    read_bounded_open_file(&mut file, path, max_bytes, label)
}

#[allow(dead_code)]
pub fn load_arg_file_if_present(path: &Path) -> ResultType<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_arg_file(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("Unable to inspect configuration file: {}", path.display())),
    }
}

#[allow(dead_code)]
pub fn init_args(args: Vec<Arg>, name: &str, about: &str) -> ResultType<()> {
    let matches = Command::new(name.to_owned())
        .version(crate::version::VERSION)
        .author("Camellia Computing")
        .about(about.to_owned())
        .args(args)
        .get_matches();
    if let Some(config) = matches.get_one::<String>("config") {
        load_arg_file(Path::new(config))?;
    } else if let Ok(config) = std::env::var("CAMELLIA_REMOTE_CONFIG_FILE") {
        if !config.trim().is_empty() {
            load_arg_file(Path::new(&config))?;
        }
    }
    for id in matches.ids() {
        if let Some(v) = matches.get_one::<String>(id.as_str()) {
            set_arg(id.as_str(), v);
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn get_arg_opt(name: &str) -> Option<String> {
    std::env::var(arg_name(name)).ok()
}

#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    get_arg_opt(name).unwrap_or(default)
}

pub fn parse_yes_no(name: &str, value: &str) -> ResultType<bool> {
    match value.trim().to_ascii_uppercase().as_str() {
        "Y" => Ok(true),
        "N" => Ok(false),
        _ => camellia_remote_protocol::bail!("{name} must be Y or N"),
    }
}

pub fn get_yes_no_arg(name: &str, default: bool) -> ResultType<bool> {
    match get_arg_opt(name).filter(|value| !value.trim().is_empty()) {
        Some(value) => parse_yes_no(name, &value),
        None => Ok(default),
    }
}

pub fn get_bounded_usize_arg(
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> ResultType<usize> {
    let value = match get_arg_opt(name).filter(|value| !value.trim().is_empty()) {
        Some(value) => value
            .parse::<usize>()
            .with_context(|| format!("{name} must be an integer"))?,
        None => default,
    };
    if !(minimum..=maximum).contains(&value) {
        camellia_remote_protocol::bail!("{name} must be between {minimum} and {maximum}");
    }
    Ok(value)
}

#[allow(dead_code)]
#[inline]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or_default()
}

pub fn gen_sk(wait: u64) -> ResultType<(String, sign::SecretKey)> {
    load_or_create_keypair(Path::new("id_ed25519"), wait)
}

pub(crate) fn parse_private_key(encoded: &str, label: &str) -> ResultType<sign::SecretKey> {
    const MAX_ENCODED_KEY_BYTES: usize = 128;
    let encoded = encoded.trim();
    if encoded.len() > MAX_ENCODED_KEY_BYTES {
        camellia_remote_protocol::bail!("{label} is too large");
    }
    let decoded = BASE64
        .decode(encoded)
        .with_context(|| format!("{label} must be a base64 Ed25519 private key"))?;
    if decoded.len() != sign::SECRETKEYBYTES {
        camellia_remote_protocol::bail!(
            "{label} must be a {}-byte Ed25519 private key",
            sign::SECRETKEYBYTES
        );
    }
    let seed = sign::Seed::from_slice(&decoded[..sign::SEEDBYTES])
        .with_context(|| format!("{label} has an invalid Ed25519 seed"))?;
    let (_, private_key) = sign::keypair_from_seed(&seed);
    if private_key.as_ref() != decoded {
        camellia_remote_protocol::bail!("{label} is not a structurally valid Ed25519 private key");
    }
    Ok(private_key)
}

fn load_or_create_keypair(secret_path: &Path, wait: u64) -> ResultType<(String, sign::SecretKey)> {
    if wait > 0 && !secret_path.exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }

    if read_secret_key(secret_path)?.is_none() {
        let secret_key = generate_compatible_secret_key();
        let encoded = BASE64.encode(secret_key.as_ref());
        create_secret_key_once(secret_path, encoded.as_bytes())?;
    }

    let secret_key = read_secret_key(secret_path)?
        .with_context(|| format!("Private key disappeared: {}", secret_path.display()))?;
    let public_key = BASE64.encode(&secret_key.as_ref()[sign::SECRETKEYBYTES / 2..]);
    let mut public_name = secret_path.as_os_str().to_os_string();
    public_name.push(".pub");
    let public_path = PathBuf::from(public_name);
    write_public_key(&public_path, public_key.as_bytes())?;
    log::info!("Private key loaded from {}", secret_path.display());
    Ok((public_key, secret_key))
}

fn read_secret_key(path: &Path) -> ResultType<Option<sign::SecretKey>> {
    const MAX_PRIVATE_KEY_FILE_BYTES: usize = 1024;
    let mut file = match open_readonly_no_follow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        camellia_remote_protocol::bail!(
            "Private key path must be a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            log::warn!("Restricted private key permissions to 0600");
        }
    }
    let encoded =
        read_bounded_open_file(&mut file, path, MAX_PRIVATE_KEY_FILE_BYTES, "Private key")?;
    let encoded = std::str::from_utf8(&encoded)
        .with_context(|| format!("Private key is not UTF-8: {}", path.display()))?;
    let private_key = parse_private_key(encoded, &format!("Private key {}", path.display()))?;
    Ok(Some(private_key))
}

fn generate_compatible_secret_key() -> sign::SecretKey {
    loop {
        let (public_key, secret_key) = sign::gen_keypair();
        let encoded = BASE64.encode(public_key);
        if !encoded.contains('/') && !encoded.contains(':') {
            return secret_key;
        }
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_secret_key_once(path: &Path, contents: &[u8]) -> ResultType<()> {
    let parent = parent_directory(path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Private key path has no valid file name")?;
    let temp_path = parent.join(format!(
        ".{file_name}.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let write_result = (|| -> ResultType<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        match fs::hard_link(&temp_path, path) {
            Ok(()) => sync_parent_directory(parent),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.into()),
        }
    })();
    let _ = fs::remove_file(&temp_path);
    write_result
}

fn write_public_key(path: &Path, contents: &[u8]) -> ResultType<()> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        camellia_remote_protocol::bail!(
            "Public key path must not be a symlink: {}",
            path.display()
        );
    }
    if read_bounded_regular_file(path, contents.len() + 1, "Public key")
        .is_ok_and(|existing| existing == contents)
    {
        return Ok(());
    }
    let parent = parent_directory(path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Public key path has no valid file name")?;
    let temp_path = parent.join(format!(
        ".{file_name}.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let write_result = (|| -> ResultType<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        for _ in 0..3 {
            match fs::hard_link(&temp_path, path) {
                Ok(()) => return sync_parent_directory(parent),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = match fs::symlink_metadata(path) {
                        Ok(metadata) => metadata,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(err.into()),
                    };
                    if metadata.file_type().is_symlink() {
                        camellia_remote_protocol::bail!(
                            "Public key path must not be a symlink: {}",
                            path.display()
                        );
                    }
                    if read_bounded_regular_file(path, contents.len() + 1, "Public key")
                        .is_ok_and(|existing| existing == contents)
                    {
                        return Ok(());
                    }
                    match fs::remove_file(path) {
                        Ok(()) => sync_parent_directory(parent)?,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        camellia_remote_protocol::bail!("Unable to publish public key: {}", path.display())
    })();
    let _ = fs::remove_file(&temp_path);
    write_result
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> ResultType<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> ResultType<()> {
    Ok(())
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use camellia_remote_protocol::tokio;
    use camellia_remote_protocol::tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = terminate => {
                log::info!("signal terminate");
            }
            _ = interrupt => {
                log::info!("signal interrupt");
            }
            _ = quit => {
                log::info!("signal quit");
            }
        }
        Ok(())
    })
    .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}
#[cfg(test)]
mod tests {
    use super::*;
    // The tokio::test macro expands to unqualified `tokio` paths.
    use camellia_remote_protocol::tokio;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        path::PathBuf,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "camellia-server-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn secret_path(&self) -> PathBuf {
            self.0.join("id_ed25519")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn argument_names_have_one_canonical_product_prefix() {
        std::env::remove_var("CAMELLIA_REMOTE_CONFIG_ALIAS_TEST");
        set_arg("config-alias-test", "normalized");
        assert_eq!(
            std::env::var("CAMELLIA_REMOTE_CONFIG_ALIAS_TEST").unwrap(),
            "normalized"
        );
        assert_eq!(get_arg("CAMELLIA_REMOTE_CONFIG_ALIAS_TEST"), "normalized");
        std::env::set_var("CONFIG_ALIAS_TEST", "ignored");
        assert_eq!(get_arg("config_alias_test"), "normalized");
        std::env::remove_var("CONFIG_ALIAS_TEST");
        std::env::remove_var("CAMELLIA_REMOTE_CONFIG_ALIAS_TEST");
    }

    #[test]
    fn parses_bind_address() {
        assert_eq!(parse_bind_address("").unwrap(), None);
        assert_eq!(
            parse_bind_address("127.0.0.1").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_bind_address("::1").unwrap(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(parse_bind_address("not-an-ip").is_err());
    }

    #[test]
    fn server_lists_are_syntax_checked_without_dns() {
        let servers = get_servers(
            "relay.example.com:21117, 192.0.2.10, [2001:db8::1]:21117",
            "relay-servers",
        )
        .unwrap();
        assert_eq!(
            servers,
            [
                "relay.example.com:21117",
                "192.0.2.10",
                "[2001:db8::1]:21117"
            ]
        );

        for invalid in [
            "https://relay.example.com",
            "user@relay.example.com",
            "relay.example.com/path",
            "relay.example.com:0",
            "relay.example.com:not-a-port",
            "relay.example.invalid:21117",
            "relay.example.com,",
            "relay.example.com,,192.0.2.10",
        ] {
            assert!(get_servers(invalid, "relay-servers").is_err(), "{invalid}");
        }
        assert!(get_servers("", "relay-servers").unwrap().is_empty());
    }

    #[test]
    fn default_server_ports_preserve_ipv6_brackets() {
        assert_eq!(
            server_with_default_port("relay.example.com", "relay-servers", 21117).unwrap(),
            "relay.example.com:21117"
        );
        assert_eq!(
            server_with_default_port("[2001:db8::1]", "relay-servers", 21117).unwrap(),
            "[2001:db8::1]:21117"
        );
        assert_eq!(
            server_with_default_port("[2001:db8::1]:22117", "relay-servers", 21117).unwrap(),
            "[2001:db8::1]:22117"
        );
    }

    #[test]
    fn private_keys_must_be_structurally_valid() {
        let (_, private_key) = sign::gen_keypair();
        let encoded = BASE64.encode(private_key.as_ref());
        assert_eq!(
            parse_private_key(&encoded, "Test key").unwrap().as_ref(),
            private_key.as_ref()
        );

        let mut inconsistent = private_key.as_ref().to_vec();
        inconsistent[sign::SECRETKEYBYTES - 1] ^= 1;
        assert!(parse_private_key(&BASE64.encode(inconsistent), "Test key").is_err());
        assert!(parse_private_key("not-base64", "Test key").is_err());
    }

    #[test]
    fn relative_key_paths_sync_the_working_directory() {
        assert_eq!(parent_directory(Path::new("id_ed25519")), Path::new("."));
        assert_eq!(
            parent_directory(Path::new("keys/id_ed25519")),
            Path::new("keys")
        );
    }

    #[test]
    fn yes_no_values_are_strict() {
        assert!(parse_yes_no("FEATURE", "y").unwrap());
        assert!(!parse_yes_no("FEATURE", "N").unwrap());
        for invalid in ["", "yes", "true", "1"] {
            assert!(parse_yes_no("FEATURE", invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn configuration_files_fail_closed() {
        let directory = TestDirectory::new("configuration");
        let valid = directory.0.join("valid.env");
        fs::write(&valid, "CAMELLIA_REMOTE_CONFIG_FILE_TEST=loaded\n").unwrap();
        load_arg_file(&valid).unwrap();
        assert_eq!(get_arg("CAMELLIA_REMOTE_CONFIG_FILE_TEST"), "loaded");
        std::env::remove_var("CAMELLIA_REMOTE_CONFIG_FILE_TEST");

        // Precedence: explicit config file only fills missing environment variables
        std::env::set_var("CAMELLIA_REMOTE_CONFIG_FILE_TEST", "env_priority");
        load_arg_file(&valid).unwrap();
        assert_eq!(get_arg("CAMELLIA_REMOTE_CONFIG_FILE_TEST"), "env_priority");
        std::env::remove_var("CAMELLIA_REMOTE_CONFIG_FILE_TEST");

        let unprefixed = directory.0.join("unprefixed.env");
        fs::write(&unprefixed, "KEY=value\n").unwrap();
        assert!(load_arg_file(&unprefixed).is_err());

        let malformed = directory.0.join("malformed.env");
        fs::write(&malformed, "[unterminated\n").unwrap();
        assert!(load_arg_file(&malformed).is_err());

        let oversized = directory.0.join("oversized.env");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        assert!(load_arg_file(&oversized).is_err());
        assert!(load_arg_file(&directory.0).is_err());
        assert!(load_arg_file_if_present(&directory.0.join("missing")).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let linked = directory.0.join("linked.env");
            symlink(&valid, &linked).unwrap();
            assert!(load_arg_file(&linked).is_err());

            let group_writable = directory.0.join("group_writable.env");
            fs::write(
                &group_writable,
                "CAMELLIA_REMOTE_CONFIG_FILE_TEST=insecure\n",
            )
            .unwrap();
            fs::set_permissions(&group_writable, fs::Permissions::from_mode(0o664)).unwrap();
            assert!(load_arg_file(&group_writable).is_err());

            let world_writable = directory.0.join("world_writable.env");
            fs::write(
                &world_writable,
                "CAMELLIA_REMOTE_CONFIG_FILE_TEST=insecure\n",
            )
            .unwrap();
            fs::set_permissions(&world_writable, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(load_arg_file(&world_writable).is_err());
        }
    }

    #[test]
    fn memory_budget_enforces_limit_and_raii_return() {
        let budget = MemoryBudget::new(1024);
        assert_eq!(budget.max_bytes(), 1024);
        assert_eq!(budget.used_bytes(), 0);

        let permit1 = budget.try_acquire(600).expect("acquire 600 bytes");
        assert_eq!(budget.used_bytes(), 600);

        assert!(budget.try_acquire(500).is_none());
        assert_eq!(budget.used_bytes(), 600);

        let permit2 = budget.try_acquire(424).expect("acquire 424 bytes");
        assert_eq!(budget.used_bytes(), 1024);
        assert!(budget.try_acquire(1).is_none());

        drop(permit1);
        assert_eq!(budget.used_bytes(), 424);

        let permit3 = budget.try_acquire(500).expect("acquire 500 bytes");
        assert_eq!(budget.used_bytes(), 924);

        drop(permit2);
        drop(permit3);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[camellia_remote_protocol::tokio::test]
    async fn tcp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = listen_tcp(Some(bind_addr), 0).await.unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), bind_addr);
    }

    #[test]
    fn console_addr_only_when_bind_does_not_cover_ipv4_localhost() {
        for bind_addr in [
            None,
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ] {
            assert_eq!(console_addr(bind_addr, 21117), None);
        }
        for bind_addr in [
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some("2001:db8::1".parse().unwrap()),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            assert_eq!(
                console_addr(bind_addr, 21117),
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21117))
            );
        }
    }

    #[camellia_remote_protocol::tokio::test]
    async fn console_listener_binds_ipv4_localhost() {
        let listener = listen_console(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert!(listen_console(None, 0).await.unwrap().is_none());
        assert!(listen_console(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn keypair_creation_is_atomic_across_threads() {
        let directory = TestDirectory::new("key-race");
        let secret_path = directory.secret_path();
        let handles = (0..8)
            .map(|_| {
                let secret_path = secret_path.clone();
                std::thread::spawn(move || load_or_create_keypair(&secret_path, 0).unwrap().0)
            })
            .collect::<Vec<_>>();
        let public_keys = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert!(public_keys
            .iter()
            .all(|public_key| public_key == &public_keys[0]));
        assert_eq!(
            fs::read_to_string(secret_path.with_file_name("id_ed25519.pub")).unwrap(),
            public_keys[0]
        );
        assert_eq!(
            load_or_create_keypair(&secret_path, 0).unwrap().0,
            public_keys[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDirectory::new("key-mode");
        let secret_path = directory.secret_path();
        let (_public_key, _secret_key) = load_or_create_keypair(&secret_path, 0).unwrap();
        assert_eq!(
            fs::metadata(secret_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn malformed_private_key_fails_closed() {
        let directory = TestDirectory::new("bad-key");
        let secret_path = directory.secret_path();
        fs::write(&secret_path, "not-a-private-key").unwrap();

        assert!(load_or_create_keypair(&secret_path, 0).is_err());
    }

    #[test]
    fn stale_public_key_is_replaced() {
        let directory = TestDirectory::new("stale-public-key");
        let secret_path = directory.secret_path();
        let (public_key, _secret_key) = load_or_create_keypair(&secret_path, 0).unwrap();
        let public_path = secret_path.with_file_name("id_ed25519.pub");
        fs::write(&public_path, "stale-public-key").unwrap();

        assert_eq!(
            load_or_create_keypair(&secret_path, 0).unwrap().0,
            public_key
        );
        assert_eq!(fs::read_to_string(public_path).unwrap(), public_key);
    }

    #[cfg(unix)]
    #[test]
    fn key_paths_reject_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("key-symlinks");
        let victim = directory.0.join("victim");
        fs::write(&victim, "unchanged").unwrap();

        let secret_path = directory.secret_path();
        symlink(&victim, &secret_path).unwrap();
        assert!(load_or_create_keypair(&secret_path, 0).is_err());
        fs::remove_file(&secret_path).unwrap();

        let (_public_key, _secret_key) = load_or_create_keypair(&secret_path, 0).unwrap();
        let public_path = secret_path.with_file_name("id_ed25519.pub");
        fs::remove_file(&public_path).unwrap();
        symlink(&victim, &public_path).unwrap();
        assert!(load_or_create_keypair(&secret_path, 0).is_err());
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
    }
}
