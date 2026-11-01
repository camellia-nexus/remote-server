use clap::{Arg, Command};
mod common;
mod relay_server;
use camellia_remote_protocol::{config::RELAY_PORT, ResultType};
use flexi_logger::*;
use relay_server::*;
use std::path::Path;
mod version {
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
}

fn main() -> ResultType<()> {
    let log_filter =
        std::env::var("CAMELLIA_REMOTE_LOG_FILTER").unwrap_or_else(|_| "info".to_owned());
    let _logger = Logger::try_with_str(&log_filter)?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let matches = Command::new("camellia-remote-relay")
        .version(version::VERSION)
        .author("Camellia Computing")
        .about("Camellia Remote relay server")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file"),
        )
        .arg(
            Arg::new("bind")
                .short('b')
                .long("bind")
                .value_name("IP")
                .help("Sets the IP address to bind to (default: all interfaces)"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name(format!("NUMBER(default={RELAY_PORT})"))
                .help("Sets the listening port"),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .value_name("KEY")
                .help("Only allow the client with the same key"),
        )
        .arg(
            Arg::new("trust-proxy-headers")
                .long("trust-proxy-headers")
                .value_name("Y/N")
                .help("Trust client address headers only from configured proxy CIDRs"),
        )
        .arg(
            Arg::new("trusted-proxy-cidrs")
                .long("trusted-proxy-cidrs")
                .value_name("CIDR,...")
                .help("Trusted reverse proxy IPv4/IPv6 CIDRs for websocket listeners"),
        )
        .arg(
            Arg::new("console-token")
                .long("console-token")
                .value_name("TOKEN")
                .help("Authentication token for loopback runtime console"),
        )
        .arg(
            Arg::new("console-token-file")
                .long("console-token-file")
                .value_name("FILE")
                .help("Path to secure file containing console authentication token"),
        )
        .get_matches();
    if let Some(config) = matches.get_one::<String>("config") {
        common::load_arg_file(Path::new(config))?;
    } else if let Ok(config) = std::env::var("CAMELLIA_REMOTE_CONFIG_FILE") {
        if !config.trim().is_empty() {
            common::load_arg_file(Path::new(&config))?;
        }
    }
    let default_port = common::get_arg_or("CAMELLIA_REMOTE_RELAY_PORT", RELAY_PORT.to_string());
    let bind = matches
        .get_one::<String>("bind")
        .map(String::to_owned)
        .unwrap_or_else(|| common::get_arg("BIND"));
    let bind_addr = common::parse_bind_address(&bind)?;
    let key = matches
        .get_one::<String>("key")
        .map(String::to_owned)
        .unwrap_or_else(|| common::get_arg("KEY"));
    let trust_proxy_headers = match matches.get_one::<String>("trust-proxy-headers") {
        Some(value) => common::parse_yes_no("trust-proxy-headers", value)?,
        None => common::get_yes_no_arg("TRUST_PROXY_HEADERS", false)?,
    };
    let trusted_proxy_cidrs = matches
        .get_one::<String>("trusted-proxy-cidrs")
        .map(String::to_owned)
        .unwrap_or_else(|| common::get_arg("TRUSTED_PROXY_CIDRS"));
    let trusted_proxies =
        common::TrustedProxyConfig::parse(trust_proxy_headers, &trusted_proxy_cidrs)?;
    if let Some(token) = matches.get_one::<String>("console-token") {
        common::set_arg("console-token", token);
    }
    if let Some(token_file) = matches.get_one::<String>("console-token-file") {
        common::set_arg("console-token-file", token_file);
    }
    start_with_bind(
        bind_addr,
        matches
            .get_one::<String>("port")
            .map(String::as_str)
            .unwrap_or(&default_port),
        &key,
        trusted_proxies,
    )?;
    Ok(())
}
