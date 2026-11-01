// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use camellia_remote_protocol::{bail, config::RENDEZVOUS_PORT, ResultType};
use camellia_remote_server::{common::*, *};
use clap::Arg;
use flexi_logger::*;

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let log_filter =
        std::env::var("CAMELLIA_REMOTE_LOG_FILTER").unwrap_or_else(|_| "info".to_owned());
    let _logger = Logger::try_with_str(&log_filter)?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = vec![
        Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file"),
        Arg::new("bind")
            .short('b')
            .long("bind")
            .value_name("IP")
            .help("Sets the IP address to bind to (default: all interfaces)"),
        Arg::new("port")
            .short('p')
            .long("port")
            .value_name(format!("NUMBER(default={RENDEZVOUS_PORT})"))
            .help("Sets the listening port"),
        Arg::new("relay-servers")
            .short('r')
            .long("relay-servers")
            .value_name("HOST")
            .help("Sets the default relay servers, separated by comma"),
        Arg::new("api-server")
            .long("api-server")
            .value_name("URL")
            .help("Sets the API server used by the built-in TCP API proxy"),
        Arg::new("trust-proxy-headers")
            .long("trust-proxy-headers")
            .value_name("Y/N")
            .help("Trust client address headers only from configured proxy CIDRs"),
        Arg::new("trusted-proxy-cidrs")
            .long("trusted-proxy-cidrs")
            .value_name("CIDR,...")
            .help("Trusted reverse proxy IPv4/IPv6 CIDRs for websocket listeners"),
        Arg::new("console-token")
            .long("console-token")
            .value_name("TOKEN")
            .help("Authentication token for loopback runtime console"),
        Arg::new("console-token-file")
            .long("console-token-file")
            .value_name("FILE")
            .help("Path to secure file containing console authentication token"),
        Arg::new("rmem")
            .short('M')
            .long("rmem")
            .value_name(format!("NUMBER(default={RMEM})"))
            .help("Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p"),
        Arg::new("key")
            .short('k')
            .long("key")
            .value_name("KEY")
            .help("Only allow the client with the same key"),
    ];
    init_args(
        args,
        "camellia-remote-identity",
        "Camellia Remote identity and rendezvous server",
    )?;
    let port = get_arg_opt("PORT")
        .or_else(|| get_arg_opt("CAMELLIA_REMOTE_IDENTITY_PORT"))
        .unwrap_or_else(|| RENDEZVOUS_PORT.to_string())
        .parse::<i32>()?;
    if !(3..=65_533).contains(&port) {
        bail!("Port must be between 3 and 65533");
    }
    let bind_addr = parse_bind_address(&get_arg("bind"))?;
    let rmem = get_arg_opt("rmem")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(RMEM);
    RendezvousServer::start_with_bind(
        bind_addr,
        port,
        0,
        &get_arg_or("key", "-".to_owned()),
        rmem,
    )?;
    Ok(())
}
