//! monitor-agent: reports one host to a monitor hub over WebSocket.

mod collect;
mod logging;
mod secure_fs;

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    path::PathBuf,
    time::Duration,
};

// Shares the clock `tokio::time::timeout` and `sleep` read, so deadline
// arithmetic cannot drift from the timers enforcing it, and tests can advance
// it. Outside a paused runtime this is the monotonic clock.
use tokio::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use collect::{Ifaces, WorkerCollector};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

struct Args {
    server: String,
    token: zeroize::Zeroizing<String>,
    /// Locally authorized private/sensitive TCP probe destinations.
    probe_allow: String,
    interval: u64,
    /// Adapter aliases selected by `--iface`; empty uses the default filter.
    ifaces: Ifaces,
    service_name: String,
    /// Permits plain HTTP to a hub reached at ip:port with no TLS in front.
    /// Off by default: the token would otherwise travel in the clear.
    insecure: bool,
    config_path: PathBuf,
}

const DEFAULT_SERVICE_NAME: &str = "monitor-agent";
const SERVICE_DISPLAY_NAME: &str = "Monitor Agent";
const SERVICE_DESCRIPTION: &str = "Reports Windows host metrics to a monitor hub.";
const CONFIG_DIR_NAME: &str = "monitor-agent";
const CONFIG_FILE_NAME: &str = "agent.env";
const LOG_FILE_NAME: &str = "agent.log";

/// Printed on `--help` and on any argument error. A raw literal rather than
/// line continuations: `\`-continuations strip the leading whitespace of the
/// next source line, which silently flattened every description's second line.
const USAGE: &str = r#"Usage: monitor-agent [command] [options]

Commands:
  install              Write config, install and start the Windows service
  uninstall            Stop and remove the Windows service
  start                Start the Windows service
  stop                 Stop the Windows service
  status               Show the Windows service status
  service              Internal service entry point

Options:
  --server <url>       Hub base URL, e.g. https://hub.example.com
  --token <token>      Node token from the hub panel
  --config <path>      Config file (default: per-service ProgramData path)
  --service-name <name> Service name (default: monitor-agent)
  --probe-allow <list> Locally authorized probe destination CIDRs (default public only)
  --interval <secs>    Report interval (default 1)
  --iface <list>       Select adapter aliases; -name excludes from defaults
                       (e.g. Ethernet,-vEthernet (WSL))
  --nics <list>        Legacy alias: count only these adapter aliases
  --insecure           Allow plain ws:// to a remote hub; the token travels
                       in the clear. Only for a hub reached at ip:port with
                       no TLS in front."#;

fn usage() -> ! {
    eprintln!("monitor-agent {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
    std::process::exit(2)
}

fn parse_args() -> Result<Args> {
    parse_options(std::env::args().skip(1))
}

fn parse_options<I>(args: I) -> Result<Args>
where
    I: IntoIterator<Item = String>,
{
    let (mut server, mut token, mut interval, mut iface, mut insecure) = (None, None, None, None, None);
    let mut probe_allow = None;
    let mut config_path = None;
    let mut explicit_config = false;
    let mut service_name = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyhow!("missing value for {arg}"));
        match arg.as_str() {
            "--server" => server = Some(value()?),
            "--token" => token = Some(value()?),
            "--probe-allow" => probe_allow = Some(value()?),
            "--config" => {
                config_path = Some(PathBuf::from(value()?));
                explicit_config = true;
            }
            "--service-name" => service_name = Some(value()?),
            "--interval" => {
                interval = Some(value()?.parse().context("--interval must be an integer")?);
            }
            "--iface" => iface = Some((value()?, false)),
            "-nics" | "--nics" => iface = Some((value()?, true)),
            "--insecure" => insecure = Some(true),
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {other}"),
        }
    }
    let service_name = service_name
        .or_else(|| std::env::var("MONITOR_SERVICE_NAME").ok())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());
    validate_service_name(&service_name)?;
    let config_path = absolute_path(&config_path.unwrap_or_else(|| default_config_path(&service_name)))?;
    let config = match read_config(&config_path) {
        Ok(config) => config,
        Err(error) if !explicit_config && secure_fs::is_missing(&error) => HashMap::new(),
        Err(error) => return Err(error),
    };
    let config_value = |name: &str| config.get(name).map(|value| value.as_str());

    let server = server
        .or_else(|| config_value("MONITOR_SERVER").map(str::to_owned))
        .or_else(|| std::env::var("MONITOR_SERVER").ok())
        .ok_or_else(|| anyhow!("missing --server or MONITOR_SERVER"))?;
    let token = zeroize::Zeroizing::new(
        token
            .or_else(|| config_value("MONITOR_TOKEN").map(str::to_owned))
            .or_else(|| std::env::var("MONITOR_TOKEN").ok())
            .ok_or_else(|| anyhow!("missing --token or MONITOR_TOKEN"))?,
    );
    let interval = interval
        .or_else(|| config_value("MONITOR_INTERVAL").and_then(|v| v.parse().ok()))
        .or_else(|| std::env::var("MONITOR_INTERVAL").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(1);
    let iface_setting = iface
        .or_else(|| config_value("MONITOR_IFACE").map(|value| (value.to_owned(), false)))
        .or_else(|| config_value("MONITOR_NICS").map(|value| (value.to_owned(), true)))
        .or_else(|| std::env::var("MONITOR_IFACE").ok().map(|value| (value, false)))
        .or_else(|| std::env::var("MONITOR_NICS").ok().map(|value| (value, true)));
    let ifaces = match iface_setting {
        Some((value, true)) => {
            if value.len() > 4096 || value.chars().any(char::is_control) {
                bail!("legacy interface list is too long or contains control characters");
            }
            Ifaces::from_legacy(parse_nics(&value))
        }
        Some((value, false)) => Ifaces::parse(&value).map_err(anyhow::Error::msg)?,
        None => Ifaces::default(),
    };
    let insecure = match insecure {
        Some(value) => value,
        None => match config_value("MONITOR_INSECURE") {
            Some(value) => parse_bool(value)?,
            None => match std::env::var("MONITOR_INSECURE") {
                Ok(value) => parse_bool(&value)?,
                Err(_) => false,
            },
        },
    };
    if server.len() > 4096 || token.len() > 4096 || ifaces.spec().len() > 4096 {
        bail!("server, token and interface settings must not exceed 4096 bytes");
    }
    let probe_allow = probe_allow
        .or_else(|| config_value("MONITOR_PROBE_ALLOW").map(str::to_owned))
        .or_else(|| std::env::var("MONITOR_PROBE_ALLOW").ok())
        .unwrap_or_default();
    if probe_allow.len() > 4096 || probe_allow.chars().any(char::is_control) {
        bail!("probe allowlist is too long or contains control characters");
    }
    // Reject unusable settings before install mutates configuration or stops services.
    let url = ws_url(&server, insecure)?;
    authorized(&url, token.as_str())?;
    probe::Policy::parse(&probe_allow)?;
    Ok(Args {
        server,
        token,
        probe_allow,
        interval: interval.clamp(1, 3600),
        ifaces,
        service_name,
        insecure,
        config_path,
    })
}

#[path = "install.rs"]
mod install;
use install::*;

fn log_line(line: &str) {
    logging::log_line(line);
}

macro_rules! agent_log {
    ($($arg:tt)*) => {{
        log_line(&format!($($arg)*));
    }};
}

fn run_foreground(args: Args) -> Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(run_agent(args, shutdown_rx));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

fn run_service(arguments: Vec<OsString>) -> Result<()> {
    let mut raw: Vec<String> = arguments.into_iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
    // SCM may include the registered service name as argv[0] for ServiceMain.
    if raw.first().is_some_and(|arg| arg != "service" && !arg.starts_with('-')) {
        raw.remove(0);
    }
    let service_name = parse_service_name(raw.iter().cloned())?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            let _ = shutdown_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(&service_name, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 1,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })?;

    let options = raw.into_iter().filter(|arg| arg != "service");
    let args = match parse_options(options) {
        Ok(args) => args,
        Err(error) => {
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::ZERO,
                process_id: None,
            });
            return Err(error);
        }
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: Some(std::process::id()),
    })?;
    let result = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let result = runtime.block_on(run_agent(args, shutdown_rx));
            runtime.shutdown_timeout(Duration::from_secs(1));
            result
        }
        Err(error) => Err(error.into()),
    };
    let exit_code = if result.is_ok() { ServiceExitCode::NO_ERROR } else { ServiceExitCode::Win32(1) };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });
    result
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<OsString>) {
    if let Err(error) = run_service(arguments) {
        agent_log!("service failed: {error:#}");
    }
}

fn start_service_dispatcher(service_name: &str) -> Result<()> {
    service_dispatcher::start(service_name, ffi_service_main).context("start service dispatcher")
}

/// `--nics Ethernet,Wi-Fi` -> `["Ethernet", "Wi-Fi"]`. Whitespace around
/// each list entry is trimmed while internal spaces in adapter aliases remain.
///
/// Duplicates are kept: they cost nothing, because each operating-system
/// interface row is summed once rather than once per list entry.
fn parse_nics(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).collect()
}

/// `https://host/path` -> `wss://host/path/api/agent/ws`. The token travels in
/// an Authorization header rather than the query string, keeping it out of
/// reverse-proxy access logs.
///
/// `insecure` declares that the hub has no TLS. It permits plain ws:// to a
/// remote hub and suppresses the bare-host upgrade to TLS; without the latter
/// the flag would dial a port that cannot complete a TLS handshake.
fn ws_url(server: &str, insecure: bool) -> Result<String> {
    let base = server.trim_end_matches('/');
    let scheme = if insecure { "ws" } else { "wss" };
    // Schemes are case-insensitive (RFC 3986); normalize only the scheme so
    // the original host and path remain unchanged.
    let (given, rest) = base.split_once("://").unwrap_or(("", base));
    let base = match given.to_ascii_lowercase().as_str() {
        "https" => format!("wss://{rest}"),
        "http" => format!("ws://{rest}"),
        ws @ ("wss" | "ws") => format!("{ws}://{rest}"),
        _ => format!("{scheme}://{base}"),
    };
    // RFC 3986 places userinfo before the host, so `127.0.0.1:28080@evil.example.com`
    // reads as loopback to any check that splits at the first colon while the
    // connection goes to the name following it -- bypassing both the refusal below
    // and `--insecure`. A hub address never needs userinfo, so it is rejected.
    let authority = base.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    if authority.contains('@') {
        bail!("server URL must not contain '@': the host is whatever follows it, not what precedes it");
    }
    if base.starts_with("ws://") && !insecure && !is_loopback(&base) {
        bail!(
            "refusing plaintext ws:// to a remote hub; the token would travel in the clear. \
             Pass --insecure if that hub really has no TLS"
        );
    }
    Ok(format!("{base}/api/agent/ws"))
}

/// Parses the host rather than prefix-matching it: `127.attacker.example`
/// begins with the loopback net but resolves elsewhere. IPv6 literals are
/// bracketed, so the port is not split off at the first colon. Anything that is
/// not a literal loopback address falls to the plaintext refusal, including
/// `::ffff:127.0.0.1`.
///
/// `ws_url` has already rejected an authority containing `@`, so the first
/// colon here is the port separator.
fn is_loopback(url: &str) -> bool {
    let authority = url.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    host.parse::<std::net::IpAddr>().map_or(host == "localhost", |ip| ip.is_loopback())
}

#[derive(Deserialize)]
struct Rpc {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Deserialize, Clone, Debug)]
struct PingTask {
    id: i64,
    target: String,
    interval: u64,
}

fn notify(method: &str, params: serde_json::Value) -> Message {
    Message::Text(
        serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string().into(),
    )
}

/// Writes under a deadline drawn from the remaining silence budget.
///
/// Reads and writes share one `select!` loop, so a socket that never drains
/// also stalls the watchdog; the kernel abandons such a socket only after
/// tcp_retries2, roughly fifteen minutes.
///
/// Charging the write against the remaining budget rather than a fresh
/// [`HUB_SILENCE`] bounds a stall at the end of a quiet stretch: two full
/// budgets would exceed the 120s after which the hub drops the node. An
/// exhausted budget fails the write and ends the session, as the watchdog
/// would have.
///
/// A timed-out write leaves a partial frame in the stream; every caller ends
/// the session on the error, discarding it with the socket.
async fn send(
    ws: &mut (impl Sink<Message, Error = WsError> + Unpin),
    m: Message,
    budget: Duration,
) -> Result<()> {
    tokio::time::timeout(budget, ws.send(m))
        .await
        .map_err(|_| anyhow!("write stalled for {}s", budget.as_secs()))?
        .context("write")
}

async fn send_or_stop(
    ws: &mut (impl Sink<Message, Error = WsError> + Unpin),
    message: Message,
    budget: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Option<Result<()>> {
    tokio::select! {
        result = send(ws, message, budget) => Some(result),
        _ = shutdown.changed() => None,
    }
}

/// Remaining silence budget, measured from the last sign of life.
///
/// Every write draws from this single window, so no sequence of writes can
/// push the give-up point beyond one [`HUB_SILENCE`] past the last frame.
fn remaining(last_frame: Instant) -> Duration {
    HUB_SILENCE.saturating_sub(last_frame.elapsed())
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1);
    let result = match command.as_deref() {
        Some("install") => install_service(parse_options(std::env::args().skip(2))?),
        Some("uninstall") => uninstall_service(&parse_service_name(std::env::args().skip(2))?),
        Some("start") => start_service(&parse_service_name(std::env::args().skip(2))?),
        Some("stop") => stop_service(&parse_service_name(std::env::args().skip(2))?),
        Some("status") => status_service(&parse_service_name(std::env::args().skip(2))?),
        Some("service") => start_service_dispatcher(&parse_service_name(std::env::args().skip(2))?),
        _ => run_foreground(parse_args()?),
    };
    if let Err(error) = &result {
        agent_log!("command failed: {error:#}");
    }
    result
}

#[path = "network.rs"]
mod network;
#[path = "probe.rs"]
mod probe;
#[path = "resolver.rs"]
mod resolver;

async fn run_agent(args: Args, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let url = ws_url(&args.server, args.insecure)?;
    let network = network::Network::shared()?;
    let policy = std::sync::Arc::new(probe::Policy::parse(&args.probe_allow)?);
    let loopback_only = !args.insecure && url.starts_with("ws://");
    let mut collector = WorkerCollector::start(args.ifaces.clone())?;
    let mut wait = 0u64;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let mut connected = None;
        let result = session(
            &url,
            &args.token,
            &mut collector,
            args.interval,
            &mut connected,
            &mut shutdown,
            &network,
            &policy,
            loopback_only,
        )
        .await;
        if *shutdown.borrow() {
            return Ok(());
        }
        if let Err(error) = result {
            agent_log!("session ended: {error:#}");
        }
        wait = reconnect_wait(wait, connected.map_or(Duration::ZERO, |t: Instant| t.elapsed()));
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
            _ = shutdown.changed() => return Ok(()),
        }
    }
}

/// Backoff before the next connection attempt, derived from the previous wait
/// and the duration of the session that just ended -- measured from the
/// handshake, so a peer that swallows a connect for the whole
/// [`CONNECT_DEADLINE`] earns no credit.
///
/// A session that reported for a while proves the hub reachable and the token
/// valid, so the wait resets to one second. Only short-lived sessions keep
/// doubling, which keeps an agent off a hub in a crash loop.
fn reconnect_wait(previous: u64, lasted: Duration) -> u64 {
    if lasted >= Duration::from_secs(30) {
        1
    } else {
        (previous * 2).clamp(1, 60)
    }
}

/// Deadline covering all three stages of establishing a connection.
///
/// Only the TCP handshake has a deadline of its own; the TLS exchange and the
/// HTTP upgrade have none, so a peer that accepts and then goes silent would
/// leave `connect_async` pending indefinitely, and the agent running without
/// reporting or logging.
///
/// Deliberately generous: a healthy connect takes a quarter of a second, the
/// slowest measured sixty. This is not a latency budget but the point past
/// which nothing is expected to arrive.
const CONNECT_DEADLINE: Duration = Duration::from_secs(120);
/// Bound a failed address so a black-holed IPv6 route yields to the next address.
const DIAL_FALLBACK: Duration = Duration::from_secs(5);

/// The hub sends one kind of message, a probe list a few hundred bytes long.
/// Tungstenite's 64 MiB default would hand the peer this process's entire
/// memory budget.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long the agent waits for any frame from the hub before giving up.
///
/// The hub pings every 30 seconds and drops an agent silent for 120. Without a
/// matching watchdog, a one-way path failure -- an expired NAT entry, a route
/// gone dark -- leaves the agent writing into a socket the kernel retransmits
/// on for fifteen minutes, long after the panel has marked the node offline.
///
/// Staying under the hub's own timeout makes the agent give up first, bounding
/// recovery at this constant rather than at tcp_retries2.
const HUB_SILENCE: Duration = Duration::from_secs(90);

/// How often a session recollects Facts and sends another hello when they change.
const FACTS_RECHECK: Duration = Duration::from_secs(60);

/// Initial host identity must be real before selecting an address family or
/// sending hello. A stuck collector costs one short attempt, then reconnect
/// backoff, rather than registering an empty/default host with the hub.
const INITIAL_FACTS_DEADLINE: Duration = Duration::from_millis(250);

async fn wait_initial_facts<F, Fut>(
    mut poll: F,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<collect::Facts>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<collect::Facts>>>,
{
    if *shutdown.borrow() {
        return Ok(None);
    }
    let ready = async {
        loop {
            if let Some(facts) = poll().await? {
                return Ok(Some(facts));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        biased;
        _ = shutdown.changed() => Ok(None),
        result = tokio::time::timeout(INITIAL_FACTS_DEADLINE, ready) =>
            result.map_err(|_| anyhow!("initial Facts unavailable within 250ms"))?,
    }
}

/// One connection: handshake, then report until the socket closes.
#[allow(clippy::too_many_arguments)]
async fn session(
    url: &str,
    token: &str,
    collector: &mut WorkerCollector,
    interval: u64,
    connected: &mut Option<Instant>,
    shutdown: &mut watch::Receiver<bool>,
    network: &std::sync::Arc<network::Network>,
    policy: &std::sync::Arc<probe::Policy>,
    loopback_only: bool,
) -> Result<()> {
    let request = authorized(url, token)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
        .write_buffer_size(8 * 1024)
        .max_write_buffer_size(128 * 1024);
    let uri = request.uri();
    let host = uri
        .host()
        .context("server URL has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
    // Polling only needs shared access; do not let the repeated async closure
    // capture/reborrow the session's mutable reference across calls.
    let collector: &WorkerCollector = collector;
    let Some(mut facts) = wait_initial_facts(
        || async {
            // Read readiness BEFORE taking the snapshot: a background completion
            // must not retroactively validate a default snapshot already returned.
            let ready = collector.has_facts();
            let facts = collector.facts().await?;
            Ok(ready.then_some(facts))
        },
        shutdown,
    )
    .await?
    else {
        return Ok(());
    };
    let connect = async {
        let stream = dial(network, &host, port, prefers_ipv4(&facts.ipv4), loopback_only).await?;
        let peer = stream.stream.peer_addr()?;
        ensure_loopback_peer(peer, loopback_only)?;
        let (ws, _) = tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), None)
            .await
            .map_err(|_| anyhow!("hub handshake failed"))?;
        anyhow::Ok((ws, peer))
    };
    let connect_result = tokio::select! {
        result = tokio::time::timeout(CONNECT_DEADLINE, connect) => result,
        _ = shutdown.changed() => return Ok(()),
    };
    let (mut ws, peer) = connect_result
        .with_context(|| format!("no connection after {}s", CONNECT_DEADLINE.as_secs()))?
        .context("connect")?;
    agent_log!("connected to {peer}");
    *connected = Some(Instant::now());
    let mut echoes = EchoTasks::default();
    let echo_token = std::sync::Arc::new(zeroize::Zeroizing::new(token.to_owned()));
    echoes
        .update(
            glimpse_family(peer.is_ipv6(), &facts.ipv4, &facts.ipv6),
            url,
            &echo_token,
            &host,
            port,
            network,
            loopback_only,
        )
        .await;
    // The clock starts at the handshake and the hello below draws from it like
    // every other write, so no two writes can each claim a full HUB_SILENCE.
    let mut last_frame = Instant::now();

    let Some(result) = send_or_stop(
        &mut ws,
        notify("hello", serde_json::to_value(&facts)?),
        remaining(last_frame),
        shutdown.clone(),
    )
    .await
    else {
        return Ok(());
    };
    result?;

    let (result_tx, mut result_rx) = mpsc::channel::<Message>(64);
    let mut ping_tasks = PingTasks::default();
    // The baseline is taken a second before the first report, which then
    // measures CPU and network over that second rather than over nothing --
    // all a freshly started process has -- or over the outage since the
    // previous session.
    collector.begin_session_baseline().await?;
    let mut ticker =
        tokio::time::interval_at(Instant::now() + Duration::from_secs(1), Duration::from_secs(interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut recheck = tokio::time::interval_at(Instant::now() + FACTS_RECHECK, FACTS_RECHECK);
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // RAII aborts probes and echo retries on every exit, including `?`.
    // The socket wrapper retains admission until its actual cancellation.
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let sample = collector.collect().await?;
                if !collector.has_sample() { continue; }
                let m = serde_json::to_value(sample)?;
                let Some(result) = send_or_stop(&mut ws, notify("report", m), remaining(last_frame), shutdown.clone()).await else {
                    break Ok(())
                };
                if let Err(error) = result { break Err(error); }
            }
            _ = recheck.tick() => {
                let fresh = collector.facts().await?;
                if fresh == facts {
                    continue;
                }
                if (&fresh.ipv4, &fresh.ipv6) != (&facts.ipv4, &facts.ipv6) {
                    echoes.update(glimpse_family(peer.is_ipv6(), &fresh.ipv4, &fresh.ipv6),
                        url, &echo_token, &host, port, network, loopback_only).await;
                }
                let hello = notify("hello", serde_json::to_value(&fresh)?);
                let Some(result) =
                    send_or_stop(&mut ws, hello, remaining(last_frame), shutdown.clone()).await
                else {
                    break Ok(())
                };
                if let Err(error) = result {
                    break Err(error);
                }
                facts = fresh;
            }
            // Rebuilt each pass from the last frame, so silence costs exactly
            // HUB_SILENCE rather than a polling interval more. Kept separate
            // from the report tick, which --interval can stretch to an hour.
            _ = tokio::time::sleep(remaining(last_frame)) => {
                break Err(anyhow!("no frame from the hub in {}s", HUB_SILENCE.as_secs()));
            }
            Some(msg) = result_rx.recv() => {
                let Some(result) = send_or_stop(&mut ws, msg, remaining(last_frame), shutdown.clone()).await else {
                    break Ok(())
                };
                if let Err(error) = result { break Err(error); }
            }
            _ = shutdown.changed() => {
                break Ok(())
            }
            incoming = ws.next() => {
                if let Some(Ok(message)) = &incoming {
                    if network.control(message.len()).is_err() {
                        break Err(anyhow!("hub control message budget exceeded"));
                    }
                }
                // Any frame proves the path alive, including the hub's
                // heartbeat ping -- the only one on an otherwise idle link.
                last_frame = Instant::now();
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(rpc) = serde_json::from_str::<Rpc>(&text) {
                            if rpc.method == "ping.tasks" {
                                if let Ok(tasks) = serde_json::from_value::<Vec<PingTask>>(rpc.params) {
                                    respawn_ping_tasks(&mut ping_tasks.0, tasks, &result_tx, network, policy);
                                }
                            }
                        }
                    }
                    // Ping included: tungstenite queues the pong itself and
                    // sends it on the next read; a manual reply would duplicate it.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(e.into()),
                    None => break Ok(()),
                }
            }
        }
    }
}

/// The upgrade request for `url`, carrying the node's token.
fn authorized(url: &str, token: &str) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request> {
    let mut request = url.into_client_request()?;
    let bearer = zeroize::Zeroizing::new(format!("Bearer {token}"));
    let mut value = bearer
        .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
        .context("token is not header-safe")?;
    value.set_sensitive(true);
    request.headers_mut().insert("authorization", value);
    Ok(request)
}

/// Which family a second connection is wanted in, as `v6`, given the one the
/// session runs over and the addresses the interfaces hold. The session shows
/// the hub one exit; for the other family it is wanted only where the interface
/// holds a private address of it -- NAT66, a ULA behind a masquerading host --
/// since a public one is reported as it is and none means nothing to connect
/// from.
fn glimpse_family(session_v6: bool, ipv4: &str, ipv6: &str) -> Option<bool> {
    let held = if session_v6 { ipv4 } else { ipv6 };
    held.parse::<std::net::IpAddr>().is_ok_and(|ip| !collect::is_public(ip)).then_some(!session_v6)
}

/// How long one attempt of [`glimpse`] may take. The session does not wait on
/// it, so a path that cannot complete is abandoned well before
/// [`CONNECT_DEADLINE`].
const GLIMPSE_DEADLINE: Duration = Duration::from_secs(15);

/// Attempts of [`glimpse`], and the wait between them. A session on a NAT66
/// node can run for weeks, so one lost SYN or failed lookup would leave the hub
/// without the exit until the next reconnect.
const GLIMPSE_TRIES: u32 = 3;
const GLIMPSE_RETRY: Duration = Duration::from_secs(30);

/// How an attempt of [`glimpse`] ended once a connection was possible.
enum Glimpse {
    /// The hub took the connection, or has no address in that family.
    Done,
    /// The hub answered the handshake with a refusal: an older hub without the
    /// route (404), or a proxy or firewall in front of it (403). Retrying
    /// changes nothing.
    Refused(u16),
}

/// The hub's echo route, from the session's URL.
fn echo_url(session: &str) -> Result<String> {
    let base = session.strip_suffix("/ws").context("server URL is not a session route")?;
    Ok(format!("{base}/echo"))
}

/// Connects to the hub's echo route once over one address family, `v6` or v4,
/// and drops the connection once it is upgraded. The hub learns the address this
/// host exits at in that family from where the connection came, which an
/// interface holding only a private address cannot tell it. Nothing is
/// exchanged. Failures are logged and otherwise ignored: the session does not
/// depend on this one.
#[derive(Default)]
struct EchoTasks {
    task: network::TaskGuard,
}
impl EchoTasks {
    #[allow(clippy::too_many_arguments)]
    async fn update(
        &mut self,
        family: Option<bool>,
        url: &str,
        token: &std::sync::Arc<zeroize::Zeroizing<String>>,
        host: &str,
        port: u16,
        network: &std::sync::Arc<network::Network>,
        loopback_only: bool,
    ) {
        // Called on initial hello and address changes only. Even in the same
        // family an address change needs a fresh echo. Await actual cancellation
        // before replacing it so old sockets/tokens cannot overlap a replacement.
        for handle in self.task.0.drain(..) {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(v6) = family {
            self.task.0.push(tokio::spawn(glimpse(
                url.to_owned(),
                token.clone(),
                host.to_owned(),
                port,
                v6,
                network.clone(),
                loopback_only,
            )));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn glimpse(
    url: String,
    token: std::sync::Arc<zeroize::Zeroizing<String>>,
    host: String,
    port: u16,
    v6: bool,
    network: std::sync::Arc<network::Network>,
    loopback_only: bool,
) {
    let family = if v6 { "IPv6" } else { "IPv4" };
    for attempt in 1..=GLIMPSE_TRIES {
        match tokio::time::timeout(
            GLIMPSE_DEADLINE,
            echo_once(&url, &token, &host, port, v6, &network, loopback_only),
        )
        .await
        {
            Ok(Ok(Glimpse::Done)) => return,
            Ok(Ok(Glimpse::Refused(status))) => {
                agent_log!("the hub answered {status} on its echo route over {family}; its exit there is not recorded");
                return;
            }
            // Do not log untrusted handshake response bodies/headers (which
            // may reflect the Authorization token).
            Ok(Err(_)) => agent_log!("the hub could not be reached over {family}: echo failed"),
            Err(_) => agent_log!("the hub could not be reached over {family}: no answer"),
        }
        if attempt < GLIMPSE_TRIES {
            tokio::time::sleep(GLIMPSE_RETRY).await;
        }
    }
}

async fn echo_once(
    url: &str,
    token: &str,
    host: &str,
    port: u16,
    v6: bool,
    network: &network::Network,
    loopback_only: bool,
) -> Result<Glimpse> {
    let addrs: Vec<_> = network
        .resolve(host, port)
        .await
        .context("resolve hub")?
        .into_iter()
        .filter(|a| a.is_ipv6() == v6 && (!loopback_only || probe::unmapped(a.ip()).is_loopback()))
        .collect();
    if addrs.is_empty() {
        return Ok(Glimpse::Done);
    }
    let stream = connect_first(network, &addrs).await?;
    ensure_loopback_peer(stream.stream.peer_addr()?, loopback_only)?;
    let request = authorized(&echo_url(url)?, token)?;
    let config =
        WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    match tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), None).await {
        Ok(_) => Ok(Glimpse::Done),
        Err(WsError::Http(response)) => Ok(Glimpse::Refused(response.status().as_u16())),
        Err(_) => Err(anyhow!("echo handshake failed")),
    }
}

/// The URL spelling localhost is not proof of the peer's address. Check
/// both resolved candidates (before a connection) and the actual socket peer
/// (before sending credentials), including IPv4-mapped IPv6.
fn ensure_loopback_peer(peer: std::net::SocketAddr, loopback_only: bool) -> Result<()> {
    if loopback_only && !probe::unmapped(peer.ip()).is_loopback() {
        bail!("plaintext hub without --insecure must have a loopback peer");
    }
    Ok(())
}

/// A private local IPv4 means the hub can learn the host's public NAT address
/// only from a connection that arrives over IPv4.
fn prefers_ipv4(ipv4: &str) -> bool {
    ipv4.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| !collect::is_public(ip.into()))
}

fn sort_addresses(addrs: &mut [std::net::SocketAddr], prefer_v4: bool) {
    if prefer_v4 {
        addrs.sort_by_key(|addr| !addr.is_ipv4());
    }
}

async fn dial(
    network: &network::Network,
    host: &str,
    port: u16,
    prefer_v4: bool,
    loopback_only: bool,
) -> Result<network::Connection> {
    let mut addrs = network.resolve(host, port).await.context("resolve hub")?;
    if loopback_only {
        addrs.retain(|a| probe::unmapped(a.ip()).is_loopback());
    }
    sort_addresses(&mut addrs, prefer_v4);
    connect_first(network, &addrs).await
}

async fn connect_first(
    network: &network::Network,
    addrs: &[std::net::SocketAddr],
) -> Result<network::Connection> {
    for addr in addrs.iter().take(resolver::MAX_ADDRESSES) {
        if let Ok(Ok(connection)) = tokio::time::timeout(DIAL_FALLBACK, network.connect(*addr, false)).await {
            return Ok(connection);
        }
    }
    bail!("no reachable hub address");
}

/// Ceiling on concurrent probe loops.
///
/// A task serialises to about forty bytes, so one [`MAX_MESSAGE`] frame could
/// request some fifteen hundred; at the five-second interval floor that is
/// hundreds of outbound connects per second to hub-chosen addresses, which on
/// a shared VPS reads as a port scan and acts as an amplifier. A compromised
/// or merely buggy hub is within the threat model, so the list is bounded
/// rather than trusted.
const MAX_PING_TASKS: usize = 64;

/// Replaces the running probe loops with the hub's current task list, leaving
/// unchanged tasks in place so their timers survive a push.
#[derive(Default)]
struct PingTasks(Vec<(PingTask, tokio::task::JoinHandle<()>)>);
impl Drop for PingTasks {
    fn drop(&mut self) {
        for (_, handle) in &self.0 {
            handle.abort();
        }
    }
}

fn respawn_ping_tasks(
    running: &mut Vec<(PingTask, tokio::task::JoinHandle<()>)>,
    mut wanted: Vec<PingTask>,
    tx: &mpsc::Sender<Message>,
    network: &std::sync::Arc<network::Network>,
    policy: &std::sync::Arc<probe::Policy>,
) {
    // Canonical values are compared, not hub-controlled padding/raw intervals.
    // First duplicate id wins, and invalid targets consume no task slots.
    let mut ids = HashSet::new();
    wanted = wanted
        .into_iter()
        .filter_map(|mut task| {
            task.target = probe::normalize(&task.target).ok()?.2;
            task.interval = task.interval.clamp(5, 3600);
            ids.insert(task.id).then_some(task)
        })
        .take(MAX_PING_TASKS)
        .collect();
    running.retain(|(task, handle)| {
        let keep =
            wanted.iter().any(|w| w.id == task.id && w.target == task.target && w.interval == task.interval);
        if !keep {
            handle.abort();
        }
        keep
    });
    for task in wanted {
        if running.iter().any(|(t, _)| t.id == task.id) {
            continue;
        }
        let (tx, spawned) = (tx.clone(), task.clone());
        let (network, policy) = (network.clone(), policy.clone());
        let handle = tokio::spawn(async move {
            let period = Duration::from_secs(spawned.interval);
            let mut ticker = tokio::time::interval_at(Instant::now() + period, period);
            // As with the report ticker, missed ticks must not fire back to
            // back: the default burst behaviour would turn one stalled
            // resolution into a rapid series of connects.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(latency) = tcp_ping(&spawned.target, &network, &policy).await else {
                    continue;
                };
                let msg =
                    notify("ping.result", serde_json::json!({"task_id": spawned.id, "latency_ms": latency}));
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        });
        running.push((task, handle));
    }
}

/// Deadline for one handshake, deliberately under the kernel's first SYN
/// retransmit.
///
/// A TCP SYN retransmission turns a dropped packet into a late success,
/// reporting the retransmit timer plus the round trip as latency.
///
/// Cutting it short guarantees that every reading belongs to a handshake
/// completed on the first SYN, and that a dropped one becomes -1. The cost is
/// that a link whose genuine round trip exceeds this reads as unreachable.
const HANDSHAKE_DEADLINE: Duration = Duration::from_millis(900);

/// How many of a name's addresses one probe attempts.
///
/// Each dead address costs a [`HANDSHAKE_DEADLINE`], and a probe must not
/// outlast the five-second floor on its own interval.
const MAX_PING_ADDRS: usize = 3;

/// Round-trip time of a TCP handshake in milliseconds; -1 when no address
/// answered within [`HANDSHAKE_DEADLINE`], `None` when the name could not be
/// resolved in that time.
///
/// The two failure modes must stay distinct. -1 is the protocol's word for a
/// target that did not answer, and the hub folds every negative reading into a
/// bucket's packet loss, so returning it for a slow resolver would draw loss on
/// a link that dropped nothing. An overrun resolution is a sample not taken,
/// which is not a reading of zero.
///
/// The name is resolved before the clock starts: `TcpStream::connect` on a
/// hostname resolves first and connects second, which would fold resolver
/// latency into every sample. Resolution is repeated each round.
///
/// Policy rejection, resolver saturation and exhausted resource budgets also
/// produce no sample, never fabricated packet loss.
async fn tcp_ping(target: &str, network: &network::Network, policy: &probe::Policy) -> Option<i32> {
    let Ok((host, port, normalized)) = probe::normalize(target) else { return Some(-1) };
    if network.probe_round(&normalized).is_err() {
        return None;
    }
    let resolved = tokio::time::timeout(HANDSHAKE_DEADLINE, network.resolve(&host, port)).await;
    let addresses = match resolved {
        Err(_) => return None,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
        Ok(Err(_)) => return Some(-1),
        Ok(Ok(addresses)) => addresses,
    };
    // Validate every resolved candidate before connecting. Mixed public/private
    // answers fail closed, preventing rebinding and mapped-v6 policy bypass.
    if addresses.iter().any(|address| !policy.allows(*address)) {
        return None;
    }
    handshake(addresses.into_iter(), network).await
}

async fn handshake(
    addresses: impl Iterator<Item = std::net::SocketAddr>,
    network: &network::Network,
) -> Option<i32> {
    for address in addresses.take(MAX_PING_ADDRS) {
        let started = std::time::Instant::now();
        match tokio::time::timeout(HANDSHAKE_DEADLINE, network.connect(address, true)).await {
            Ok(Ok(_connection)) => return Some(started.elapsed().as_millis().min(i32::MAX as u128) as i32),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
            _ => {}
        }
    }
    Some(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_restart_costs_a_second_while_an_unreachable_one_still_backs_off() {
        // Nothing on the other end: double to the ceiling and hold. Zero is
        // what the caller passes for a connect that never completed, so a
        // stalled attempt cannot be credited as a session that ran.
        let mut wait = 0;
        let climb: Vec<u64> = (0..8)
            .map(|_| {
                wait = reconnect_wait(wait, Duration::ZERO);
                wait
            })
            .collect();
        assert_eq!(climb, [1, 2, 4, 8, 16, 32, 60, 60]);

        // A session that ran resets the wait however high it had climbed:
        // the hub-restart case.
        assert_eq!(reconnect_wait(60, Duration::from_secs(3600)), 1);
        // Connected but dropped too early to prove anything: still a retreat.
        assert_eq!(reconnect_wait(4, Duration::from_secs(29)), 8);
    }

    #[test]
    fn nics_accepts_both_spellings_and_ignores_padding() {
        assert_eq!(parse_nics("Ethernet,Wi-Fi"), ["Ethernet", "Wi-Fi"]);
        // A value from a unit file or a shell variable arrives with spaces.
        assert_eq!(parse_nics(" Ethernet , Wi-Fi "), ["Ethernet", "Wi-Fi"]);
        // A single interface is the common case, and a trailing comma from a
        // generated list is not an interface name.
        assert_eq!(parse_nics("Ethernet"), ["Ethernet"]);
        assert_eq!(parse_nics("Ethernet,"), ["Ethernet"]);
        // `--nics ""` is not a way to count nothing; it is no list at all.
        assert!(parse_nics("  ,  ").is_empty());
    }

    #[test]
    fn private_ipv4_triggers_ipv4_priority_only_for_nat_hosts() {
        assert!(prefers_ipv4("10.0.0.2"));
        assert!(prefers_ipv4("100.64.1.2"));
        assert!(!prefers_ipv4("8.8.8.8"));
        assert!(!prefers_ipv4(""));
    }

    #[test]
    fn a_second_connection_is_wanted_only_for_a_private_address_in_the_other_family() {
        // A v4 session: NAT66 or a ULA is worth asking about, a public v6 is
        // reported as it is, and none leaves nothing to connect from.
        assert_eq!(glimpse_family(false, "10.0.0.5", "fd00::5"), Some(true));
        assert_eq!(glimpse_family(false, "203.0.113.5", "fd42::1"), Some(true));
        assert_eq!(glimpse_family(false, "10.0.0.5", "2001:db8::5"), None);
        assert_eq!(glimpse_family(false, "10.0.0.5", ""), None);
        // A v6 session reached over a hub that has no v4 record, or whose v4 failed.
        assert_eq!(glimpse_family(true, "10.0.0.5", "2001:db8::5"), Some(false));
        assert_eq!(glimpse_family(true, "203.0.113.5", "2001:db8::5"), None);
        assert_eq!(glimpse_family(true, "", "2001:db8::5"), None);
    }

    #[test]
    fn the_echo_route_sits_beside_the_session_route() {
        let session = ws_url("https://hub.example.com/", false).unwrap();
        assert_eq!(echo_url(&session).unwrap(), "wss://hub.example.com/api/agent/echo");
        assert!(echo_url("wss://hub.example.com/other").is_err());
    }

    #[test]
    fn address_sort_prefers_ipv4_only_when_requested() {
        let v4: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        let v6: std::net::SocketAddr = "[::1]:80".parse().unwrap();
        let original = [v6, v4];
        let mut addresses = original;
        sort_addresses(&mut addresses, true);
        assert!(addresses[0].is_ipv4());
        let mut addresses = original;
        sort_addresses(&mut addresses, false);
        assert_eq!(addresses, original, "normal hosts retain resolver order");
    }

    #[tokio::test]
    async fn hub_dial_tries_the_next_address_after_a_refusal() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        let network = network::Network::new().unwrap();
        let connection = connect_first(&network, &[dead, live]).await.unwrap();
        assert_eq!(connection.stream.peer_addr().unwrap(), live);
    }

    #[test]
    fn service_name_defaults_and_allows_independent_instances() {
        assert_eq!(parse_service_name(std::iter::empty::<String>()).unwrap(), DEFAULT_SERVICE_NAME);
        assert_eq!(
            parse_service_name(["--service-name".into(), "monitor-agent-backup".into()]).unwrap(),
            "monitor-agent-backup"
        );
        assert!(parse_service_name(["--service-name".into(), "bad/name".into()]).is_err());
    }

    #[test]
    fn ws_url_upgrades_scheme_and_refuses_plaintext_to_remote() {
        assert_eq!(ws_url("https://hub.example.com/", false).unwrap(), "wss://hub.example.com/api/agent/ws");
        assert_eq!(ws_url("HTTPS://hub.example.com/", false).unwrap(), "wss://hub.example.com/api/agent/ws");
        assert_eq!(ws_url("HTTP://127.0.0.1:28080", false).unwrap(), "ws://127.0.0.1:28080/api/agent/ws");
        assert_eq!(ws_url("WSS://hub.example.com", false).unwrap(), "wss://hub.example.com/api/agent/ws");
        assert!(ws_url("HTTP://hub.example.com", false).is_err());
        assert!(ws_url("WS://hub.example.com", false).is_err());
        assert_eq!(ws_url("http://127.0.0.1:28080", false).unwrap(), "ws://127.0.0.1:28080/api/agent/ws");
        // A bare host defaults to TLS rather than leaking the token.
        assert!(ws_url("hub.example.com", false).unwrap().starts_with("wss://"));
        assert!(ws_url("http://hub.example.com", false).is_err());
        // Bracketed IPv6 loopback is not remote.
        assert_eq!(ws_url("http://[::1]:28080", false).unwrap(), "ws://[::1]:28080/api/agent/ws");
        assert_eq!(ws_url("http://localhost:28080", false).unwrap(), "ws://localhost:28080/api/agent/ws");
        // A name that merely begins like the loopback net belongs to someone
        // else: the host is parsed, not prefix-matched.
        assert!(ws_url("http://127.attacker.example/", false).is_err());
        // Fail closed: a mapped literal is not read as loopback either.
        assert!(ws_url("http://[::ffff:127.0.0.1]:28080", false).is_err());
        // Userinfo places a loopback address where the host check looks and
        // another name where the socket goes; http::Uri resolves this authority's
        // host to evil.example.com. --insecure skips the plaintext refusal, so the
        // check cannot live inside it.
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", false).is_err());
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", true).is_err());
        assert!(ws_url("https://hub.example.com@evil.example.com/", false).is_err());
        // No token anywhere in the URL; it travels in a header.
        assert!(!ws_url("https://hub.example.com", false).unwrap().contains("token"));
    }

    /// `--insecure` covers a hub reached at ip:port with no TLS: it permits the
    /// plaintext hop and suppresses the bare-host TLS upgrade, which would
    /// otherwise dial wss:// at a port that cannot answer.
    #[test]
    fn insecure_allows_plaintext_to_a_remote_hub_and_stops_upgrading_bare_hosts() {
        assert_eq!(
            ws_url("http://203.0.113.10:28080", true).unwrap(),
            "ws://203.0.113.10:28080/api/agent/ws"
        );
        assert_eq!(ws_url("203.0.113.10:28080", true).unwrap(), "ws://203.0.113.10:28080/api/agent/ws");
        // An explicit https:// hub stays on TLS: the flag permits plaintext
        // rather than forcing it.
        assert_eq!(ws_url("https://hub.example.com", true).unwrap(), "wss://hub.example.com/api/agent/ws");
    }

    #[tokio::test(start_paused = true)]
    async fn initial_facts_timeout_never_promotes_a_default_snapshot() {
        let (_tx, mut shutdown) = watch::channel(false);
        let started = Instant::now();
        let result = wait_initial_facts(|| async { Ok(None) }, &mut shutdown).await;
        assert!(result.is_err());
        assert_eq!(started.elapsed(), INITIAL_FACTS_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn initial_facts_returns_only_a_valid_snapshot_and_honors_stop() {
        let (tx, mut shutdown) = watch::channel(false);
        let calls = std::cell::Cell::new(0);
        let facts = wait_initial_facts(
            || {
                let call = calls.get();
                calls.set(call + 1);
                async move {
                    Ok((call != 0).then(|| collect::Facts { ipv4: "10.0.0.2".into(), ..Default::default() }))
                }
            },
            &mut shutdown,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(facts.ipv4, "10.0.0.2");
        assert!(prefers_ipv4(&facts.ipv4));
        tx.send(true).unwrap();
        assert!(wait_initial_facts(|| async { panic!("polled after Stop") }, &mut shutdown)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_initial_facts_is_interruptible_by_stop() {
        let (tx, mut shutdown) = watch::channel(false);
        let stop = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send(true).unwrap();
        };
        let wait = wait_initial_facts(std::future::pending::<Result<Option<collect::Facts>>>, &mut shutdown);
        let (result, ()) = tokio::join!(wait, stop);
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn tcp_ping_measures_success_and_reports_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let policy = probe::Policy::parse("127.0.0.0/8").unwrap();
        let network = network::Network::new().unwrap();
        assert!(tcp_ping(&addr.to_string(), &network, &policy).await.unwrap() >= 0);
        assert_eq!(tcp_ping("127.0.0.1:1", &network, &policy).await, Some(-1));
        assert_eq!(tcp_ping("127.0.0.1:99999", &network, &policy).await, Some(-1));
        let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(handshake([dead, addr].into_iter(), &network).await.unwrap() >= 0);
        assert_eq!(handshake([dead, dead].into_iter(), &network).await, Some(-1));
        assert_eq!(handshake([dead, dead, dead, addr].into_iter(), &network).await, Some(-1));
    }

    #[tokio::test]
    async fn a_hub_probe_cannot_access_loopback_without_local_opt_in() {
        let network = network::Network::new().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        assert_eq!(tcp_ping(&target, &network, &probe::Policy::default()).await, None);
        assert!(tokio::time::timeout(Duration::from_millis(30), listener.accept()).await.is_err());
    }

    #[test]
    fn plaintext_localhost_requires_an_actual_loopback_peer() {
        assert!(ensure_loopback_peer("127.0.0.1:80".parse().unwrap(), true).is_ok());
        assert!(ensure_loopback_peer("[::ffff:127.0.0.1]:80".parse().unwrap(), true).is_ok());
        assert!(ensure_loopback_peer("10.0.0.1:80".parse().unwrap(), true).is_err());
        assert!(ensure_loopback_peer("8.8.8.8:80".parse().unwrap(), true).is_err());
        assert!(ensure_loopback_peer("10.0.0.1:80".parse().unwrap(), false).is_ok());
        let request = authorized("wss://hub.example.com/api/agent/ws", "secret").unwrap();
        assert!(request.headers()["authorization"].is_sensitive());
    }

    #[tokio::test]
    async fn echo_is_unique_per_family_and_owned_by_the_session() {
        let network = network::Network::new().unwrap();
        let token = std::sync::Arc::new(zeroize::Zeroizing::new("secret".to_owned()));
        let mut echoes = EchoTasks::default();
        echoes
            .update(Some(true), "wss://example.com/api/agent/ws", &token, "example.com", 443, &network, false)
            .await;
        let old = echoes.task.0[0].abort_handle();
        echoes
            .update(Some(true), "wss://example.com/api/agent/ws", &token, "example.com", 443, &network, false)
            .await;
        assert!(old.is_finished(), "same-family address change cancels old echo first");
        assert_eq!(echoes.task.0.len(), 1);
        echoes
            .update(None, "wss://example.com/api/agent/ws", &token, "example.com", 443, &network, false)
            .await;
        tokio::task::yield_now().await;
        assert!(old.is_finished());
        echoes
            .update(
                Some(false),
                "wss://example.com/api/agent/ws",
                &token,
                "example.com",
                443,
                &network,
                false,
            )
            .await;
        let last = echoes.task.0[0].abort_handle();
        drop(echoes);
        tokio::task::yield_now().await;
        assert!(last.is_finished());
    }

    /// The deadline must stay below a normal SYN retransmission window, or a
    /// dropped SYN is reported as latency instead of loss.
    #[test]
    fn the_handshake_deadline_stays_under_the_kernels_syn_timer() {
        assert!(
            HANDSHAKE_DEADLINE < Duration::from_secs(1),
            "a deadline at or past the 1s initial RTO lets retransmits be reported as latency"
        );
    }

    /// The hub pings every 30s and drops an agent silent for 120s. Both ends of
    /// this window are load-bearing and neither is visible from this file.
    ///
    /// The bound holds only because the watchdog sleeps to a deadline and each
    /// write draws from what remains of that same deadline; the two structures
    /// enforcing that are asserted separately below.
    #[test]
    fn the_agent_gives_up_on_a_silent_hub_before_the_hub_gives_up_on_it() {
        assert!(
            HUB_SILENCE < Duration::from_secs(120),
            "past the hub's own timeout the agent stops being what recovers the connection"
        );
        assert!(HUB_SILENCE > Duration::from_secs(60), "two lost heartbeats are a blip, not a dead link");
    }

    /// A sink that never accepts: the socket whose peer has stopped reading,
    /// which is the case the write deadline exists for.
    struct NeverDrains;

    impl Sink<Message> for NeverDrains {
        type Error = WsError;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), WsError> {
            unreachable!("never ready")
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }
    }

    /// Every write draws from one clock started at the handshake, so a session
    /// gives up exactly HUB_SILENCE after its last sign of life regardless of
    /// how many writes stalled in between. The hello is the first such write.
    #[tokio::test(start_paused = true)]
    async fn a_slow_hello_cannot_push_the_give_up_point_past_the_hubs_own_timeout() {
        let handshake = Instant::now();
        assert_eq!(remaining(handshake), HUB_SILENCE, "the first write gets the whole budget");

        // A stalled hello must fail at the budget it was handed, not one of
        // its own.
        assert!(send(&mut NeverDrains, notify("hello", serde_json::json!({})), remaining(handshake))
            .await
            .is_err());
        assert_eq!(handshake.elapsed(), HUB_SILENCE, "the stall costs the budget, no more");

        // Afterwards the give-up moment stays at last_frame + HUB_SILENCE:
        // spent plus remaining is always that one window.
        for spent in [0, 30, 89, 90, 200] {
            let last_frame = Instant::now();
            tokio::time::advance(Duration::from_secs(spent)).await;
            assert_eq!(
                last_frame.elapsed() + remaining(last_frame),
                HUB_SILENCE.max(last_frame.elapsed()),
                "{spent}s in, the budget must not push the deadline out"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn task_churn_never_earns_an_immediate_probe() {
        let network = network::Network::new().unwrap();
        let policy = std::sync::Arc::new(probe::Policy::parse("127.0.0.0/8").unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let (tx, mut rx) = mpsc::channel(8);
        let mut tasks = PingTasks::default();
        for id in 0..100 {
            respawn_ping_tasks(
                &mut tasks.0,
                vec![PingTask { id, target: target.clone(), interval: 5 }],
                &tx,
                &network,
                &policy,
            );
            tokio::task::yield_now().await;
        }
        assert!(rx.try_recv().is_err());
        assert!(network.probe_round(&target).is_ok(), "no churned task performed even a DNS round");
        assert_eq!(tasks.0.len(), 1);
    }

    #[test]
    fn ping_tasks_keep_their_timers_unless_the_task_changed() {
        // The runtime flavour the binary uses.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let (tx, _rx) = mpsc::channel(8);
        let mut running = Vec::new();
        let network = network::Network::new().unwrap();
        let policy = std::sync::Arc::new(probe::Policy::default());
        let task = |id, target: &str, interval| PingTask { id, target: target.into(), interval };

        respawn_ping_tasks(
            &mut running,
            vec![task(1, "a:1", 60), task(2, "b:2", 60)],
            &tx,
            &network,
            &policy,
        );
        assert_eq!(running.len(), 2);
        let (first, second) = (running[0].1.id(), running[1].1.id());

        // Task 1 unchanged, task 2 retargeted, task 3 added.
        respawn_ping_tasks(
            &mut running,
            vec![task(1, "a:1", 60), task(2, "c:3", 60), task(3, "d:4", 60)],
            &tx,
            &network,
            &policy,
        );
        assert_eq!(running.len(), 3);
        assert_eq!(running[0].1.id(), first, "unchanged task must not be restarted");
        // A task whose target changed must be torn down, or it keeps probing
        // the old address.
        assert_ne!(running[1].1.id(), second, "a retargeted task must be restarted");

        // Interval 0 must not take the probe down: tokio's interval panics on
        // a zero period, and a panicked task stops reporting silently.
        respawn_ping_tasks(&mut running, vec![task(9, "e:5", 0)], &tx, &network, &policy);
        rt.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
        assert!(!running[0].1.is_finished(), "a zero interval must be clamped, not panic the probe");

        let normalized = running[0].1.id();
        respawn_ping_tasks(&mut running, vec![task(9, " E.:0005 ", 1)], &tx, &network, &policy);
        assert_eq!(running[0].1.id(), normalized, "normalized interval and target retain timer");

        // One 64 KiB frame could carry some fifteen hundred of these; the
        // agent enforces its own ceiling rather than trusting the count.
        let flood = (0..500).map(|id| task(id, "f:6", 60)).collect();
        respawn_ping_tasks(&mut running, flood, &tx, &network, &policy);
        assert_eq!(running.len(), MAX_PING_TASKS, "the hub does not choose how many probes run");
    }
}
