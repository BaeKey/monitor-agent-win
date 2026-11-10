//! Process-lifetime network budgets; task replacement cannot refill them.
use crate::{resolver::Resolver, TcpStream};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

pub(crate) const SOCKETS: usize = 12;
const PROBE_SOCKETS: usize = 8;
const CONNECTIONS_PER_SECOND: usize = 20;
const PROBE_CONNECTIONS_PER_SECOND: usize = 10;
const DNS_PER_SECOND: usize = 20;
const TARGET_COOLDOWN: Duration = Duration::from_secs(5);
const TRACKED_TARGETS: usize = 1024;

pub(crate) struct Network {
    pub(crate) resolver: Resolver,
    sockets: Arc<Semaphore>,
    probes: Arc<Semaphore>,
    attempts: Mutex<Window>,
    probe_attempts: Mutex<Window>,
    resolutions: Mutex<Window>,
    controls: Mutex<Window>,
    targets: Mutex<HashMap<String, Instant>>,
}

/// Exact sliding-window count and bytes, rather than a bucket that permits
/// double the advertised rate immediately across window boundaries.
struct Window {
    events: VecDeque<(Instant, usize)>,
    bytes: usize,
    count_limit: usize,
    byte_limit: usize,
}
impl Window {
    fn new(count_limit: usize, byte_limit: usize) -> Self {
        Self { events: VecDeque::new(), bytes: 0, count_limit, byte_limit }
    }
    fn admit(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        while self.events.front().is_some_and(|(at, _)| now.duration_since(*at) >= Duration::from_secs(1)) {
            self.bytes -= self.events.pop_front().expect("front present").1;
        }
        if self.events.len() >= self.count_limit || bytes > self.byte_limit.saturating_sub(self.bytes) {
            return false;
        }
        self.events.push_back((now, bytes));
        self.bytes += bytes;
        true
    }
}
fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "network resource budget exhausted")
}
fn admit(window: &Mutex<Window>, bytes: usize) -> io::Result<()> {
    if window.lock().map_err(|_| io::Error::other("network budget state"))?.admit(bytes) {
        Ok(())
    } else {
        Err(busy())
    }
}

impl Network {
    pub(crate) fn new() -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            resolver: Resolver::new()?,
            sockets: Arc::new(Semaphore::new(SOCKETS)),
            probes: Arc::new(Semaphore::new(PROBE_SOCKETS)),
            attempts: Mutex::new(Window::new(CONNECTIONS_PER_SECOND, usize::MAX)),
            probe_attempts: Mutex::new(Window::new(PROBE_CONNECTIONS_PER_SECOND, usize::MAX)),
            resolutions: Mutex::new(Window::new(DNS_PER_SECOND, usize::MAX)),
            controls: Mutex::new(Window::new(32, 128 * 1024)),
            targets: Mutex::new(HashMap::new()),
        }))
    }
    pub(crate) fn shared() -> io::Result<Arc<Self>> {
        static NETWORK: OnceLock<Result<Arc<Network>, String>> = OnceLock::new();
        NETWORK
            .get_or_init(|| Self::new().map_err(|e| e.to_string()))
            .as_ref()
            .cloned()
            .map_err(|message| io::Error::other(message.clone()))
    }
    pub(crate) fn control(&self, bytes: usize) -> io::Result<()> {
        admit(&self.controls, bytes)
    }
    pub(crate) fn probe_round(&self, target: &str) -> io::Result<()> {
        let mut targets = self.targets.lock().map_err(|_| io::Error::other("probe budget state"))?;
        let now = Instant::now();
        targets.retain(|_, at| now.duration_since(*at) < TARGET_COOLDOWN);
        if targets.contains_key(target) || targets.len() >= TRACKED_TARGETS {
            return Err(busy());
        }
        targets.insert(target.to_owned(), now);
        Ok(())
    }
    pub(crate) async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        admit(&self.resolutions, 0)?;
        self.resolver.resolve(host, port).await
    }
    pub(crate) async fn connect(&self, address: SocketAddr, probe: bool) -> io::Result<Connection> {
        let probe_permit =
            if probe { Some(self.probes.clone().try_acquire_owned().map_err(|_| busy())?) } else { None };
        let permit = self.sockets.clone().try_acquire_owned().map_err(|_| busy())?;
        if probe {
            admit(&self.probe_attempts, 0)?;
        }
        admit(&self.attempts, 0)?;
        let stream = TcpStream::connect(address).await?;
        Ok(Connection { stream, _permits: SocketPermits { _socket: permit, _probe: probe_permit } })
    }
}

pub(crate) struct Connection {
    pub(crate) stream: TcpStream,
    // Struct field order closes the real socket before releasing admission.
    _permits: SocketPermits,
}
impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.get_mut().stream), cx, buf)
    }
}
impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.get_mut().stream), cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.get_mut().stream), cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.get_mut().stream), cx)
    }
}
pub(crate) struct SocketPermits {
    _socket: OwnedSemaphorePermit,
    _probe: Option<OwnedSemaphorePermit>,
}

/// Abort on every exit path, including `?`, cancellation and unwinding.
#[derive(Default)]
pub(crate) struct TaskGuard(pub(crate) Vec<tokio::task::JoinHandle<()>>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn sliding_count_and_byte_limits_do_not_refill_on_rebuild() {
        let network = Network::new().unwrap();
        for _ in 0..32 {
            network.control(1).unwrap();
        }
        assert!(network.clone().control(0).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        network.control(65536).unwrap();
        network.control(65536).unwrap();
        assert!(network.control(1).is_err());
        network.probe_round("host:80").unwrap();
        assert!(network.clone().probe_round("host:80").is_err());
        tokio::time::advance(TARGET_COOLDOWN).await;
        network.probe_round("host:80").unwrap();
    }
    #[tokio::test]
    async fn real_connected_sockets_keep_permits_until_dropped() {
        let network = Network::new().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut held = Vec::new();
        for _ in 0..PROBE_SOCKETS {
            held.push(network.connect(address, true).await.unwrap());
        }
        assert!(network.connect(address, true).await.is_err());
        for _ in PROBE_SOCKETS..SOCKETS {
            held.push(network.connect(address, false).await.unwrap());
        }
        assert!(network.connect(address, false).await.is_err());
        drop(held.pop());
        assert!(network.connect(address, false).await.is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn socket_attempt_budget_survives_short_lived_connections() {
        let network = Network::new().unwrap();
        // Exercise the very gates called immediately before TcpStream::connect;
        // no OS sockets are needed to prove sliding-window cancellation safety.
        for _ in 0..PROBE_CONNECTIONS_PER_SECOND {
            admit(&network.probe_attempts, 0).unwrap();
        }
        assert!(admit(&network.clone().probe_attempts, 0).is_err());
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(admit(&network.probe_attempts, 0).is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(admit(&network.probe_attempts, 0).is_ok());
    }
}
