//! A bounded system resolver, deliberately independent of Tokio's blocking pool.
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{mpsc, Arc, Mutex},
};
use tokio::sync::oneshot;

const WORKERS: usize = 2;
const QUEUE: usize = 16;
pub(crate) const MAX_ADDRESSES: usize = 16;
type Key = (String, u16);
type Lookup = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;
struct Job {
    key: Key,
    reply: oneshot::Sender<io::Result<Vec<SocketAddr>>>,
}

pub(crate) struct Resolver {
    tx: mpsc::SyncSender<Job>,
    pending: Arc<Mutex<HashSet<Key>>>,
}

impl Resolver {
    pub(crate) fn new() -> io::Result<Self> {
        Self::with_lookup(Arc::new(|host, port| {
            (host, port).to_socket_addrs().map(|addresses| addresses.take(MAX_ADDRESSES).collect())
        }))
    }

    fn with_lookup(lookup: Arc<Lookup>) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        let pending = Arc::new(Mutex::new(HashSet::new()));
        for index in 0..WORKERS {
            let (rx, pending, lookup) = (rx.clone(), pending.clone(), lookup.clone());
            // Detached, fixed-size workers: an uninterruptible OS resolver must
            // neither accumulate Tokio blocking jobs nor delay runtime shutdown.
            std::thread::Builder::new().name(format!("agent-dns-{index}")).spawn(move || loop {
                let job = match rx.lock() {
                    Ok(rx) => rx.recv(),
                    Err(_) => return,
                };
                let Ok(job) = job else { return };
                if !job.reply.is_closed() {
                    let answer = lookup(&job.key.0, job.key.1);
                    let _ = job.reply.send(answer);
                }
                // Cancellation/timeout of the receiver does not remove this
                // key until the real getaddrinfo invocation has completed.
                if let Ok(mut keys) = pending.lock() {
                    keys.remove(&job.key);
                }
            })?;
        }
        Ok(Self { tx, pending })
    }

    pub(crate) async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if host.len() > 253 || host.chars().any(char::is_control) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"));
        }
        let key = (host.to_ascii_lowercase(), port);
        let (reply, receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock().map_err(|_| io::Error::other("resolver state"))?;
            if !pending.insert(key.clone()) {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "DNS already in flight"));
            }
            if self.tx.try_send(Job { key: key.clone(), reply }).is_err() {
                pending.remove(&key);
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "DNS queue full"));
            }
        }
        receiver.await.map_err(|_| io::Error::other("resolver unavailable"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Condvar,
        },
        time::Duration,
    };

    struct Release(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    #[tokio::test]
    async fn timed_out_dns_keeps_real_inflight_and_queue_bounded() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Release(gate.clone());
        let active = Arc::new(AtomicUsize::new(0));
        let lookup = {
            let (gate, active) = (gate.clone(), active.clone());
            Arc::new(move |_: &str, _: u16| {
                active.fetch_add(1, Ordering::SeqCst);
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(Vec::new())
            }) as Arc<Lookup>
        };
        let resolver = Arc::new(Resolver::with_lookup(lookup).unwrap());
        let mut calls = Vec::new();
        for id in 0..100 {
            let resolver = resolver.clone();
            calls.push(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_millis(40),
                    resolver.resolve(&format!("h{id}.invalid"), 80),
                )
                .await
            }));
        }
        for call in calls {
            let _ = call.await.unwrap();
        }
        let keys = resolver.pending.lock().unwrap().clone();
        assert!(keys.len() <= WORKERS + QUEUE);
        assert!(active.load(Ordering::SeqCst) <= WORKERS);
        assert!(!keys.is_empty(), "caller timeout must not release real DNS work");
        let key = keys.iter().next().unwrap();
        assert_eq!(resolver.resolve(&key.0, key.1).await.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !resolver.pending.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn dropping_runtime_does_not_wait_for_a_stuck_system_resolver() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Release(gate.clone());
        let (started, ready) = mpsc::sync_channel(1);
        let resolver = Resolver::with_lookup(Arc::new(move |_, _| {
            let _ = started.try_send(());
            let mut open = gate.0.lock().unwrap();
            while !*open {
                open = gate.1.wait(open).unwrap();
            }
            Ok(Vec::new())
        }))
        .unwrap();
        let (done, finished) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), resolver.resolve("stuck.invalid", 80))
                        .await;
            });
            drop(runtime);
            let _ = done.send(());
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        finished.recv_timeout(Duration::from_secs(2)).expect("runtime drop waited on dedicated DNS worker");
        drop(release);
    }

    #[tokio::test]
    async fn literal_ips_bypass_the_system_resolver() {
        let resolver = Resolver::with_lookup(Arc::new(|_, _| panic!("DNS used for IP"))).unwrap();
        assert_eq!(
            resolver.resolve("::1", 443).await.unwrap(),
            vec!["[::1]:443".parse::<SocketAddr>().unwrap()]
        );
    }
}
