//! One detachable OS thread owns all potentially blocking collection APIs.
//! A timed-out caller does not cancel an OS call or release its admission slot.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::{oneshot, watch};

use super::{Collector, Facts, Ifaces, Metrics};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const BASELINE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum Kind {
    Facts,
    Metrics,
    Baseline,
}

struct Request {
    kind: Kind,
    done: oneshot::Sender<()>,
    // Only dropping the actual worker request releases the admission slot.
    _permit: Permit,
}

struct Permit(Arc<AtomicBool>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone, Default)]
struct Cache {
    facts: Facts,
    metrics: Metrics,
    metrics_epoch: u64,
    facts_valid: bool,
    metrics_valid: bool,
}

/// Safe to drop even if a faulty disk driver blocks forever: JoinHandle is
/// deliberately not retained/joined. A single instance never replaces a hung
/// worker with another thread, and owns at most one outstanding request.
pub struct WorkerCollector {
    requests: mpsc::SyncSender<Request>,
    cache: watch::Receiver<Cache>,
    inflight: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    delivered_epoch: AtomicU64,
    delivered_valid: AtomicBool,
    iface: String,
}

impl WorkerCollector {
    pub fn start(ifaces: Ifaces) -> Result<Self> {
        let iface = ifaces.spec().to_owned();
        Self::spawn(iface, move |requests, cache, epoch| {
            let mut collector = Collector::new(ifaces);
            let mut state = Cache::default();
            let mut baseline_epoch = 0;
            let mut baseline_at = None;
            while let Ok(request) = requests.recv() {
                let wanted = epoch.load(Ordering::Acquire);
                if wanted != baseline_epoch {
                    collector.begin_session_baseline();
                    baseline_at = Some(Instant::now());
                    baseline_epoch = wanted;
                    state.metrics = Metrics::default();
                    state.metrics_epoch = wanted;
                    state.metrics_valid = false;
                }
                match request.kind {
                    Kind::Facts => {
                        state.facts = collector.facts();
                        state.facts_valid = true;
                    }
                    Kind::Metrics => {
                        // Even if the caller's baseline request timed out or
                        // found a busy worker, never publish a baseline's zero
                        // rates or a previous session's average as a sample.
                        if baseline_at.is_none()
                            || (!state.metrics_valid
                                && baseline_at.is_some_and(|at| at.elapsed() > BASELINE_INTERVAL * 2))
                        {
                            collector.begin_session_baseline();
                            baseline_at = Some(Instant::now());
                        }
                        if let Some(at) = baseline_at {
                            std::thread::sleep(BASELINE_INTERVAL.saturating_sub(at.elapsed()));
                        }
                        let metrics = collector.collect();
                        if collector.sample_valid && epoch.load(Ordering::Acquire) == wanted {
                            state.metrics = metrics;
                            state.metrics_epoch = wanted;
                            state.metrics_valid = true;
                        }
                    }
                    Kind::Baseline => {}
                }
                // Do not hold a watch borrow across OS APIs or the sleep.
                cache.send_replace(state.clone());
                let Request { done, _permit, .. } = request;
                // Release admission before waking the caller. If its timeout
                // already expired, the slot is still released here, not there.
                drop(_permit);
                let _ = done.send(());
            }
        })
    }

    fn spawn(
        iface: String,
        run: impl FnOnce(mpsc::Receiver<Request>, watch::Sender<Cache>, Arc<AtomicU64>) + Send + 'static,
    ) -> Result<Self> {
        let (requests, receiver) = mpsc::sync_channel(1);
        let (cache_tx, cache) = watch::channel(Cache::default());
        let epoch = Arc::new(AtomicU64::new(0));
        let worker_epoch = Arc::clone(&epoch);
        std::thread::Builder::new()
            .name("monitor-collector".into())
            .spawn(move || run(receiver, cache_tx, worker_epoch))?;
        Ok(Self {
            requests,
            cache,
            inflight: Arc::new(AtomicBool::new(false)),
            epoch,
            delivered_epoch: AtomicU64::new(0),
            delivered_valid: AtomicBool::new(false),
            iface,
        })
    }

    async fn request(&self, kind: Kind) {
        if self.inflight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        let permit = Permit(Arc::clone(&self.inflight));
        let (done, response) = oneshot::channel();
        let request = Request { kind, done, _permit: permit };
        // Never wait for queue space. On failure, Request's permit is dropped.
        if self.requests.try_send(request).is_ok() {
            let _ = tokio::time::timeout(REQUEST_TIMEOUT, response).await;
        }
    }

    /// Failure/timeout is deliberately represented by the last snapshot or a
    /// default, never Err: optional host metrics must not end a hub session.
    pub async fn facts(&self) -> Result<Facts> {
        self.request(Kind::Facts).await;
        Ok(if self.has_facts() { self.cache.borrow().facts.clone() } else { Facts::default() })
    }

    pub async fn collect(&self) -> Result<Metrics> {
        self.request(Kind::Metrics).await;
        let cache = self.cache.borrow();
        let current_epoch = self.epoch.load(Ordering::Acquire);
        let valid = cache.metrics_valid && cache.metrics_epoch == current_epoch;
        let mut metrics = if valid { cache.metrics.clone() } else { Metrics::default() };
        metrics.iface.clone_from(&self.iface);
        // A worker completion between collect() and has_sample() must not turn
        // the default just returned to the caller into a "valid" report.
        self.delivered_valid.store(false, Ordering::Release);
        self.delivered_epoch.store(current_epoch, Ordering::Release);
        self.delivered_valid.store(valid, Ordering::Release);
        Ok(metrics)
    }

    /// True only if the last collect() returned an actual current-session
    /// sample. A background cache update alone cannot validate a default that
    /// the caller already received. Call collect(), then check this flag.
    pub fn has_sample(&self) -> bool {
        let cache = self.cache.borrow();
        let current_epoch = self.epoch.load(Ordering::Acquire);
        cache.metrics_valid
            && cache.metrics_epoch == current_epoch
            && self.delivered_valid.load(Ordering::Acquire)
            && self.delivered_epoch.load(Ordering::Acquire) == current_epoch
    }

    pub fn has_facts(&self) -> bool {
        self.cache.borrow().facts_valid
    }

    pub async fn begin_session_baseline(&self) -> Result<()> {
        // Epoch is out-of-band: a busy/full queue cannot lose a reset. Old
        // metrics are immediately invisible, even before the worker finishes.
        self.delivered_valid.store(false, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.request(Kind::Baseline).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn windows_worker_publishes_only_after_a_real_session_baseline_interval() {
        let worker = WorkerCollector::start(Ifaces::default()).unwrap();
        let requested = Instant::now();
        worker.begin_session_baseline().await.unwrap();
        assert!(!worker.has_sample());
        // The caller's baseline completion may time out; the worker still owns
        // the same reset and must enforce its one-second interval itself.
        for _ in 0..100 {
            worker.collect().await.unwrap();
            if worker.has_sample() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(worker.has_sample(), "Windows collection must finish within the test budget");
        assert!(requested.elapsed() >= BASELINE_INTERVAL);
        worker.begin_session_baseline().await.unwrap();
        assert!(!worker.has_sample(), "a reconnect must invalidate the old sample immediately");
    }

    // Tokio's paused clock may reach a deadline before the OS schedules the
    // worker. Do not use a virtual sleep as evidence of real-thread progress.
    // Explicit, bounded handshakes make every detached assertion observable.
    const THREAD_DEADLINE: Duration = Duration::from_secs(10);

    struct BlockedWorker {
        collector: WorkerCollector,
        release: mpsc::SyncSender<()>,
        started: mpsc::Receiver<()>,
        finished: mpsc::Receiver<()>,
    }

    impl BlockedWorker {
        fn new(initial: Cache) -> Self {
            let (release, blocked) = mpsc::sync_channel(1);
            let (started_tx, started) = mpsc::sync_channel(1);
            let (finished_tx, finished) = mpsc::sync_channel(1);
            let collector = WorkerCollector::spawn("Ethernet".into(), move |requests, cache, _| {
                cache.send_replace(initial);
                let request = requests.recv_timeout(THREAD_DEADLINE).unwrap();
                started_tx.send(()).unwrap();
                // Dropping release during a failed test also unblocks cleanup.
                let _ = blocked.recv_timeout(THREAD_DEADLINE);
                assert!(requests.try_recv().is_err(), "a timeout must not enqueue more work");
                drop(request);
                finished_tx.send(()).unwrap();
            })
            .unwrap();
            Self { collector, release, started, finished }
        }

        fn wait_started(&self) {
            self.started.recv_timeout(THREAD_DEADLINE).unwrap();
        }

        fn finish(self) {
            self.release.send(()).unwrap();
            self.finished.recv_timeout(THREAD_DEADLINE).unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_keep_exactly_one_real_request() {
        let worker = BlockedWorker::new(Cache::default());
        // First facts timeout returns a default instead of ending the agent.
        assert_eq!(worker.collector.facts().await.unwrap(), Facts::default());
        worker.wait_started();
        assert!(!worker.collector.has_facts());
        assert!(!worker.collector.has_sample());
        assert!(worker.collector.inflight.load(Ordering::Acquire));
        for _ in 0..100 {
            assert_eq!(worker.collector.collect().await.unwrap().iface, "Ethernet");
            worker.collector.begin_session_baseline().await.unwrap();
            assert!(worker.collector.inflight.load(Ordering::Acquire));
        }
        worker.finish();
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_collector_does_not_join_a_blocked_worker() {
        let worker = BlockedWorker::new(Cache::default());
        worker.collector.facts().await.unwrap();
        worker.wait_started();
        let BlockedWorker { collector, release, finished, .. } = worker;
        // Drop on a separate thread, so a regression that joins cannot hang
        // the entire test process. The worker remains blocked until confirmed.
        let (dropped_tx, dropped) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            drop(collector);
            dropped_tx.send(()).unwrap();
        });
        let outcome = dropped.recv_timeout(THREAD_DEADLINE);
        release.send(()).unwrap();
        finished.recv_timeout(THREAD_DEADLINE).unwrap();
        outcome.expect("dropping the collector waited for a blocked OS call");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_caller_cannot_release_a_running_os_call() {
        let worker = BlockedWorker::new(Cache::default());
        // The outer deadline cancels the future before request()'s own timeout.
        assert!(tokio::time::timeout(Duration::from_millis(1), worker.collector.facts()).await.is_err());
        worker.wait_started();
        assert!(worker.collector.inflight.load(Ordering::Acquire));
        worker.collector.collect().await.unwrap();
        assert!(worker.collector.inflight.load(Ordering::Acquire));
        assert!(!worker.collector.has_sample());
        worker.finish();
    }

    #[tokio::test]
    async fn disconnected_worker_returns_defaults_and_releases_admission() {
        let (exited, receiver) = mpsc::sync_channel(1);
        let worker = WorkerCollector::spawn(String::new(), move |requests, cache, epoch| {
            // Notify only after the receiver has actually closed. A signal
            // sent before dropping it races the caller's try_send/admission.
            drop(requests);
            drop(cache);
            drop(epoch);
            exited.send(()).unwrap();
        })
        .unwrap();
        receiver.recv_timeout(THREAD_DEADLINE).unwrap();
        assert_eq!(worker.facts().await.unwrap(), Facts::default());
        assert!(!worker.has_facts());
        assert!(!worker.has_sample());
        assert!(!worker.inflight.load(Ordering::Acquire));
        worker.begin_session_baseline().await.unwrap();
        assert_eq!(worker.collect().await.unwrap(), Metrics::default());
    }

    #[tokio::test(start_paused = true)]
    async fn cache_completion_cannot_validate_a_default_already_returned_to_caller() {
        let (publish, publish_rx) = mpsc::sync_channel(1);
        let (published_tx, published) = mpsc::sync_channel(1);
        let (finish, finish_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished) = mpsc::sync_channel(1);
        let worker = WorkerCollector::spawn(String::new(), move |requests, cache, _| {
            let request = requests.recv_timeout(THREAD_DEADLINE).unwrap();
            publish_rx.recv_timeout(THREAD_DEADLINE).unwrap();
            cache.send_replace(Cache {
                metrics: Metrics { cpu: 42.0, ..Metrics::default() },
                metrics_valid: true,
                ..Cache::default()
            });
            published_tx.send(()).unwrap();
            finish_rx.recv_timeout(THREAD_DEADLINE).unwrap();
            drop(request);
            finished_tx.send(()).unwrap();
        })
        .unwrap();
        let first = worker.collect().await.unwrap();
        assert_eq!(first, Metrics::default());
        assert!(!worker.has_sample());
        publish.send(()).unwrap();
        published.recv_timeout(THREAD_DEADLINE).unwrap();
        assert!(!worker.has_sample(), "the caller still holds a default, not the new cache");
        let second = worker.collect().await.unwrap();
        assert_eq!(second.cpu, 42.0);
        assert!(worker.has_sample());
        finish.send(()).unwrap();
        finished.recv_timeout(THREAD_DEADLINE).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_hides_old_cache_even_if_worker_is_still_busy() {
        let worker = BlockedWorker::new(Cache {
            metrics: Metrics { cpu: 99.0, load: [99.0; 3], ..Metrics::default() },
            metrics_epoch: 0,
            metrics_valid: true,
            ..Cache::default()
        });
        worker.collector.facts().await.unwrap();
        worker.wait_started();
        assert_eq!(worker.collector.collect().await.unwrap().cpu, 99.0);
        assert!(worker.collector.has_sample());
        worker.collector.begin_session_baseline().await.unwrap();
        assert!(!worker.collector.has_sample());
        let metrics = worker.collector.collect().await.unwrap();
        assert_eq!(metrics.cpu, 0.0);
        assert_eq!(metrics.load, [0.0; 3]);
        worker.finish();
    }
}
