use crate::model::{DashboardSnapshot, PluginActionKind};
use preen_core::dashboard_provider::DashboardProvider;
use preen_core::dashboard_service::DashboardApplicationService;
use preen_os::dashboard::SnapshotCollector;
use preen_os::plugin_command::{PluginCommandOutput, run_plugin_cli_command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug)]
pub enum WorkerEvent {
    Snapshot(Box<DashboardSnapshot>),
    Error(String),
    PluginActionResult {
        action: PluginActionKind,
        ok: bool,
        lines: Vec<String>,
    },
}

#[derive(Debug)]
pub enum WorkerCommand {
    RefreshNow,
    RunPluginAction {
        action: PluginActionKind,
        spec: Option<String>,
    },
    Shutdown,
}

pub struct StatusWorker {
    command_tx: Sender<WorkerCommand>,
    join_handle: Option<JoinHandle<()>>,
}

type PluginCommandRunner =
    Arc<dyn Fn(PluginActionKind, Option<&str>) -> PluginCommandOutput + Send + Sync>;

impl StatusWorker {
    pub fn spawn(interval: Duration) -> (Self, Receiver<WorkerEvent>) {
        Self::spawn_with_provider(interval, Box::new(SnapshotCollector::new()))
    }

    pub fn spawn_with_provider(
        interval: Duration,
        provider: Box<dyn DashboardProvider>,
    ) -> (Self, Receiver<WorkerEvent>) {
        Self::spawn_with_provider_and_runner(interval, provider, Arc::new(run_plugin_cli_command))
    }

    pub(crate) fn spawn_with_provider_and_runner(
        interval: Duration,
        provider: Box<dyn DashboardProvider>,
        plugin_runner: PluginCommandRunner,
    ) -> (Self, Receiver<WorkerEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();

        let join_handle = thread::spawn(move || {
            run_worker_loop(interval, command_rx, event_tx, provider, plugin_runner)
        });

        (
            Self {
                command_tx,
                join_handle: Some(join_handle),
            },
            event_rx,
        )
    }

    pub fn refresh_now(&self) {
        let _ = self.command_tx.send(WorkerCommand::RefreshNow);
    }

    pub fn run_plugin_action(&self, action: PluginActionKind, spec: Option<String>) {
        let _ = self
            .command_tx
            .send(WorkerCommand::RunPluginAction { action, spec });
    }

    pub fn shutdown(&mut self) {
        let _ = self.command_tx.send(WorkerCommand::Shutdown);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_worker_loop(
    interval: Duration,
    command_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
    provider: Box<dyn DashboardProvider>,
    plugin_runner: PluginCommandRunner,
) {
    let mut service = DashboardApplicationService::new(provider);
    let plugin_action_running = Arc::new(AtomicBool::new(false));
    loop {
        match service.next_snapshot() {
            Ok(snapshot) => {
                if event_tx
                    .send(WorkerEvent::Snapshot(Box::new(snapshot)))
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                if event_tx
                    .send(WorkerEvent::Error(error.to_string()))
                    .is_err()
                {
                    break;
                }
            }
        }

        match command_rx.recv_timeout(interval) {
            Ok(WorkerCommand::RefreshNow) => continue,
            Ok(WorkerCommand::RunPluginAction { action, spec }) => {
                if plugin_action_running.swap(true, Ordering::SeqCst) {
                    if event_tx
                        .send(WorkerEvent::Error(
                            "plugin action already running".to_string(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                let event_tx_for_plugin = event_tx.clone();
                let plugin_runner = Arc::clone(&plugin_runner);
                let plugin_action_running = Arc::clone(&plugin_action_running);
                thread::spawn(move || {
                    let output = plugin_runner(action, spec.as_deref());
                    plugin_action_running.store(false, Ordering::SeqCst);
                    let _ = event_tx_for_plugin.send(WorkerEvent::PluginActionResult {
                        action,
                        ok: output.ok,
                        lines: output.lines,
                    });
                });
                continue;
            }
            Ok(WorkerCommand::Shutdown) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use preen_core::dashboard::{
        DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
        DashboardSnapshot, RegistrySummary,
    };
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;

    struct TestProvider {
        seq: u8,
    }

    impl DashboardProvider for TestProvider {
        fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            let score = self.seq;
            self.seq = self.seq.saturating_add(1);
            Ok(snapshot_with_health(score))
        }
    }

    struct FlakyProvider {
        first_call_failed: bool,
        next_score: u8,
    }

    impl DashboardProvider for FlakyProvider {
        fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String> {
            if !self.first_call_failed {
                self.first_call_failed = true;
                return Err("transient snapshot failure".to_string());
            }
            let score = self.next_score;
            self.next_score = self.next_score.saturating_add(1);
            Ok(snapshot_with_health(score))
        }
    }

    fn snapshot_with_health(score: u8) -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen-state"),
            health_score: score,
            overall_passed: true,
            plugin_count: 0,
            installed_plugins_on_disk: 0,
            checks: Vec::new(),
            warnings: Vec::new(),
            suggested_actions: Vec::new(),
            registry: RegistrySummary::default(),
            metrics: DashboardMetrics::default(),
            plugins: Vec::new(),
        }
    }

    #[test]
    fn refresh_now_emits_next_snapshot_immediately() {
        let provider = Box::new(TestProvider { seq: 42 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);

        let first = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first event");
        let WorkerEvent::Snapshot(first_snapshot) = first else {
            panic!("expected first snapshot event");
        };
        assert_eq!(first_snapshot.health_score, 42);

        let start = Instant::now();
        worker.refresh_now();
        let second = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second event");
        let WorkerEvent::Snapshot(second_snapshot) = second else {
            panic!("expected refreshed snapshot event");
        };
        assert_eq!(second_snapshot.health_score, 43);
        assert!(start.elapsed() < Duration::from_secs(2));

        worker.shutdown();
    }

    #[test]
    fn plugin_action_uses_injected_runner() {
        let provider = Box::new(TestProvider { seq: 1 });
        let captured = Arc::new(Mutex::new(Vec::<(PluginActionKind, Option<String>)>::new()));
        let captured_for_runner = Arc::clone(&captured);
        let runner: PluginCommandRunner = Arc::new(move |action, spec| {
            captured_for_runner
                .lock()
                .expect("lock captured runner calls")
                .push((action, spec.map(ToString::to_string)));
            PluginCommandOutput {
                ok: true,
                lines: vec!["ok".to_string()],
            }
        });

        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider_and_runner(Duration::from_secs(60), provider, runner);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        worker.run_plugin_action(
            PluginActionKind::Info,
            Some("preen-rs.homebrew@1.0.7".to_string()),
        );

        let started = Instant::now();
        let event = loop {
            assert!(started.elapsed() < Duration::from_secs(2));
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::PluginActionResult { action, ok, lines }) => {
                    break (action, ok, lines);
                }
                Ok(WorkerEvent::Snapshot(_)) => {}
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!("worker disconnected"),
            }
        };
        let (action, ok, lines) = event;
        assert_eq!(action, PluginActionKind::Info);
        assert!(ok);
        assert_eq!(lines, vec!["ok".to_string()]);

        let calls = captured.lock().expect("lock captured calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, PluginActionKind::Info);
        assert_eq!(calls[0].1.as_deref(), Some("preen-rs.homebrew@1.0.7"));

        worker.shutdown();
    }

    #[test]
    fn shutdown_stops_event_stream() {
        let provider = Box::new(TestProvider { seq: 10 });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_millis(100), provider);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");
        worker.shutdown();
        match event_rx.recv_timeout(Duration::from_millis(300)) {
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {}
            Ok(_) => panic!("unexpected event after shutdown"),
        }
    }

    #[test]
    fn worker_recovers_after_transient_snapshot_error() {
        let provider = Box::new(FlakyProvider {
            first_call_failed: false,
            next_score: 80,
        });
        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider(Duration::from_secs(60), provider);

        let first = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first worker event");
        let WorkerEvent::Error(error) = first else {
            panic!("expected initial transient error");
        };
        assert!(error.contains("transient snapshot failure"));

        worker.refresh_now();

        let second = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("recovered snapshot event");
        let WorkerEvent::Snapshot(snapshot) = second else {
            panic!("expected recovered snapshot event");
        };
        assert_eq!(snapshot.health_score, 80);

        worker.shutdown();
    }

    #[test]
    fn plugin_action_runs_async_without_blocking_snapshot_updates() {
        let provider = Box::new(TestProvider { seq: 1 });
        let runner: PluginCommandRunner = Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(300));
            PluginCommandOutput {
                ok: true,
                lines: vec!["done".to_string()],
            }
        });

        let (mut worker, event_rx) = StatusWorker::spawn_with_provider_and_runner(
            Duration::from_millis(50),
            provider,
            runner,
        );
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");
        worker.run_plugin_action(
            PluginActionKind::Test,
            Some("preen-rs.homebrew@1.0.7".to_string()),
        );

        let mut saw_snapshot_before_result = false;
        let mut saw_plugin_result = false;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(WorkerEvent::Snapshot(_)) => {
                    if !saw_plugin_result {
                        saw_snapshot_before_result = true;
                    }
                }
                Ok(WorkerEvent::PluginActionResult { .. }) => {
                    saw_plugin_result = true;
                    break;
                }
                Ok(WorkerEvent::Error(error)) => panic!("unexpected worker error: {error}"),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(saw_snapshot_before_result);
        assert!(saw_plugin_result);
        worker.shutdown();
    }

    #[test]
    fn worker_rejects_concurrent_plugin_actions() {
        let provider = Box::new(TestProvider { seq: 1 });
        let runner: PluginCommandRunner = Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(350));
            PluginCommandOutput {
                ok: true,
                lines: vec!["done".to_string()],
            }
        });

        let (mut worker, event_rx) =
            StatusWorker::spawn_with_provider_and_runner(Duration::from_secs(60), provider, runner);
        let _ = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("initial snapshot");

        let spec = Some("preen-rs.homebrew@1.0.7".to_string());
        worker.run_plugin_action(PluginActionKind::Preflight, spec.clone());
        worker.run_plugin_action(PluginActionKind::Install, spec);

        let mut saw_busy_error = false;
        let mut saw_any_result = false;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            match event_rx.recv_timeout(Duration::from_millis(300)) {
                Ok(WorkerEvent::Error(error)) => {
                    if error.contains("already running") {
                        saw_busy_error = true;
                    }
                }
                Ok(WorkerEvent::PluginActionResult { .. }) => {
                    saw_any_result = true;
                    if saw_busy_error {
                        break;
                    }
                }
                Ok(WorkerEvent::Snapshot(_)) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(saw_busy_error);
        assert!(saw_any_result);
        worker.shutdown();
    }
}
