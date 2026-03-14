use std::path::PathBuf;

use preen_core::config::AppConfig;
use preen_core::error::CoreError;
use preen_core::rules;
use preen_core::{
    CleanableItem, Command, CoreService, Event, FileSystemPort, ItemCategory, ScanResult,
};

use async_trait::async_trait;
use tokio::runtime::Runtime;
use tokio::time::Duration;

#[derive(Clone)]
struct MockFileSystemPort {
    scan_result: Result<ScanResult, CoreError>,
    prepare_clean_result: Result<Vec<CleanableItem>, CoreError>,
    clean_result: Result<u64, CoreError>,
    undo_clean_result: Result<(), CoreError>,
}

#[async_trait]
impl FileSystemPort for MockFileSystemPort {
    async fn scan_cleanable_items(
        &self,
        _rules: &[rules::ScanRule],
        _config: &AppConfig,
    ) -> Result<ScanResult, CoreError> {
        self.scan_result.clone()
    }

    async fn prepare_clean(
        &self,
        items: &[CleanableItem],
    ) -> Result<Vec<CleanableItem>, CoreError> {
        self.prepare_clean_result.clone().map(|_| items.to_vec())
    }

    async fn clean_items(&self, _item_ids: &[String]) -> Result<u64, CoreError> {
        self.clean_result.clone()
    }

    async fn undo_clean(&self, _items: &[CleanableItem]) -> Result<(), CoreError> {
        self.undo_clean_result.clone()
    }
}

fn run_test<F: std::future::Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap();
    rt.block_on(f)
}

#[test]
fn test_core_service_start_and_quit() {
    run_test(async {
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: vec![],
            }),
            prepare_clean_result: Ok(vec![]),
            clean_result: Ok(0),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::Quit);

        let event = receiver.recv().unwrap();
        assert!(matches!(event, Event::Shutdown));
    });
}

#[test]
fn test_start_scan_success() {
    run_test(async {
        let rules = vec![rules::ScanRule {
            id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            category: ItemCategory::Cache,
            path_pattern: "/tmp".to_string(),
            strategy: rules::ScanStrategy::Shallow,
            description: "A test rule".to_string(),
        }];
        let mock_result = ScanResult {
            executed_rules: rules.clone(),
            total_size: 1024,
            items: vec![CleanableItem {
                rule_id: "test-rule".to_string(),
                id: "1".to_string(),
                category: ItemCategory::Cache,
                path: PathBuf::from("/tmp/cache"),
                size: 1024,
                description: "Test cache file".to_string(),
                can_undo: true,
                undo_info: Some("/tmp/cache.bak".to_string()),
            }],
        };
        let mock_port = MockFileSystemPort {
            scan_result: Ok(mock_result.clone()),
            prepare_clean_result: Ok(vec![]),
            clean_result: Ok(0),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::StartScan(rules));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.0, _) | Event::Progress(0.0, _)
        ));

        let event = receiver.recv().unwrap();
        match event {
            Event::ScanCompleted(result) => assert_eq!(result.total_size, 1024),
            _ => panic!("Expected ScanCompleted event, got {event:?}"),
        }

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}

#[test]
fn test_clean_selected_success() {
    run_test(async {
        let items_to_clean = vec![CleanableItem {
            rule_id: "test-rule".to_string(),
            id: "1".to_string(),
            category: ItemCategory::Cache,
            path: PathBuf::from("/tmp/cache"),
            size: 100,
            description: "Test cache file".to_string(),
            can_undo: true,
            undo_info: Some("/tmp/cache.bak".to_string()),
        }];
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: items_to_clean.clone(),
            }),
            prepare_clean_result: Ok(items_to_clean.clone()),
            clean_result: Ok(100),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::StartScan(vec![]));
        receiver.recv().unwrap();
        receiver.recv().unwrap();

        handle.send_command(Command::CleanSelected(vec!["1".to_string()]));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.0, _) | Event::Progress(0.0, _)
        ));
        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.5, _) | Event::Progress(0.5, _)
        ));

        let event = receiver.recv().unwrap();
        match event {
            Event::CleanCompleted(freed) => assert_eq!(freed, 100),
            _ => panic!("Expected CleanCompleted event, got {event:?}"),
        }

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}

#[test]
fn test_undo_clean_success() {
    run_test(async {
        let cleaned_item = CleanableItem {
            rule_id: "test-rule".to_string(),
            id: "1".to_string(),
            category: ItemCategory::Cache,
            path: PathBuf::from("/tmp/cache"),
            size: 100,
            description: "Test cache file".to_string(),
            can_undo: true,
            undo_info: Some("/tmp/cache.bak".to_string()),
        };
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: vec![cleaned_item.clone()],
            }),
            prepare_clean_result: Ok(vec![cleaned_item.clone()]),
            clean_result: Ok(100),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::StartScan(vec![]));
        receiver.recv().unwrap();
        receiver.recv().unwrap();
        handle.send_command(Command::CleanSelected(vec!["1".to_string()]));
        receiver.recv().unwrap();
        receiver.recv().unwrap();
        receiver.recv().unwrap();

        handle.send_command(Command::UndoClean(vec!["1".to_string()]));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.0, _) | Event::Progress(0.0, _)
        ));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(1.0, _) | Event::Progress(1.0, _)
        ));

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}

#[test]
fn test_schedule_scan() {
    run_test(async {
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: vec![],
            }),
            prepare_clean_result: Ok(vec![]),
            clean_result: Ok(0),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        let rules = vec![rules::ScanRule {
            id: "scheduled-rule".to_string(),
            name: "Scheduled Rule".to_string(),
            category: ItemCategory::Cache,
            path_pattern: "/tmp".to_string(),
            strategy: rules::ScanStrategy::Shallow,
            description: "A scheduled test rule".to_string(),
        }];

        handle.send_command(Command::ScheduleScan(
            "Daily Scan".to_string(),
            Duration::from_secs(1),
            rules.clone(),
        ));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.0, _) | Event::Progress(0.0, _)
        ));

        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut scan_completed = false;
        for _ in 0..5 {
            let event = receiver.recv().unwrap();
            if matches!(event, Event::ScanCompleted(_)) {
                scan_completed = true;
                break;
            }
        }
        assert!(scan_completed);

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}

#[test]
fn test_undo_clean_failure_emits_structured_event() {
    run_test(async {
        let cleaned_item = CleanableItem {
            rule_id: "test-rule".to_string(),
            id: "1".to_string(),
            category: ItemCategory::Cache,
            path: PathBuf::from("/tmp/cache"),
            size: 100,
            description: "Test cache file".to_string(),
            can_undo: true,
            undo_info: Some("/tmp/cache.bak".to_string()),
        };
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: vec![cleaned_item.clone()],
            }),
            prepare_clean_result: Ok(vec![cleaned_item.clone()]),
            clean_result: Ok(100),
            undo_clean_result: Err(CoreError::Os {
                message: "ambiguous trash candidates for 1 (count=2)".to_string(),
            }),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::StartScan(vec![]));
        receiver.recv().unwrap();
        receiver.recv().unwrap();
        handle.send_command(Command::CleanSelected(vec!["1".to_string()]));
        receiver.recv().unwrap();
        receiver.recv().unwrap();
        receiver.recv().unwrap();

        handle.send_command(Command::UndoClean(vec!["1".to_string()]));

        let event = receiver.recv().unwrap();
        assert!(matches!(
            event,
            Event::ProgressKey(0.0, _) | Event::Progress(0.0, _)
        ));

        let event = receiver.recv().unwrap();
        match event {
            Event::UndoFailed {
                code,
                user_message,
                message,
            } => {
                assert_eq!(code, "undo_ambiguous");
                assert!(user_message.contains("matching trash entries"));
                assert!(message.contains("ambiguous trash candidates"));
            }
            _ => panic!("Expected UndoFailed event, got {event:?}"),
        }

        let event = receiver.recv().unwrap();
        match event {
            Event::Error(message) => assert!(message.contains("Undo failed:")),
            _ => panic!("Expected Error event, got {event:?}"),
        }

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}

#[test]
fn test_request_history_and_statistics() {
    run_test(async {
        let mock_port = MockFileSystemPort {
            scan_result: Ok(ScanResult {
                executed_rules: vec![],
                total_size: 0,
                items: vec![],
            }),
            prepare_clean_result: Ok(vec![]),
            clean_result: Ok(0),
            undo_clean_result: Ok(()),
        };
        let (handle, receiver) = CoreService::start(mock_port);

        handle.send_command(Command::RequestHistory);
        let event = receiver.recv().unwrap();
        assert!(matches!(event, Event::History(_)));

        handle.send_command(Command::RequestStatistics);
        let event = receiver.recv().unwrap();
        assert!(matches!(event, Event::Statistics(_)));

        handle.send_command(Command::Quit);
        receiver.recv().unwrap();
    });
}
