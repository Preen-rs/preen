use async_trait::async_trait;
use preen_core::action_runtime::{ActionRisk, ExecutionMode};
use preen_core::smart_care::{
    PluginSmartCareAnalysis, PluginSmartCareExecuteRequest, PluginSmartCareExecutionResult,
    PluginSmartCareUndoResult, SmartCareAnalyzeRequest, SmartCareCapability,
    SmartCareCapabilitySelection, SmartCareCapabilityStatus, SmartCareCheckResult,
    SmartCareCheckStatus, SmartCareDescriptorSource, SmartCareError, SmartCareExecuteRequest,
    SmartCareOrchestrator, SmartCarePluginDescriptor, SmartCarePluginPort, SmartCarePreview,
    SmartCareProfile, SmartCareTask, SmartCareTaskExecutionResult, SmartCareUndoRequest,
    build_preview_from_descriptors, classify_capability_descriptor_source,
    classify_descriptor_pack_source, default_pack_id_for_capability, descriptors_from_plugin_rules,
    preferred_plugin_spec_for_capability,
};
use preen_core::{
    ItemCategory,
    plugin::{ActionSpec, ActionType, Capability, MatchMode, MatchSpec, RiskLevel, RuleFile},
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

struct MockPluginEngine {
    descriptor: SmartCarePluginDescriptor,
    analysis: PluginSmartCareAnalysis,
    restored_items: u64,
    execute_calls: Arc<Mutex<Vec<Vec<String>>>>,
    undo_calls: Arc<Mutex<u64>>,
}

impl MockPluginEngine {
    fn new(
        descriptor: SmartCarePluginDescriptor,
        analysis: PluginSmartCareAnalysis,
        restored_items: u64,
        execute_calls: Arc<Mutex<Vec<Vec<String>>>>,
        undo_calls: Arc<Mutex<u64>>,
    ) -> Self {
        Self {
            descriptor,
            analysis,
            restored_items,
            execute_calls,
            undo_calls,
        }
    }
}

#[async_trait]
impl SmartCarePluginPort for MockPluginEngine {
    fn descriptor(&self) -> SmartCarePluginDescriptor {
        self.descriptor.clone()
    }

    async fn analyze(
        &self,
        _request: SmartCareAnalyzeRequest,
    ) -> Result<PluginSmartCareAnalysis, String> {
        Ok(self.analysis.clone())
    }

    async fn execute(
        &self,
        request: PluginSmartCareExecuteRequest,
    ) -> Result<PluginSmartCareExecutionResult, String> {
        let task_ids = request.tasks.iter().map(|task| task.id.clone()).collect();
        self.execute_calls
            .lock()
            .expect("execute call lock")
            .push(task_ids);

        let task_results = request
            .tasks
            .into_iter()
            .map(|task| SmartCareTaskExecutionResult {
                task_id: task.id,
                capability: task.capability,
                plugin_pack_id: self.descriptor.pack_id.clone(),
                succeeded: true,
                affected_items: 1,
                freed_bytes: task.estimated_freed_bytes.unwrap_or(0),
                message: None,
                warnings: Vec::new(),
            })
            .collect();

        Ok(PluginSmartCareExecutionResult {
            task_results,
            warnings: Vec::new(),
        })
    }

    async fn undo(
        &self,
        _request: SmartCareUndoRequest,
    ) -> Result<PluginSmartCareUndoResult, String> {
        let mut guard = self.undo_calls.lock().expect("undo call lock");
        *guard = guard.saturating_add(1);
        Ok(PluginSmartCareUndoResult {
            restored_items: self.restored_items,
            warnings: Vec::new(),
        })
    }
}

fn build_analysis(
    pack_id: &str,
    capability: SmartCareCapability,
    task_ids: &[&str],
    estimate: u64,
) -> PluginSmartCareAnalysis {
    PluginSmartCareAnalysis {
        checks: vec![SmartCareCheckResult {
            id: format!("{pack_id}:check"),
            label: format!("{pack_id} status"),
            capability,
            plugin_pack_id: pack_id.to_string(),
            status: SmartCareCheckStatus::Passed,
            message: "ok".to_string(),
        }],
        tasks: task_ids
            .iter()
            .map(|task_id| {
                let mut task = SmartCareTask::new(
                    (*task_id).to_string(),
                    format!("{pack_id} task {task_id}"),
                    capability,
                    pack_id,
                    ActionRisk::Low,
                );
                task.estimated_freed_bytes = Some(estimate);
                task
            })
            .collect(),
        warnings: Vec::new(),
        estimated_freed_bytes: estimate,
    }
}

fn descriptor(pack_id: &str, capability: SmartCareCapability) -> SmartCarePluginDescriptor {
    SmartCarePluginDescriptor {
        pack_id: pack_id.to_string(),
        capability,
        enabled: true,
        trusted_identity: Some("https://example.com/workflow".to_string()),
        version: Some("1.0.0".to_string()),
    }
}

fn preview_profile() -> SmartCareProfile {
    SmartCareProfile {
        id: "smart-care.default".to_string(),
        name: "Smart Care".to_string(),
        capabilities: vec![
            SmartCareCapabilitySelection::enabled(SmartCareCapability::Cleanup),
            SmartCareCapabilitySelection::enabled(SmartCareCapability::Performance),
            SmartCareCapabilitySelection::enabled(SmartCareCapability::Applications),
            SmartCareCapabilitySelection::enabled(SmartCareCapability::Protection),
        ],
    }
}

#[test]
fn preview_marks_ready_and_blocked_capabilities() {
    let profile = preview_profile();
    let descriptors = vec![
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.performance.base".to_string(),
            capability: SmartCareCapability::Performance,
            enabled: true,
            trusted_identity: None,
            version: Some("1.0.0".to_string()),
        },
    ];

    let preview: SmartCarePreview = build_preview_from_descriptors(&profile, &descriptors);
    let cleanup = preview
        .cards
        .iter()
        .find(|card| card.capability == SmartCareCapability::Cleanup)
        .expect("cleanup card");
    let performance = preview
        .cards
        .iter()
        .find(|card| card.capability == SmartCareCapability::Performance)
        .expect("performance card");
    let applications = preview
        .cards
        .iter()
        .find(|card| card.capability == SmartCareCapability::Applications)
        .expect("applications card");

    assert_eq!(cleanup.status, SmartCareCapabilityStatus::Ready);
    assert_eq!(performance.status, SmartCareCapabilityStatus::UntrustedOnly);
    assert_eq!(
        applications.status,
        SmartCareCapabilityStatus::MissingPlugin
    );
    assert!(!preview.overall_ready);
    assert!(
        preview
            .selected_plugins
            .contains(&"preen-rs.cleanup.base@1.0.0".to_string())
    );
}

#[test]
fn preview_dedups_duplicate_descriptors_from_same_pack() {
    let profile = preview_profile();
    let descriptors = vec![
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
    ];

    let preview = build_preview_from_descriptors(&profile, &descriptors);
    let cleanup = preview
        .cards
        .iter()
        .find(|card| card.capability == SmartCareCapability::Cleanup)
        .expect("cleanup card");

    assert_eq!(cleanup.plugin_count, 1);
    assert_eq!(cleanup.trusted_plugin_count, 1);
    assert_eq!(cleanup.review_count, 1);
    assert_eq!(preview.review_entries.len(), 1);
    assert_eq!(preview.selected_plugins.len(), 1);
    assert_eq!(
        cleanup.subline,
        "1 capability plugin(s) detected".to_string()
    );
}

#[test]
fn classify_capability_source_returns_expected_values() {
    let descriptors = vec![
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.extra".to_string(),
            capability: SmartCareCapability::Cleanup,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.1.0".to_string()),
        },
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.performance.base".to_string(),
            capability: SmartCareCapability::Performance,
            enabled: false,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
    ];

    let mut fallback = BTreeSet::new();
    assert_eq!(
        classify_capability_descriptor_source(
            SmartCareCapability::Applications,
            &descriptors,
            &fallback,
        ),
        SmartCareDescriptorSource::None
    );
    assert_eq!(
        classify_capability_descriptor_source(
            SmartCareCapability::Cleanup,
            &descriptors,
            &fallback
        ),
        SmartCareDescriptorSource::State
    );

    fallback.insert("preen-rs.cleanup.base".to_string());
    assert_eq!(
        classify_capability_descriptor_source(
            SmartCareCapability::Cleanup,
            &descriptors,
            &fallback
        ),
        SmartCareDescriptorSource::Mixed
    );

    fallback.insert("preen-rs.cleanup.extra".to_string());
    assert_eq!(
        classify_capability_descriptor_source(
            SmartCareCapability::Cleanup,
            &descriptors,
            &fallback
        ),
        SmartCareDescriptorSource::DevFallback
    );
}

#[test]
fn classify_pack_source_detects_dev_fallback() {
    let mut fallback = BTreeSet::new();
    fallback.insert("preen-rs.cleanup.base".to_string());

    assert_eq!(
        classify_descriptor_pack_source("preen-rs.cleanup.base", &fallback),
        SmartCareDescriptorSource::DevFallback
    );
    assert_eq!(
        classify_descriptor_pack_source("preen-rs.performance.base", &fallback),
        SmartCareDescriptorSource::State
    );
}

#[test]
fn preferred_plugin_spec_uses_trusted_descriptor_first() {
    let capability = SmartCareCapability::Cleanup;
    let descriptors = vec![
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.alt".to_string(),
            capability,
            enabled: true,
            trusted_identity: None,
            version: Some("2.0.0".to_string()),
        },
        SmartCarePluginDescriptor {
            pack_id: "preen-rs.cleanup.base".to_string(),
            capability,
            enabled: true,
            trusted_identity: Some("https://github.com/Preen-rs".to_string()),
            version: Some("1.0.0".to_string()),
        },
    ];

    let spec = preferred_plugin_spec_for_capability(capability, &descriptors);
    assert_eq!(spec, "preen-rs.cleanup.base@1.0.0");
}

#[test]
fn preferred_plugin_spec_falls_back_to_official_default_pack() {
    let spec = preferred_plugin_spec_for_capability(SmartCareCapability::Protection, &[]);
    assert_eq!(
        spec,
        default_pack_id_for_capability(SmartCareCapability::Protection)
    );
}

#[tokio::test]
async fn smart_care_analyze_aggregates_selected_capability_plugins() {
    let cleanup_calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let cleanup_undo_calls = Arc::new(Mutex::new(0));
    let apps_calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let apps_undo_calls = Arc::new(Mutex::new(0));

    let orchestrator = SmartCareOrchestrator::new(vec![
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup),
            build_analysis(
                "preen-rs.cleanup.base",
                SmartCareCapability::Cleanup,
                &["cache", "logs"],
                100,
            ),
            2,
            cleanup_calls,
            cleanup_undo_calls,
        )),
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.app.updates", SmartCareCapability::Applications),
            build_analysis(
                "preen-rs.app.updates",
                SmartCareCapability::Applications,
                &["updates"],
                300,
            ),
            1,
            apps_calls,
            apps_undo_calls,
        )),
    ])
    .expect("orchestrator");

    let request = SmartCareAnalyzeRequest {
        profile: SmartCareProfile {
            id: "smart-care.default".to_string(),
            name: "Smart Care".to_string(),
            capabilities: vec![
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Cleanup),
                SmartCareCapabilitySelection::disabled(SmartCareCapability::Performance),
                SmartCareCapabilitySelection::enabled(SmartCareCapability::Applications),
            ],
        },
        locale: "en-US".to_string(),
        require_trusted_identity: true,
    };

    let plan = orchestrator
        .analyze(request)
        .await
        .expect("analyze should pass");
    let task_ids: Vec<String> = plan.tasks.iter().map(|task| task.id.clone()).collect();

    assert_eq!(plan.profile_id, "smart-care.default");
    assert_eq!(plan.checks.len(), 2);
    assert_eq!(plan.tasks.len(), 3);
    assert_eq!(plan.selected_plugin_count, 2);
    assert!(task_ids.contains(&"preen-rs.cleanup.base:cache".to_string()));
    assert!(task_ids.contains(&"preen-rs.cleanup.base:logs".to_string()));
    assert!(task_ids.contains(&"preen-rs.app.updates:updates".to_string()));
    assert_eq!(plan.estimated_freed_bytes, 400);
}

#[tokio::test]
async fn smart_care_analyze_fails_when_no_plugin_matches_profile() {
    let orchestrator = SmartCareOrchestrator::new(vec![Box::new(MockPluginEngine::new(
        descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup),
        build_analysis(
            "preen-rs.cleanup.base",
            SmartCareCapability::Cleanup,
            &["cache"],
            100,
        ),
        1,
        Arc::new(Mutex::new(Vec::<Vec<String>>::new())),
        Arc::new(Mutex::new(0)),
    ))])
    .expect("orchestrator");

    let request = SmartCareAnalyzeRequest {
        profile: SmartCareProfile {
            id: "smart-care.default".to_string(),
            name: "Smart Care".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Applications,
            )],
        },
        locale: "en-US".to_string(),
        require_trusted_identity: true,
    };

    let error = orchestrator
        .analyze(request)
        .await
        .expect_err("no plugin for profile");
    assert_eq!(error, SmartCareError::NoActivePluginsForProfile);
}

#[tokio::test]
async fn smart_care_execute_routes_selected_tasks_to_owning_plugin() {
    let cleanup_calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let cleanup_undo_calls = Arc::new(Mutex::new(0));
    let apps_calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let apps_undo_calls = Arc::new(Mutex::new(0));

    let orchestrator = SmartCareOrchestrator::new(vec![
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup),
            build_analysis(
                "preen-rs.cleanup.base",
                SmartCareCapability::Cleanup,
                &["cache"],
                100,
            ),
            1,
            cleanup_calls.clone(),
            cleanup_undo_calls,
        )),
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.app.updates", SmartCareCapability::Applications),
            build_analysis(
                "preen-rs.app.updates",
                SmartCareCapability::Applications,
                &["updates"],
                100,
            ),
            1,
            apps_calls.clone(),
            apps_undo_calls,
        )),
    ])
    .expect("orchestrator");

    let plan = orchestrator
        .analyze(SmartCareAnalyzeRequest {
            profile: SmartCareProfile {
                id: "smart-care.default".to_string(),
                name: "Smart Care".to_string(),
                capabilities: vec![
                    SmartCareCapabilitySelection::enabled(SmartCareCapability::Cleanup),
                    SmartCareCapabilitySelection::enabled(SmartCareCapability::Applications),
                ],
            },
            locale: "en-US".to_string(),
            require_trusted_identity: true,
        })
        .await
        .expect("plan");

    let result = orchestrator
        .execute(SmartCareExecuteRequest {
            plan,
            mode: ExecutionMode::DryRun,
            selected_task_ids: vec!["preen-rs.cleanup.base:cache".to_string()],
            confirmation_token: None,
        })
        .await
        .expect("execute");

    let cleanup_call_log = cleanup_calls.lock().expect("cleanup calls");
    let apps_call_log = apps_calls.lock().expect("apps calls");
    assert_eq!(cleanup_call_log.len(), 1);
    assert_eq!(
        cleanup_call_log[0],
        vec!["preen-rs.cleanup.base:cache".to_string()]
    );
    assert!(apps_call_log.is_empty());
    assert_eq!(result.task_results.len(), 1);
    assert_eq!(
        result.task_results[0].task_id,
        "preen-rs.cleanup.base:cache"
    );
    assert_eq!(
        result.task_results[0].plugin_pack_id,
        "preen-rs.cleanup.base".to_string()
    );
}

#[tokio::test]
async fn smart_care_analyze_can_allow_untrusted_plugins_by_policy() {
    let mut untrusted = descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup);
    untrusted.trusted_identity = None;

    let orchestrator = SmartCareOrchestrator::new(vec![Box::new(MockPluginEngine::new(
        untrusted,
        build_analysis(
            "preen-rs.cleanup.base",
            SmartCareCapability::Cleanup,
            &["cache"],
            100,
        ),
        1,
        Arc::new(Mutex::new(Vec::<Vec<String>>::new())),
        Arc::new(Mutex::new(0)),
    ))])
    .expect("orchestrator");

    let request = SmartCareAnalyzeRequest {
        profile: SmartCareProfile {
            id: "smart-care.default".to_string(),
            name: "Smart Care".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        },
        locale: "en-US".to_string(),
        require_trusted_identity: false,
    };

    let plan = orchestrator.analyze(request).await.expect("analyze");
    assert_eq!(plan.selected_plugin_count, 1);
}

#[tokio::test]
async fn smart_care_analyze_fails_when_only_untrusted_plugins_are_available() {
    let mut untrusted = descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup);
    untrusted.trusted_identity = None;

    let orchestrator = SmartCareOrchestrator::new(vec![Box::new(MockPluginEngine::new(
        untrusted,
        build_analysis(
            "preen-rs.cleanup.base",
            SmartCareCapability::Cleanup,
            &["cache"],
            100,
        ),
        1,
        Arc::new(Mutex::new(Vec::<Vec<String>>::new())),
        Arc::new(Mutex::new(0)),
    ))])
    .expect("orchestrator");

    let request = SmartCareAnalyzeRequest {
        profile: SmartCareProfile {
            id: "smart-care.default".to_string(),
            name: "Smart Care".to_string(),
            capabilities: vec![SmartCareCapabilitySelection::enabled(
                SmartCareCapability::Cleanup,
            )],
        },
        locale: "en-US".to_string(),
        require_trusted_identity: true,
    };

    let error = orchestrator
        .analyze(request)
        .await
        .expect_err("untrusted filtered");
    assert_eq!(error, SmartCareError::NoTrustedPluginsForProfile);
}

#[test]
fn descriptor_derivation_prefers_manifest_hints_when_present() {
    let rules = vec![RuleFile {
        schema_version: 1,
        id: "cleanup-cache".to_string(),
        name: "Cleanup cache".to_string(),
        category: ItemCategory::Cache,
        risk: RiskLevel::Low,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec!["~/Library/Caches".to_string()],
            strategy: None,
            command: Vec::new(),
            parser: None,
        },
        action: ActionSpec {
            action_type: ActionType::TrashPaths,
            paths: vec!["~/Library/Caches".to_string()],
            command: Vec::new(),
            mode: None,
            timeout_sec: None,
            allow_globs: false,
            max_items: None,
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    }];

    let descriptors = descriptors_from_plugin_rules(
        "preen-rs.cleanup.base",
        true,
        Some("https://example.com/workflow".to_string()),
        Some("1.0.0".to_string()),
        &[Capability::SystemOptimize],
        &rules,
    );

    let capabilities = descriptors
        .iter()
        .map(|entry| entry.capability)
        .collect::<std::collections::HashSet<_>>();
    assert!(capabilities.contains(&SmartCareCapability::Performance));
    assert!(!capabilities.contains(&SmartCareCapability::Cleanup));
}

#[test]
fn descriptor_derivation_falls_back_to_pack_id_when_rules_and_manifest_are_ambiguous() {
    let rules = vec![RuleFile {
        schema_version: 1,
        id: "custom-review".to_string(),
        name: "Custom review".to_string(),
        category: ItemCategory::Other("custom".to_string()),
        risk: RiskLevel::Low,
        enabled: true,
        matcher: MatchSpec {
            mode: MatchMode::Paths,
            paths: vec!["~/tmp".to_string()],
            strategy: None,
            command: Vec::new(),
            parser: None,
        },
        action: ActionSpec {
            action_type: ActionType::RunCommand,
            paths: Vec::new(),
            command: vec!["echo".to_string(), "ok".to_string()],
            mode: None,
            timeout_sec: None,
            allow_globs: false,
            max_items: None,
            package_manager: None,
            project_types: Vec::new(),
            params: std::collections::HashMap::new(),
        },
    }];

    let descriptors = descriptors_from_plugin_rules(
        "preen-rs.protection.base",
        true,
        Some("https://example.com/workflow".to_string()),
        Some("1.0.0".to_string()),
        &[],
        &rules,
    );

    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].capability, SmartCareCapability::Protection);
    assert_eq!(descriptors[0].pack_id, "preen-rs.protection.base");
}

#[tokio::test]
async fn smart_care_undo_runs_all_enabled_plugins_when_capability_filter_is_empty() {
    let cleanup_undo_calls = Arc::new(Mutex::new(0));
    let apps_undo_calls = Arc::new(Mutex::new(0));

    let orchestrator = SmartCareOrchestrator::new(vec![
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.cleanup.base", SmartCareCapability::Cleanup),
            build_analysis(
                "preen-rs.cleanup.base",
                SmartCareCapability::Cleanup,
                &["cache"],
                100,
            ),
            2,
            Arc::new(Mutex::new(Vec::<Vec<String>>::new())),
            cleanup_undo_calls.clone(),
        )),
        Box::new(MockPluginEngine::new(
            descriptor("preen-rs.app.updates", SmartCareCapability::Applications),
            build_analysis(
                "preen-rs.app.updates",
                SmartCareCapability::Applications,
                &["updates"],
                100,
            ),
            3,
            Arc::new(Mutex::new(Vec::<Vec<String>>::new())),
            apps_undo_calls.clone(),
        )),
    ])
    .expect("orchestrator");

    let run_id = Uuid::new_v4();
    let result = orchestrator
        .undo(SmartCareUndoRequest {
            run_id,
            capabilities: Vec::new(),
        })
        .await
        .expect("undo");

    assert_eq!(result.run_id, run_id);
    assert_eq!(result.restored_items, 5);
    assert_eq!(*cleanup_undo_calls.lock().expect("cleanup undo"), 1);
    assert_eq!(*apps_undo_calls.lock().expect("apps undo"), 1);
}
