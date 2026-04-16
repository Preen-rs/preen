use crate::dashboard::{CheckSeverity, DashboardSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckListItemView {
    pub passed: bool,
    pub label: String,
    pub severity_label: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckListView {
    pub total_checks: usize,
    pub items: Vec<CheckListItemView>,
}

impl CheckListView {
    pub fn from_snapshot(snapshot: &DashboardSnapshot) -> Self {
        let items = snapshot
            .checks
            .iter()
            .map(|check| CheckListItemView {
                passed: check.passed,
                label: check.label.clone(),
                severity_label: severity_label(&check.severity).to_string(),
                message: check.message.clone(),
            })
            .collect::<Vec<_>>();

        Self {
            total_checks: items.len(),
            items,
        }
    }
}

fn severity_label(severity: &CheckSeverity) -> &'static str {
    match severity {
        CheckSeverity::Critical => "critical",
        CheckSeverity::Warning => "warning",
    }
}
