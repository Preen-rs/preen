use crate::model::DashboardSnapshot;
use preen_core::dashboard_view::DashboardViewModel;
use ratatui::text::Line;

mod build;
mod card;

pub(super) fn dashboard_lines(
    snapshot: &DashboardSnapshot,
    content_width: usize,
) -> Vec<Line<'static>> {
    let view = DashboardViewModel::from_snapshot(snapshot);
    let cards = build::build_dashboard_cards(&view);
    let mut lines = vec![
        build::dashboard_status_line(&view, content_width),
        Line::from(""),
    ];
    let mut body = card::render_dashboard_cards(&cards, content_width);
    lines.append(&mut body);
    lines
}

#[cfg(test)]
mod tests {
    use super::dashboard_lines;
    use crate::model::DashboardSnapshot;
    use preen_core::dashboard::{
        DASHBOARD_SNAPSHOT_CONTRACT, DASHBOARD_SNAPSHOT_SCHEMA_VERSION, DashboardMetrics,
        PluginRow, ProcessMetric, RegistrySummary,
    };
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn synthetic_snapshot() -> DashboardSnapshot {
        let mut metrics = DashboardMetrics {
            cpu_model: Some("Apple M2".to_string()),
            cpu_cores: Some(12),
            cpu_usage_pct: Some(42.5),
            cpu_core_usage: vec![20.0; 64],
            load_avg_1m: Some(3.2),
            load_avg_5m: Some(2.8),
            load_avg_15m: Some(2.1),
            uptime_seconds: Some(90_000),
            memory_total_bytes: Some(24 * 1024 * 1024 * 1024),
            memory_used_bytes: Some(15 * 1024 * 1024 * 1024),
            memory_used_pct: Some(62.5),
            disk_total_bytes: Some(926 * 1024 * 1024 * 1024),
            disk_available_bytes: Some(407 * 1024 * 1024 * 1024),
            disk_free_pct: Some(43.9),
            disk_filesystem: Some("apfs".to_string()),
            disk_read_rate_mbps: Some(12.5),
            disk_write_rate_mbps: Some(8.1),
            process_count: Some(900),
            top_processes: Vec::new(),
            network_rx_rate_mbps: Some(0.15),
            network_tx_rate_mbps: Some(0.08),
            network_rx_history_mbps: vec![0.05; 120],
            network_tx_history_mbps: vec![0.02; 120],
            network_proxy: Some("TUN · 192.168.4.165".to_string()),
            power_level_pct: Some(72.0),
            power_status: Some("discharging".to_string()),
            power_time_left: Some("4:12".to_string()),
            power_health: Some("Normal".to_string()),
            power_cycle_count: Some(341),
            power_capacity_pct: Some(89.0),
            battery_temperature_c: Some(30.8),
            system_power_watts: Some(26.0),
            ..DashboardMetrics::default()
        };
        for idx in 0..32 {
            metrics.top_processes.push(ProcessMetric {
                name: format!("proc-{idx}"),
                cpu_pct: 50.0 - idx as f64,
                memory_pct: 1.0 + (idx as f64 / 10.0),
            });
        }

        DashboardSnapshot {
            schema_version: DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
            contract: DASHBOARD_SNAPSHOT_CONTRACT.to_string(),
            collected_at: std::time::SystemTime::now().into(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            state_dir: PathBuf::from("/tmp/preen"),
            health_score: 91,
            overall_passed: true,
            plugin_count: 1,
            installed_plugins_on_disk: 1,
            checks: Vec::new(),
            warnings: Vec::new(),
            suggested_actions: Vec::new(),
            registry: RegistrySummary::default(),
            metrics,
            plugins: vec![PluginRow {
                pack_id: "preen-rs.homebrew".to_string(),
                version: "1.0.7".to_string(),
                source: "registry".to_string(),
                rev: "381d2c7b496b0efce4ef8be8f89a74b0ba40c647".to_string(),
                installed: true,
                trusted_identity:
                    "https://github.com/Preen-rs/preen-rulepack-homebrew/.github/workflows/release-manual.yml@refs/heads/main"
                        .to_string(),
            }],
        }
    }

    #[test]
    fn renders_dashboard_lines_for_stress_snapshot_under_budget() {
        let snapshot = synthetic_snapshot();
        let started = Instant::now();
        let lines = dashboard_lines(&snapshot, 160);
        let elapsed = started.elapsed();

        assert!(!lines.is_empty());
        assert!(lines.len() > 20);
        assert!(elapsed < Duration::from_secs(2));
    }
}
