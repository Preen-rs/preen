#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardLevel {
    Good,
    Warn,
    Danger,
}

pub fn classify_health_score(score: u8) -> DashboardLevel {
    if score >= 85 {
        return DashboardLevel::Good;
    }
    if score >= 60 {
        return DashboardLevel::Warn;
    }
    DashboardLevel::Danger
}

pub fn classify_usage_percent(percent: f64) -> DashboardLevel {
    if percent >= 85.0 {
        return DashboardLevel::Danger;
    }
    if percent >= 60.0 {
        return DashboardLevel::Warn;
    }
    DashboardLevel::Good
}

pub fn classify_battery_percent(percent: f64) -> DashboardLevel {
    if percent < 20.0 {
        return DashboardLevel::Danger;
    }
    if percent < 50.0 {
        return DashboardLevel::Warn;
    }
    DashboardLevel::Good
}

pub fn classify_network_rate_mbps(rate_mbps: f64) -> DashboardLevel {
    if rate_mbps > 8.0 {
        return DashboardLevel::Danger;
    }
    if rate_mbps > 3.0 {
        return DashboardLevel::Warn;
    }
    DashboardLevel::Good
}
