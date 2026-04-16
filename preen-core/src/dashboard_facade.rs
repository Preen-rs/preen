use crate::dashboard::DashboardSnapshot;

#[derive(Debug, Clone, PartialEq)]
pub struct DashboardDerived {
    pub disk_used_pct: Option<f64>,
    pub network_peak_rate_mbps: f64,
    pub power_health_pct: Option<f64>,
    pub proxy_line: String,
}

pub struct DashboardFacade;

impl DashboardFacade {
    pub fn derive(snapshot: &DashboardSnapshot) -> DashboardDerived {
        let disk_used_pct = snapshot
            .metrics
            .disk_free_pct
            .map(|value| (100.0 - value).max(0.0));
        let network_peak_rate_mbps = snapshot
            .metrics
            .network_rx_rate_mbps
            .unwrap_or(0.0)
            .max(snapshot.metrics.network_tx_rate_mbps.unwrap_or(0.0));
        let power_health_pct = Self::resolve_battery_health_percent(
            snapshot.metrics.power_capacity_pct,
            snapshot.metrics.power_health.as_deref(),
        );
        let proxy_line = Self::compose_proxy_line(
            snapshot.metrics.network_proxy.as_deref(),
            snapshot.metrics.network_primary_ip.as_deref(),
        );

        DashboardDerived {
            disk_used_pct,
            network_peak_rate_mbps,
            power_health_pct,
            proxy_line,
        }
    }

    pub fn resolve_battery_health_percent(
        capacity_pct: Option<f64>,
        health_text: Option<&str>,
    ) -> Option<f64> {
        if capacity_pct.is_some() {
            return capacity_pct;
        }
        let value = health_text?.to_lowercase();
        if value.contains("excellent") {
            return Some(100.0);
        }
        if value.contains("good") {
            return Some(90.0);
        }
        if value.contains("normal") {
            return Some(80.0);
        }
        if value.contains("fair") {
            return Some(70.0);
        }
        if value.contains("poor") || value.contains("bad") {
            return Some(55.0);
        }
        None
    }

    pub fn is_power_status_charging(power_status: &str) -> bool {
        power_status.eq_ignore_ascii_case("charging")
            || power_status.eq_ignore_ascii_case("charged")
    }

    pub fn compose_proxy_line(proxy: Option<&str>, primary_ip: Option<&str>) -> String {
        let proxy = proxy.unwrap_or("none");
        match (proxy, primary_ip) {
            ("none", Some(ip)) => format!("Proxy    {ip}"),
            (value, Some(ip)) if !value.contains(ip) => format!("Proxy    {value} · {ip}"),
            (value, _) => format!("Proxy    {value}"),
        }
    }
}
