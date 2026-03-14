use std::time::Duration;

pub trait MetricsSink: Send + Sync {
    fn incr(&self, name: &str, value: u64);
    fn timing(&self, name: &str, duration: Duration);
}

pub struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn incr(&self, _name: &str, _value: u64) {}
    fn timing(&self, _name: &str, _duration: Duration) {}
}

pub struct StdoutMetrics;

impl MetricsSink for StdoutMetrics {
    fn incr(&self, name: &str, value: u64) {
        println!("[metrics] {name} += {value}");
    }

    fn timing(&self, name: &str, duration: Duration) {
        println!("[metrics] {name} = {:?}ms", duration.as_millis());
    }
}
