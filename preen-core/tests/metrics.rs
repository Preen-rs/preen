use preen_core::metrics::{MetricsSink, StdoutMetrics};
use std::time::Duration;

#[test]
fn stdout_metrics_does_not_panic() {
    let metrics = StdoutMetrics;
    metrics.incr("test.counter", 1);
    metrics.timing("test.timing", Duration::from_millis(5));
}
