pub(super) fn pad_to_width(value: &str, width: usize) -> String {
    let truncated = truncate_with_ellipsis(value, width);
    let len = truncated.chars().count();
    if len >= width {
        return truncated;
    }
    format!("{truncated}{}", " ".repeat(width - len))
}

pub(super) fn percent_bar(value: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let clamped = value.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

pub(super) fn percent_bar_opt(value: Option<f64>, width: usize) -> String {
    value
        .map(|item| percent_bar(item, width))
        .unwrap_or_else(|| "░".repeat(width))
}

pub(super) fn format_load_triplet(
    one: Option<f64>,
    five: Option<f64>,
    fifteen: Option<f64>,
) -> String {
    let one = one
        .map(format_load_value)
        .unwrap_or_else(|| "n/a".to_string());
    let five = five
        .map(format_load_value)
        .unwrap_or_else(|| "n/a".to_string());
    let fifteen = fifteen
        .map(format_load_value)
        .unwrap_or_else(|| "n/a".to_string());
    format!("{one} / {five} / {fifteen}")
}

fn format_load_value(value: f64) -> String {
    format!("{value:.2}")
}

pub(super) fn sparkline(history: &[f64], width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let glyphs = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let mut data = Vec::with_capacity(width);
    if history.len() >= width {
        data.extend_from_slice(&history[history.len() - width..]);
    } else {
        data.resize(width - history.len(), 0.0);
        data.extend_from_slice(history);
    }
    let peak = data.iter().copied().fold(0.0_f64, f64::max).max(0.01);
    data.into_iter()
        .map(|value| {
            let idx = ((value / peak) * (glyphs.len() as f64 - 1.0)).round() as usize;
            glyphs[idx.min(glyphs.len() - 1)]
        })
        .collect()
}

pub(super) fn format_rate_mbps_opt(rate_mbps: Option<f64>) -> String {
    match rate_mbps {
        Some(value) if value >= 1024.0 => format!("{:.2} GB/s", value / 1024.0),
        Some(value) => format!("{value:.2} MB/s"),
        None => "n/a".to_string(),
    }
}

pub(super) fn format_rate_mbps_fixed(rate_mbps: Option<f64>) -> String {
    let rate = format_rate_mbps_opt(rate_mbps);
    format!("{rate:>8}")
}

pub(super) fn format_rate_mbps_compact(rate_mbps: Option<f64>) -> String {
    let value = rate_mbps.unwrap_or(0.0);
    if value < 0.01 {
        return "0 MB/s".to_string();
    }
    if value < 1.0 {
        return format!("{value:.2} MB/s");
    }
    if value < 10.0 {
        return format!("{value:.1} MB/s");
    }
    format!("{value:.0} MB/s")
}

pub(super) fn io_rate_bar(rate_mbps: f64, width: usize) -> String {
    if rate_mbps <= 0.0 {
        return "▯".repeat(width);
    }
    let scaled = ((rate_mbps / 10.0).floor() as usize).clamp(1, width);
    format!("{}{}", "▮".repeat(scaled), "▯".repeat(width - scaled))
}

pub(super) fn process_bar(cpu_pct: f64, width: usize) -> String {
    let clamped = cpu_pct.clamp(0.0, 100.0);
    let mut filled = ((clamped / 100.0) * width as f64).round() as usize;
    if clamped > 0.0 && filled == 0 {
        filled = 1;
    }
    filled = filled.min(width);
    format!("{}{}", "▮".repeat(filled), "▯".repeat(width - filled))
}

pub(super) fn format_percent(value: f64) -> String {
    format!("{value:.1}%")
}

pub(super) fn format_percent_fixed(value: f64) -> String {
    format!("{value:>5.1}%")
}

pub(super) fn format_percent_rounded(value: f64) -> String {
    format!("{value:.0}%")
}

pub(super) fn format_uptime(total_seconds: u64) -> String {
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    if days > 0 {
        return format!("{days}d {hours}h {minutes}m");
    }
    if hours > 0 {
        return format!("{hours}h {minutes}m");
    }
    format!("{minutes}m")
}

pub(super) fn format_capacity_pair(memory_total: Option<u64>, disk_total: Option<u64>) -> String {
    let memory = memory_total
        .map(format_bytes_spaced)
        .unwrap_or_else(|| "n/a".to_string());
    let disk = disk_total
        .map(format_bytes_spaced)
        .unwrap_or_else(|| "n/a".to_string());
    format!("{memory}/{disk}")
}

pub(super) fn format_disk_usage_line(used_pct: Option<f64>, free_bytes: Option<u64>) -> String {
    match (used_pct, free_bytes) {
        (Some(used), Some(free)) => format!(
            "{:.1}% used, {} free",
            used.clamp(0.0, 100.0),
            format_bytes_short(free)
        ),
        (Some(used), None) => format!("{:.1}% used", used.clamp(0.0, 100.0)),
        (None, Some(free)) => format!("{} free", format_bytes_short(free)),
        (None, None) => "n/a".to_string(),
    }
}

pub(super) fn format_disk_total_line(total: Option<u64>, filesystem: Option<&str>) -> String {
    let total = total
        .map(format_bytes_short)
        .unwrap_or_else(|| "n/a".to_string());
    let fs = filesystem
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_uppercase())
        .unwrap_or_else(|| "n/a".to_string());
    format!("{total} · {fs}")
}

fn format_bytes_spaced(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;
    let value = bytes as f64;
    if value >= TB {
        return format!("{:.1} TB", value / TB);
    }
    if value >= GB {
        return format!("{:.1} GB", value / GB);
    }
    if value >= MB {
        return format!("{:.1} MB", value / MB);
    }
    if value >= KB {
        return format!("{:.1} KB", value / KB);
    }
    format!("{bytes} B")
}

fn format_bytes_short(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    if bytes >= TB {
        return format!("{:.0}T", bytes as f64 / TB as f64);
    }
    if bytes >= GB {
        return format!("{:.0}G", bytes as f64 / GB as f64);
    }
    if bytes >= MB {
        return format!("{:.0}M", bytes as f64 / MB as f64);
    }
    if bytes >= KB {
        return format!("{:.0}K", bytes as f64 / KB as f64);
    }
    bytes.to_string()
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    if bytes >= TB {
        return format!("{:.1}TB", bytes as f64 / TB as f64);
    }
    if bytes >= GB {
        return format!("{:.1}GB", bytes as f64 / GB as f64);
    }
    if bytes >= MB {
        return format!("{:.1}MB", bytes as f64 / MB as f64);
    }
    if bytes >= KB {
        return format!("{:.1}KB", bytes as f64 / KB as f64);
    }
    format!("{bytes}B")
}

pub(super) fn pretty_host_name(value: &str) -> String {
    let base = value
        .trim_end_matches(".local")
        .replace('-', " ")
        .replace('_', " ");
    truncate_with_ellipsis(base.trim(), 24)
}

pub(super) fn capitalize_first(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str().to_lowercase()),
        None => String::new(),
    }
}

pub(super) fn format_bytes_opt(bytes: Option<u64>) -> String {
    bytes.map(format_bytes).unwrap_or_else(|| "n/a".to_string())
}

pub(super) fn truncate_with_ellipsis(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    for ch in value.chars().take(width - 1) {
        out.push(ch);
    }
    out.push('…');
    out
}

pub(super) fn short_rev(rev: &str) -> String {
    if rev.len() <= 12 {
        return rev.to_string();
    }
    let prefix: String = rev.chars().take(12).collect();
    format!("{prefix}...")
}

pub(super) fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
