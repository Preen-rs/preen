use preen_core::dashboard_view::{CpuCoreUsageRow, DashboardViewModel};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::super::format::{
    capitalize_first, format_bytes_opt, format_capacity_pair, format_disk_total_line,
    format_disk_usage_line, format_load_triplet, format_percent, format_percent_fixed,
    format_percent_rounded, format_rate_mbps_compact, format_rate_mbps_fixed, format_uptime,
    io_rate_bar, pad_to_width, percent_bar, percent_bar_opt, pretty_host_name, process_bar,
    sparkline, truncate_with_ellipsis,
};
use super::super::theme::{
    battery_health_style, battery_style, health_dot_color, network_rate_style, usage_style,
};
use super::super::{
    BAR_WIDTH_UNIFIED, PALETTE_DANGER, PALETTE_OK, PALETTE_TEXT, PROCESS_NAME_WIDTH,
};
use super::card::{DashboardCard, DashboardCardLine, line_plain, line_styled};

pub(super) fn dashboard_status_line(
    view: &DashboardViewModel,
    content_width: usize,
) -> Line<'static> {
    let health_color = health_dot_color(view.header.health_score);
    let host = pretty_host_name(view.header.host_name.as_deref().unwrap_or("unknown-host"));
    let cpu_model = view
        .header
        .cpu_model
        .clone()
        .unwrap_or_else(|| "unknown-cpu".to_string());
    let capacity_pair = format_capacity_pair(view.memory.total_bytes, view.disk.total_bytes);
    let os_label = view
        .header
        .os_label
        .clone()
        .unwrap_or_else(|| "unknown-os".to_string());
    let uptime = view
        .memory
        .uptime_seconds
        .map(format_uptime)
        .unwrap_or_else(|| "n/a".to_string());

    let mut full_text = format!(
        " {} · {} · {} · {} · up {}",
        truncate_with_ellipsis(&host, 24),
        truncate_with_ellipsis(&cpu_model, 22),
        capacity_pair,
        truncate_with_ellipsis(&os_label, 16),
        uptime
    );
    let available = content_width.saturating_sub(19);
    full_text = truncate_with_ellipsis(&full_text, available);

    Line::from(vec![
        Span::styled(
            "Status",
            Style::default()
                .fg(Color::Rgb(191, 148, 255))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Health "),
        Span::styled(
            format!("● {}", view.header.health_score),
            Style::default()
                .fg(health_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(full_text),
    ])
}

pub(super) fn build_dashboard_cards(view: &DashboardViewModel) -> Vec<DashboardCard> {
    let cpu_usage = view.cpu.total_usage_pct;
    let cpu_usage_text = cpu_usage
        .map(format_percent)
        .unwrap_or_else(|| "n/a".to_string());
    let load = format_load_triplet(
        view.cpu.load_avg_1m,
        view.cpu.load_avg_5m,
        view.cpu.load_avg_15m,
    );
    let uptime = view
        .memory
        .uptime_seconds
        .map(format_uptime)
        .unwrap_or_else(|| "n/a".to_string());
    let process_count = view
        .memory
        .process_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let top_cpu_cores = top_cpu_core_rows(&view.cpu.top_cores, 4);
    let top_process_rows = top_process_rows(&view);
    let cpu_temp_suffix = view
        .cpu
        .temperature_c
        .map(|value| format!(" @ {:.1}°C", value))
        .unwrap_or_default();

    let disk_used_pct = view.disk.used_pct;
    let disk_usage_text = format_disk_usage_line(disk_used_pct, view.disk.available_bytes);
    let disk_total_label =
        format_disk_total_line(view.disk.total_bytes, view.disk.filesystem.as_deref());
    let network_level = view.network.peak_rate_mbps;
    let network_style = network_rate_style(network_level);
    let mut cpu_lines = vec![
        line_styled(
            format!(
                "Total    {}  {}{}",
                percent_bar_opt(cpu_usage, BAR_WIDTH_UNIFIED),
                cpu_usage_text,
                cpu_temp_suffix
            ),
            cpu_usage
                .map(usage_style)
                .unwrap_or_else(|| Style::default().fg(PALETTE_TEXT)),
        ),
        line_plain(format!(
            "Cores    {}",
            view.cpu
                .core_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        )),
        line_plain(format!("Load     {load}")),
    ];
    cpu_lines.extend(top_cpu_cores);

    vec![
        DashboardCard {
            title: "CPU",
            lines: cpu_lines,
        },
        DashboardCard {
            title: "Memory",
            lines: vec![
                line_styled(
                    format!(
                        "Used     {}  {}",
                        percent_bar_opt(view.memory.used_pct, BAR_WIDTH_UNIFIED),
                        view.memory
                            .used_pct
                            .map(format_percent)
                            .unwrap_or_else(|| "n/a".to_string())
                    ),
                    view.memory
                        .used_pct
                        .map(usage_style)
                        .unwrap_or_else(|| Style::default().fg(PALETTE_TEXT)),
                ),
                line_plain(format!(
                    "Total    {}",
                    format_bytes_opt(view.memory.total_bytes)
                )),
                line_plain(format!(
                    "Used     {}",
                    format_bytes_opt(view.memory.used_bytes)
                )),
                line_plain(format!("Uptime   {uptime}")),
                line_plain(format!("Proc     {process_count}")),
            ],
        },
        DashboardCard {
            title: "Disk",
            lines: vec![
                line_styled(
                    format!(
                        "INTR     {}  {disk_usage_text}",
                        percent_bar_opt(disk_used_pct, BAR_WIDTH_UNIFIED)
                    ),
                    disk_used_pct
                        .map(usage_style)
                        .unwrap_or_else(|| Style::default().fg(PALETTE_TEXT)),
                ),
                line_plain(format!("Total    {disk_total_label}")),
                line_styled(
                    format!(
                        "Read     {}  {}",
                        io_rate_bar(view.disk.read_rate_mbps.unwrap_or(0.0), BAR_WIDTH_UNIFIED),
                        format_rate_mbps_compact(view.disk.read_rate_mbps)
                    ),
                    usage_style(view.disk.read_rate_mbps.unwrap_or(0.0).min(100.0)),
                ),
                line_styled(
                    format!(
                        "Write    {}  {}",
                        io_rate_bar(view.disk.write_rate_mbps.unwrap_or(0.0), BAR_WIDTH_UNIFIED),
                        format_rate_mbps_compact(view.disk.write_rate_mbps)
                    ),
                    usage_style(view.disk.write_rate_mbps.unwrap_or(0.0).min(100.0)),
                ),
            ],
        },
        DashboardCard {
            title: "Power",
            lines: power_card_lines(view),
        },
        DashboardCard {
            title: "Network",
            lines: vec![
                line_styled(
                    format!(
                        "Down     {}  {}",
                        sparkline(&view.network.rx_history_mbps, 14),
                        format_rate_mbps_fixed(view.network.rx_rate_mbps)
                    ),
                    network_style,
                ),
                line_styled(
                    format!(
                        "Up       {}  {}",
                        sparkline(&view.network.tx_history_mbps, 14),
                        format_rate_mbps_fixed(view.network.tx_rate_mbps)
                    ),
                    network_style,
                ),
                line_styled(view.network.proxy_line.clone(), network_style),
            ],
        },
        DashboardCard {
            title: "Processes",
            lines: top_process_rows,
        },
    ]
}

fn top_cpu_core_rows(core_usages: &[CpuCoreUsageRow], max_rows: usize) -> Vec<DashboardCardLine> {
    let mut rows = core_usages
        .iter()
        .filter(|entry| entry.usage_pct > 0.0)
        .take(max_rows)
        .map(|entry| {
            line_styled(
                format!(
                    "Core{:<2}  {}  {}",
                    entry.core_index,
                    percent_bar(entry.usage_pct, BAR_WIDTH_UNIFIED),
                    format_percent(entry.usage_pct)
                ),
                usage_style(entry.usage_pct),
            )
        })
        .collect::<Vec<DashboardCardLine>>();
    if rows.len() < max_rows {
        for entry in core_usages
            .iter()
            .skip(rows.len())
            .take(max_rows - rows.len())
        {
            rows.push(line_styled(
                format!(
                    "Core{:<2}  {}  {}",
                    entry.core_index,
                    percent_bar(entry.usage_pct, BAR_WIDTH_UNIFIED),
                    format_percent(entry.usage_pct)
                ),
                usage_style(entry.usage_pct),
            ));
        }
    }
    rows
}

fn top_process_rows(view: &DashboardViewModel) -> Vec<DashboardCardLine> {
    let mut rows = Vec::new();
    for process in &view.processes.rows {
        let name_col = pad_to_width(
            &truncate_with_ellipsis(&process.name, PROCESS_NAME_WIDTH),
            PROCESS_NAME_WIDTH,
        );
        let bar_col = process_bar(process.cpu_pct, BAR_WIDTH_UNIFIED);
        let cpu_col = format_percent_fixed(process.cpu_pct);
        let mem_col = format_percent_fixed(process.memory_pct);
        rows.push(line_styled(
            format!("{name_col}  {bar_col}  {cpu_col}  mem {mem_col}"),
            usage_style(process.cpu_pct),
        ));
    }
    if rows.is_empty() {
        rows.push(line_plain("no process sample"));
    }
    rows
}

fn power_card_lines(view: &DashboardViewModel) -> Vec<DashboardCardLine> {
    let mut lines = Vec::new();
    let level = view.power.level_pct;
    if let Some(value) = level {
        lines.push(line_styled(
            format!(
                "Level    {}  {}",
                percent_bar(value, BAR_WIDTH_UNIFIED),
                format_percent(value)
            ),
            battery_style(value),
        ));
    } else {
        lines.push(line_plain("Level    n/a"));
    }

    let health_capacity = view.power.health_pct;
    if let Some(value) = health_capacity {
        lines.push(line_styled(
            format!(
                "Health   {}  {}",
                percent_bar(value, BAR_WIDTH_UNIFIED),
                format_percent_rounded(value)
            ),
            battery_style(value),
        ));
    } else {
        lines.push(line_plain("Health   n/a"));
    }

    let power_status = view
        .power
        .status
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let status_is_charging = view.power.status_is_charging;
    let mut status_text = capitalize_first(&power_status);
    if status_is_charging {
        if let Some(system_watts) = view.power.system_power_watts {
            status_text.push_str(&format!(" · {:.0}W", system_watts));
        } else if let Some(adapter_watts) = view.power.adapter_power_watts {
            status_text.push_str(&format!(" · {:.0}W Adapter", adapter_watts));
        }
        status_text.push_str(" ⚡");
    } else {
        if let Some(time_left) = view.power.time_left.as_deref()
            && time_left != "n/a"
        {
            status_text.push_str(&format!(" · {time_left}"));
        }
        if let Some(battery_watts) = view.power.battery_power_watts
            && battery_watts > 0.0
        {
            status_text.push_str(&format!(" · {:.0}W", battery_watts));
        }
    }
    let status_style = if status_is_charging {
        Style::default().fg(PALETTE_OK).add_modifier(Modifier::BOLD)
    } else if level.is_some_and(|value| value < 20.0) {
        Style::default()
            .fg(PALETTE_DANGER)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(PALETTE_TEXT)
    };

    lines.push(line_styled(status_text, status_style));

    let health_word = view
        .power
        .health_word
        .clone()
        .unwrap_or_else(|| "n/a".to_string());
    let mut detail = health_word.clone();
    if let Some(cycles) = view.power.cycle_count {
        detail.push_str(&format!(" · {cycles} cycles"));
    }
    if let Some(temp) = view.power.battery_temperature_c {
        detail.push_str(&format!(" · {:.1}°C", temp));
    }
    let detail_style = battery_health_style(&health_word);
    lines.push(line_styled(detail, detail_style));

    lines
}
