use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC: u64 = 120;
const PLUGIN_COMMAND_TIMEOUT_ENV: &str = "PREEN_TUI_PLUGIN_COMMAND_TIMEOUT_SEC";
const MAX_PLUGIN_SPEC_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCommandKind {
    List,
    Search,
    Info,
    Preflight,
    Test,
    Install,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCommandOutput {
    pub ok: bool,
    pub lines: Vec<String>,
}

impl PluginCommandKind {
    pub fn command(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Search => "search",
            Self::Info => "info",
            Self::Preflight => "preflight",
            Self::Test => "test",
            Self::Install => "install",
        }
    }

    pub fn label(self) -> &'static str {
        self.command()
    }

    pub fn requires_spec(self) -> bool {
        !matches!(self, Self::List | Self::Search)
    }
}

pub fn run_plugin_cli_command(kind: PluginCommandKind, spec: Option<&str>) -> PluginCommandOutput {
    if let Some(error) = validate_plugin_spec(kind, spec) {
        return PluginCommandOutput {
            ok: false,
            lines: vec![error],
        };
    }

    let mut command = ProcessCommand::new("cargo");
    command.args(build_plugin_cli_args(kind, spec));

    let output = match run_command_with_timeout(command, plugin_command_timeout()) {
        Ok(output) => output,
        Err(error) => {
            return PluginCommandOutput {
                ok: false,
                lines: vec![error],
            };
        }
    };

    PluginCommandOutput {
        ok: output.status.success(),
        lines: parse_command_output_lines(output.stdout.as_slice(), output.stderr.as_slice()),
    }
}

fn run_command_with_timeout(
    mut command: ProcessCommand,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start plugin command: {error}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|error| format!("failed to read plugin command output: {error}"));
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let output = child.wait_with_output().map_err(|error| {
                        format!("plugin command timed out and could not collect output: {error}")
                    })?;
                    return Err(format!(
                        "plugin command timed out after {}s{}",
                        timeout.as_secs(),
                        format_stderr_tail(output.stderr.as_slice())
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(format!("failed while waiting plugin command: {error}"));
            }
        }
    }
}

fn parse_command_output_lines(stdout: &[u8], stderr: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let stdout = String::from_utf8_lossy(stdout);
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            lines.push(line.to_string());
        }
    }

    let stderr = String::from_utf8_lossy(stderr);
    for line in stderr.lines() {
        if !line.trim().is_empty() {
            lines.push(format!("stderr: {line}"));
        }
    }

    if lines.is_empty() {
        lines.push("command finished with no output".to_string());
    }

    lines
}

fn format_stderr_tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let first_line = text.lines().find(|line| !line.trim().is_empty());
    match first_line {
        Some(line) => format!(" (stderr: {line})"),
        None => String::new(),
    }
}

fn plugin_command_timeout() -> Duration {
    let seconds = parse_timeout_seconds_from_env(std::env::var(PLUGIN_COMMAND_TIMEOUT_ENV).ok());
    Duration::from_secs(seconds)
}

fn parse_timeout_seconds_from_env(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC)
}

fn validate_plugin_spec(kind: PluginCommandKind, spec: Option<&str>) -> Option<String> {
    if !kind.requires_spec() {
        return None;
    }
    let value = match spec.map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return Some(format!("plugin {} requires a plugin spec", kind.label()));
        }
    };
    if value.chars().count() > MAX_PLUGIN_SPEC_LEN {
        return Some("plugin spec is too long".to_string());
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Some("plugin spec contains invalid control characters".to_string());
    }
    None
}

fn build_plugin_cli_args(kind: PluginCommandKind, spec: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "-q".to_string(),
        "-p".to_string(),
        "preen-cli".to_string(),
        "--".to_string(),
        "plugin".to_string(),
        kind.command().to_string(),
    ];
    if let Some(spec) = spec {
        args.push(spec.to_string());
    }
    if requires_json_output(kind) {
        args.push("--json".to_string());
    }
    args
}

fn requires_json_output(kind: PluginCommandKind) -> bool {
    matches!(
        kind,
        PluginCommandKind::Preflight | PluginCommandKind::Test | PluginCommandKind::Install
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC, PluginCommandKind, build_plugin_cli_args,
        parse_command_output_lines, parse_timeout_seconds_from_env, requires_json_output,
        run_command_with_timeout, validate_plugin_spec,
    };
    use std::process::Command as ProcessCommand;
    use std::time::Duration;

    #[test]
    fn preflight_test_and_install_use_json_envelope() {
        assert!(requires_json_output(PluginCommandKind::Preflight));
        assert!(requires_json_output(PluginCommandKind::Test));
        assert!(requires_json_output(PluginCommandKind::Install));
        assert!(!requires_json_output(PluginCommandKind::List));
        assert!(!requires_json_output(PluginCommandKind::Search));
        assert!(!requires_json_output(PluginCommandKind::Info));
    }

    #[test]
    fn builds_json_args_when_required() {
        let args = build_plugin_cli_args(
            PluginCommandKind::Preflight,
            Some("preen-rs.homebrew@1.0.7"),
        );
        assert_eq!(
            args,
            vec![
                "run".to_string(),
                "-q".to_string(),
                "-p".to_string(),
                "preen-cli".to_string(),
                "--".to_string(),
                "plugin".to_string(),
                "preflight".to_string(),
                "preen-rs.homebrew@1.0.7".to_string(),
                "--json".to_string(),
            ]
        );
    }

    #[test]
    fn builds_plain_args_when_json_not_required() {
        let args = build_plugin_cli_args(PluginCommandKind::List, None);
        assert_eq!(
            args,
            vec![
                "run".to_string(),
                "-q".to_string(),
                "-p".to_string(),
                "preen-cli".to_string(),
                "--".to_string(),
                "plugin".to_string(),
                "list".to_string(),
            ]
        );
    }

    #[test]
    fn validate_plugin_spec_requires_value_for_spec_commands() {
        assert_eq!(
            validate_plugin_spec(PluginCommandKind::Install, None),
            Some("plugin install requires a plugin spec".to_string())
        );
        assert_eq!(
            validate_plugin_spec(PluginCommandKind::Test, Some("   ")),
            Some("plugin test requires a plugin spec".to_string())
        );
    }

    #[test]
    fn validate_plugin_spec_rejects_control_chars_and_overlong() {
        assert_eq!(
            validate_plugin_spec(PluginCommandKind::Preflight, Some("abc\nx")),
            Some("plugin spec contains invalid control characters".to_string())
        );
        let long = "a".repeat(513);
        assert_eq!(
            validate_plugin_spec(PluginCommandKind::Preflight, Some(&long)),
            Some("plugin spec is too long".to_string())
        );
    }

    #[test]
    fn parse_command_output_lines_prefixes_stderr() {
        let lines = parse_command_output_lines(b"ok\n", b"warn\n");
        assert_eq!(lines, vec!["ok".to_string(), "stderr: warn".to_string()]);
    }

    #[test]
    fn parse_timeout_seconds_from_env_uses_default_for_invalid_values() {
        assert_eq!(parse_timeout_seconds_from_env(Some("7".to_string())), 7);
        assert_eq!(
            parse_timeout_seconds_from_env(Some("0".to_string())),
            DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC
        );
        assert_eq!(
            parse_timeout_seconds_from_env(Some("abc".to_string())),
            DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC
        );
        assert_eq!(
            parse_timeout_seconds_from_env(None),
            DEFAULT_PLUGIN_COMMAND_TIMEOUT_SEC
        );
    }

    #[test]
    fn run_command_with_timeout_times_out_long_running_process() {
        let mut command = ProcessCommand::new("sh");
        command.args(["-c", "sleep 2"]);
        let error =
            run_command_with_timeout(command, Duration::from_millis(120)).expect_err("timeout");
        assert!(error.contains("plugin command timed out"));
    }

    #[test]
    fn run_command_with_timeout_collects_output() {
        let mut command = ProcessCommand::new("sh");
        command.args(["-c", "printf ok"]);
        let output =
            run_command_with_timeout(command, Duration::from_secs(1)).expect("command output");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
    }
}
