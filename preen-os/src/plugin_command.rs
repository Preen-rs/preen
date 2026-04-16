use std::process::Command as ProcessCommand;

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
    let mut command = ProcessCommand::new("cargo");
    command.args(build_plugin_cli_args(kind, spec));

    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            return PluginCommandOutput {
                ok: false,
                lines: vec![format!("failed to start plugin command: {error}")],
            };
        }
    };

    let mut lines = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.trim().is_empty() {
            lines.push(line.to_string());
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        if !line.trim().is_empty() {
            lines.push(format!("stderr: {line}"));
        }
    }

    if lines.is_empty() {
        lines.push("command finished with no output".to_string());
    }

    PluginCommandOutput {
        ok: output.status.success(),
        lines,
    }
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
    use super::{PluginCommandKind, build_plugin_cli_args, requires_json_output};

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
}
