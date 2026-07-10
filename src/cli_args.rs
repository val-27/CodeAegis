use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "codeaegis")]
#[command(about = "CodeAegis Local Security Scanner & Workspace Agent Skill", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable quality logging for scan results and critic decisions
    #[arg(long, global = true, default_value_t = false)]
    pub logs: bool,

    /// Override the LLM model to use
    #[arg(short, long, global = true)]
    pub model: Option<String>,

    /// Setup LLM authorization or view current LLM config info
    #[arg(long)]
    pub auth: bool,

    /// Comma-separated list of security scanners to enable (trufflehog, osv, trivy, opengrep). If omitted, all are enabled.
    #[arg(long, global = true, value_delimiter = ',')]
    pub scanners: Option<Vec<String>>,

    /// Comma-separated list of security scanners to disable.
    #[arg(long, global = true, value_delimiter = ',')]
    pub skip_scanners: Option<Vec<String>>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Monitors a directory for file changes and scans them automatically
    Watch {
        /// The directory to watch
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Instantly revert files to their previous safe state if a vulnerability is detected
        #[arg(short, long, default_value_t = false)]
        strict: bool,
    },
    /// Setup a Workspace Agent Skill for CodeAegis in a directory
    Init {
        /// The target directory to install the skill in
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Skip git pre-commit hook installation
        #[arg(long, default_value_t = false)]
        no_hooks: bool,
    },
    /// Runs the CodeAegis Language Server (LSP)
    Lsp,
    /// Scans a directory or file for vulnerabilities
    Scan {
        /// The directory or file to scan
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Output findings to a SARIF compliant file
        #[arg(long)]
        report: Option<PathBuf>,

        /// Recursively scan subdirectories
        #[arg(short, long, default_value_t = false)]
        recursive: bool,

        /// Exits with 0 even if vulnerabilities are found
        #[arg(long, default_value_t = false)]
        no_fail: bool,

        /// Minimum severity to trigger non-zero exit status (none, low, medium, high, critical)
        #[arg(long, default_value = "none")]
        severity_threshold: String,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: String,

        /// Explicit report format (sarif, json, junit, markdown, csv, html). If omitted, inferred from report filename.
        #[arg(long)]
        report_format: Option<String>,
    },
    /// Manage LLM authentication credentials in the OS keychain
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },
    /// Exclude a file or directory pattern from scans
    Exclude {
        /// The file or directory pattern to exclude (e.g. 'secrets_backup.py' or 'node_modules/*')
        pattern: String,

        /// Comma-separated list of scanners to apply this exclusion to (e.g. 'trufflehog,trivy'), or 'all' for all scanners.
        #[arg(short, long, default_value = "all")]
        scanners: String,
    },
    /// Interactive configuration wizard to set up credentials, exclusions, and skills
    Setup,
}

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Save an API key to the OS keychain for a provider
    Login {
        /// The provider name (e.g., gemini, openai, grok)
        provider: String,
    },
    /// Remove an API key from the OS keychain
    Logout {
        /// The provider name (e.g., gemini, openai, grok)
        provider: String,
    },
    /// List which providers have keys stored in the keychain
    Status,
}
