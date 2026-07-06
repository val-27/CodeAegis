use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "codeaegis")]
#[command(about = "CodeAegis Security Scanner & MCP Server", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable quality logging for scan results and critic decisions
    #[arg(long, global = true, default_value_t = false)]
    pub logs: bool,

    /// Override the LLM model to use
    #[arg(short, long, global = true)]
    pub model: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Runs the CodeAegis MCP Server
    Mcp,
    /// Monitors a directory for file changes and scans them automatically
    Watch {
        /// The directory to watch
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Instantly revert files to their previous safe state if a vulnerability is detected
        #[arg(short, long, default_value_t = false)]
        strict: bool,
    },
    /// Runs the CodeAegis Language Server (LSP)
    Lsp,
    /// Scans a directory for vulnerabilities
    Scan {
        /// The directory to scan
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Output findings to a SARIF compliant file
        #[arg(short, long)]
        report: Option<PathBuf>,
    },
    /// Manage LLM authentication credentials in the OS keychain
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },
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
