mod cache;
mod engine;
mod scanners;
mod critic;
mod cli;
mod cli_args;
mod auth;
mod watchdog;
mod lsp;
mod exclusions;

use crate::cache::ResultCache;
use crate::engine::ScanEngine;
use crate::critic::Critic;
use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use cli_args::{Cli, Commands, AuthCommands};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing to write to stderr so it doesn't break CLI stdout output (e.g. JSON/SARIF reports)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.auth {
        auth::handle_auth_flag(cli.model.clone())?;
        return Ok(());
    }

    // If it's an auth command, we handle it before initializing the engine
    if let Some(Commands::Auth { action }) = &cli.command {
        match action {
            AuthCommands::Login { provider } => auth::handle_login(provider)?,
            AuthCommands::Logout { provider } => auth::handle_logout(provider)?,
            AuthCommands::Status => auth::handle_status()?,
        }
        return Ok(());
    }

    // If it's an init command, we handle it before initializing the engine
    if let Some(Commands::Init { dir }) = &cli.command {
        cli::handle_init(dir)?;
        return Ok(());
    }

    // If it's an exclude command, we handle it before initializing the engine
    if let Some(Commands::Exclude { pattern, scanners }) = &cli.command {
        exclusions::handle_exclude(pattern, scanners)?;
        return Ok(());
    }

    // If it's a setup command, we handle it before initializing the engine
    if let Some(Commands::Setup) = &cli.command {
        cli::handle_setup()?;
        return Ok(());
    }

    // Initialize core components

    // Capacity of 1000 items, TTL of 1 hour
    let cache = Arc::new(ResultCache::new(1000, 3600));
    
    let critic = match Critic::new(cli.model.clone()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Fatal Error during Critic initialization: {}", e);
            return Err(e);
        }
    };
    
    let engine = Arc::new(ScanEngine::new(
        cache,
        critic,
        cli.scanners.clone(),
        cli.skip_scanners.clone(),
    ));

    if cli.logs {
        engine.set_logging(true);
    }

    match cli.command {
        None => {
            cli::run_directory_scan(engine, std::path::PathBuf::from("."), None, false, false, "none".to_string(), "text".to_string(), None).await?;
        }
        Some(Commands::Watch { dir, strict }) => {
            watchdog::run_watchdog(engine, dir, strict).await?;
        }
        Some(Commands::Lsp) => {
            lsp::run_lsp_server(engine).await?;
        }
        Some(Commands::Scan { dir, report, recursive, no_fail, severity_threshold, format, report_format }) => {
            cli::run_directory_scan(engine, dir, report, recursive, no_fail, severity_threshold, format, report_format).await?;
        }
        Some(Commands::Auth { .. }) | Some(Commands::Init { .. }) | Some(Commands::Exclude { .. }) | Some(Commands::Setup) => unreachable!(),
    }

    Ok(())
}
