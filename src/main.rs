mod cache;
mod engine;
mod mcp;
mod scanners;
mod critic;
mod cli;
mod cli_args;
mod auth;
mod watchdog;
mod lsp;

use crate::cache::ResultCache;
use crate::engine::ScanEngine;
use crate::mcp::McpServer;
use crate::critic::Critic;
use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use cli_args::{Cli, Commands, AuthCommands};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing to write to stderr so it doesn't break MCP JSON-RPC on stdout
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // If it's an auth command, we handle it before initializing the engine
    if let Some(Commands::Auth { action }) = &cli.command {
        match action {
            AuthCommands::Login { provider } => auth::handle_login(provider)?,
            AuthCommands::Logout { provider } => auth::handle_logout(provider)?,
            AuthCommands::Status => auth::handle_status()?,
        }
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
    
    let engine = Arc::new(ScanEngine::new(cache, critic));

    if cli.logs {
        engine.set_logging(true);
    }

    match cli.command {
        Some(Commands::Mcp) | None => {
            // Always enable logs for MCP mode so the user can verify it's working via stderr
            engine.set_logging(true);
            tracing::info!("CodeAegis MCP Server starting...");
            let server = McpServer::new(engine);
            if let Err(e) = server.run().await {
                eprintln!("MCP Server encountered a fatal error: {}", e);
                return Err(e);
            }
        }
        Some(Commands::Watch { dir, strict }) => {
            watchdog::run_watchdog(engine, dir, strict).await?;
        }
        Some(Commands::Lsp) => {
            lsp::run_lsp_server(engine).await?;
        }
        Some(Commands::Scan { dir, report }) => {
            cli::run_directory_scan(engine, dir, report).await?;
        }
        Some(Commands::Auth { .. }) => unreachable!(),
    }

    Ok(())
}
