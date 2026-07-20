use crate::engine::ScanEngine;
use anyhow::Result;
use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode, DebounceEventResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::fs;

pub async fn run_watchdog(engine: Arc<ScanEngine>, dir: PathBuf, strict: bool) -> Result<()> {
    tracing::info!(
        "Starting CodeAegis Watchdog on {:?} (strict: {})",
        dir,
        strict
    );

    // Initial clean state cache
    let clean_states = Arc::new(Mutex::new(HashMap::<PathBuf, String>::new()));

    // Channel for events from the debouncer
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PathBuf>(100);

    // Initialize debouncer with 500ms delay
    let mut debouncer = new_debouncer(
        Duration::from_millis(500),
        move |res: DebounceEventResult| {
            if let Ok(events) = res {
                for event in events {
                    let _ = tx.blocking_send(event.path);
                }
            }
        },
    )?;

    // Start watching
    debouncer.watcher().watch(&dir, RecursiveMode::Recursive)?;

    println!("CodeAegis Watchdog is active. Monitoring for vulnerabilities...");

    while let Some(path_buf) = rx.recv().await {
        if should_ignore(&path_buf) {
            continue;
        }

        if let Err(e) = handle_file_event(&engine, &path_buf, strict, &clean_states).await {
            tracing::error!("Error handling file event for {:?}: {}", path_buf, e);
        }
    }

    Ok(())
}

fn should_ignore(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/.git/") || s.contains("/target/") || s.ends_with(".codeaegis-alert.md")
}

async fn handle_file_event(
    engine: &ScanEngine,
    path: &Path,
    strict: bool,
    clean_states: &Arc<Mutex<HashMap<PathBuf, String>>>,
) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let content = match fs::read_to_string(path).await {
        Ok(c) => c,
        Err(_) => return Ok(()), // Might be a deletion or temp file
    };

    let path_str = path.to_string_lossy();
    let result = engine.scan(&content, Some(&path_str), false).await?;

    let has_findings = !result.findings.is_empty();

    if has_findings {
        tracing::warn!("⚠️ Vulnerability detected in {:?}", path);

        let report = format!(
            "# CodeAegis Security Alert\n\n**File:** `{}`\n**Risk Tier:** {}\n\n## Summary\n{}\n\n## Findings\n{}",
            path_str,
            result.risk_tier,
            result.summary,
            result.findings.iter().map(|f| format!("- **{}**: {}", f.tool, f.message)).collect::<Vec<_>>().join("\n")
        );

        let alert_path = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".codeaegis-alert.md");
        fs::write(&alert_path, report).await?;

        if strict {
            let previous_state = {
                let cache = clean_states.lock().unwrap();
                cache.get(path).cloned()
            };

            if let Some(clean_content) = previous_state {
                tracing::warn!(
                    "🛡️ Strict Mode: Reverting {:?} to last known safe state.",
                    path
                );
                fs::write(path, clean_content).await?;
            } else {
                tracing::error!(
                    "❌ Strict Mode: No previous safe state found for {:?}. Cannot revert.",
                    path
                );
            }
        }
    } else {
        // File is clean, update clean state
        {
            let mut cache = clean_states.lock().unwrap();
            cache.insert(path.to_path_buf(), content);
        }

        // Remove alert if it exists
        let alert_path = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".codeaegis-alert.md");
        if alert_path.exists() {
            let _ = fs::remove_file(alert_path).await;
        }
    }

    Ok(())
}
