use anyhow::{Result, anyhow};
use crate::cache::Finding;
use tokio::process::Command;
use std::time::Duration;
use tokio::time::timeout;
use std::env;
use std::path::PathBuf;
use uuid::Uuid;

pub async fn scan(code: &str, file_path: Option<&str>) -> Result<Vec<Finding>> {
    // Create a temporary file with the original extension to help Opengrep detect language
    let extension = file_path
        .and_then(|p| std::path::Path::new(p).extension())
        .and_then(|e| e.to_str())
        .unwrap_or("txt");

    let temp_dir = env::temp_dir();
    let temp_file_path = temp_dir.join(format!("codeaegis-{}.{}", Uuid::new_v4(), extension));
    
    tokio::fs::write(&temp_file_path, code).await?;

    let result = run_opengrep_scan(&temp_file_path).await;

    // Cleanup
    let _ = tokio::fs::remove_file(&temp_file_path).await;

    result
}

async fn run_opengrep_scan(path: &PathBuf) -> Result<Vec<Finding>> {
    // Run opengrep scan --config=auto --json <path>
    let child = Command::new("opengrep")
        .arg("scan")
        .arg("--config=auto")
        .arg("--json")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let result = timeout(Duration::from_secs(30), child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            // Opengrep exits with non-zero status if findings are found,
            // but we can parse stdout if it has content.
            if !output.stdout.is_empty() {
                parse_opengrep_output(&output.stdout)
            } else {
                Ok(vec![])
            }
        }
        Ok(Err(e)) => Err(anyhow!("Opengrep execution failed: {}", e)),
        Err(_) => Err(anyhow!("Opengrep timed out")),
    }
}

fn parse_opengrep_output(stdout: &[u8]) -> Result<Vec<Finding>> {
    let v: serde_json::Value = serde_json::from_slice(stdout)?;
    let mut findings = Vec::new();

    if let Some(results) = v["results"].as_array() {
        for r in results {
            let check_id = r["check_id"].as_str().unwrap_or("unknown-rule");
            let extra = &r["extra"];
            let message = extra["message"].as_str().unwrap_or("No message");
            let severity = extra["severity"].as_str().unwrap_or("WARNING");
            let line = r["start"]["line"].as_u64().unwrap_or(0);
            
            findings.push(Finding {
                tool: "Opengrep".to_string(),
                severity: severity.to_string(),
                message: message.to_string(),
                location: Some(format!("{}:{}", check_id, line)),
                remediation: None,
            });
        }
    }

    Ok(findings)
}
