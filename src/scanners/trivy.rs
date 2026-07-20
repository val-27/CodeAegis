use crate::cache::Finding;
use anyhow::{anyhow, Result};
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

pub async fn scan(code: &str, file_path: Option<&str>) -> Result<Vec<Finding>> {
    // Determine if we should run Trivy based on file extension or content
    let should_scan = if let Some(path) = file_path {
        is_iac_file(path)
    } else {
        // Fallback: simple heuristic if no path provided
        code.contains("resource \"") || code.contains("apiVersion:") || code.contains("FROM ")
    };

    if !should_scan {
        return Ok(vec![]);
    }

    // Create a temporary file with the original extension to help Trivy detect the type
    let extension = file_path
        .and_then(|p| std::path::Path::new(p).extension())
        .and_then(|e| e.to_str())
        .unwrap_or("yaml"); // Default to yaml if unknown

    let temp_dir = env::temp_dir();
    let temp_file_path = temp_dir.join(format!("codeaegis-{}.{}", Uuid::new_v4(), extension));

    tokio::fs::write(&temp_file_path, code).await?;

    let result = run_trivy_scan(&temp_file_path).await;

    // Cleanup
    let _ = tokio::fs::remove_file(&temp_file_path).await;

    result
}

fn is_iac_file(path: &str) -> bool {
    let path = path.to_lowercase();
    path.ends_with(".yml")
        || path.ends_with(".yaml")
        || path.ends_with(".json")
        || path.ends_with(".tf")
        || path.ends_with(".tf.json")
        || path.ends_with(".tfvars")
        || path.ends_with("tfplan")
        || path.ends_with(".tfplan")
        || path.ends_with(".tpl")
        || path.ends_with(".tar.gz")
        || path.ends_with(".ini")
}

async fn run_trivy_scan(path: &PathBuf) -> Result<Vec<Finding>> {
    let child = Command::new("trivy")
        .arg("config")
        .arg("--format")
        .arg("json")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let result = timeout(Duration::from_secs(20), child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() || !output.stdout.is_empty() {
                parse_trivy_output(&output.stdout)
            } else {
                Ok(vec![])
            }
        }
        Ok(Err(e)) => Err(anyhow!("Trivy execution failed: {}", e)),
        Err(_) => Err(anyhow!("Trivy timed out")),
    }
}

fn parse_trivy_output(stdout: &[u8]) -> Result<Vec<Finding>> {
    let v: serde_json::Value = serde_json::from_slice(stdout)?;
    let mut findings = Vec::new();

    // Trivy JSON structure for 'config' scan:
    // { "Results": [ { "Misconfigurations": [ { "ID": "...", "Message": "...", "Severity": "..." } ] } ] }
    if let Some(results) = v["Results"].as_array() {
        for res in results {
            if let Some(misconfigs) = res["Misconfigurations"].as_array() {
                for m in misconfigs {
                    findings.push(Finding {
                        tool: "Trivy".to_string(),
                        severity: m["Severity"].as_str().unwrap_or("UNKNOWN").to_string(),
                        message: m["Message"].as_str().unwrap_or("No message").to_string(),
                        location: Some(format!(
                            "{}:{}",
                            m["ID"].as_str().unwrap_or(""),
                            m["Title"].as_str().unwrap_or("")
                        )),
                        remediation: None,
                    });
                }
            }
        }
    }

    Ok(findings)
}
