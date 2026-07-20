use crate::cache::Finding;
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub async fn scan(code: &str, file_path: Option<&str>) -> Result<Vec<Finding>> {
    let mut child = Command::new("trufflehog")
        .arg("stdin")
        .arg("--json")
        .arg("--no-verification")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Failed to open stdin"))?;
    tokio::io::AsyncWriteExt::write_all(&mut stdin, code.as_bytes()).await?;
    drop(stdin);

    let result = timeout(Duration::from_secs(10), child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            if !output.stdout.is_empty() {
                parse_trufflehog_output(&output.stdout, file_path)
            } else {
                Ok(vec![])
            }
        }
        Ok(Err(e)) => Err(anyhow!("TruffleHog execution failed: {}", e)),
        Err(_) => Err(anyhow!("TruffleHog timed out")),
    }
}

fn parse_trufflehog_output(stdout: &[u8], file_path: Option<&str>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let stdout_str = String::from_utf8_lossy(stdout);

    for line in stdout_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let detector = v["DetectorName"].as_str().unwrap_or("Unknown");
            let verified = v["Verified"].as_bool().unwrap_or(false);

            let line_num = v["SourceMetadata"]["Data"]["Filesystem"]["line"]
                .as_u64()
                .unwrap_or(0);

            let severity = if verified {
                "CRITICAL".to_string()
            } else {
                "HIGH".to_string()
            };

            let location = if line_num > 0 {
                Some(format!("{}:{}", file_path.unwrap_or(""), line_num))
            } else {
                file_path.map(|s| s.to_string())
            };

            let message = format!("{} secret detected by TruffleHog", detector);

            findings.push(Finding {
                tool: "TruffleHog".to_string(),
                severity,
                message,
                location,
                remediation: Some(
                    "Revoke the exposed credential immediately and remove it from history"
                        .to_string(),
                ),
            });
        }
    }

    Ok(findings)
}
