use anyhow::{Result, anyhow};
use crate::cache::Finding;
use serde_json::json;
use std::time::Duration;

pub async fn scan(code: &str, file_path: Option<&str>) -> Result<Vec<Finding>> {
    let file_name = file_path.unwrap_or("");
    if !file_name.ends_with("requirements.txt") && !code.contains("==") {
        return Ok(vec![]);
    }

    // Parse dependencies
    let mut queries = Vec::new();
    let mut dep_info = Vec::new();
    
    for line in code.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        let clean_line = if let Some(idx) = line.find(';') {
            &line[..idx]
        } else {
            line
        }.trim();

        if let Some(idx) = clean_line.find("==") {
            let name = clean_line[..idx].trim().to_string();
            let version = clean_line[idx + 2..].trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                queries.push(json!({
                    "package": {
                        "name": name.clone(),
                        "ecosystem": "PyPI"
                    },
                    "version": version.clone()
                }));
                dep_info.push((name, version));
            }
        }
    }

    if queries.is_empty() {
        return Ok(vec![]);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let payload = json!({ "queries": queries });

    let response = client.post("https://api.osv.dev/v1/querybatch")
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("OSV API querybatch failed with status: {}", response.status()));
    }

    let body: serde_json::Value = response.json().await?;
    let results = body["results"].as_array().ok_or_else(|| anyhow!("Invalid OSV API response structure"))?;

    let mut findings = Vec::new();
    let mut detail_futures = Vec::new();

    for (idx, result) in results.iter().enumerate() {
        if let Some(vulns) = result["vulns"].as_array() {
            if idx < dep_info.len() {
                let (dep_name, dep_version) = &dep_info[idx];
                for vuln in vulns {
                    if let Some(id) = vuln["id"].as_str() {
                        let id = id.to_string();
                        let dep_name = dep_name.clone();
                        let dep_version = dep_version.clone();
                        let client_clone = client.clone();
                        
                        detail_futures.push(tokio::spawn(async move {
                            let fallback = fallback_finding(&id, &dep_name, &dep_version);
                            fetch_vuln_details(&client_clone, id, dep_name, dep_version)
                                .await
                                .unwrap_or(fallback)
                        }));
                    }
                }
            }
        }
    }

    for fut in detail_futures {
        if let Ok(finding) = fut.await {
            findings.push(finding);
        }
    }

    Ok(findings)
}

async fn fetch_vuln_details(client: &reqwest::Client, id: String, dep_name: String, dep_version: String) -> Result<Finding> {
    let url = format!("https://api.osv.dev/v1/vulns/{}", id);
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Ok(fallback_finding(&id, &dep_name, &dep_version));
    }

    let val: serde_json::Value = response.json().await?;
    let summary = val["summary"].as_str().unwrap_or("");
    let details = val["details"].as_str().unwrap_or("");
    let message = if !summary.is_empty() {
        format!("Vulnerability {} in {}=={}: {}", id, dep_name, dep_version, summary)
    } else if !details.is_empty() {
        let truncated_details = if details.len() > 100 { &details[..100] } else { details };
        format!("Vulnerability {} in {}=={}: {}", id, dep_name, dep_version, truncated_details)
    } else {
        format!("Vulnerability {} found in package {}=={}", id, dep_name, dep_version)
    };

    let mut severity = "HIGH".to_string();
    if let Some(sev) = val["database_specific"]["severity"].as_str() {
        severity = sev.to_uppercase();
    } else if let Some(sevs) = val["severity"].as_array() {
        for s in sevs {
            if let Some(score) = s["score"].as_str() {
                if score.contains("CVSS") {
                    // keep default
                }
            }
        }
    }

    let mut remediation = None;
    if let Some(affected) = val["affected"].as_array() {
        for aff in affected {
            if let Some(ranges) = aff["ranges"].as_array() {
                for r in ranges {
                    if let Some(events) = r["events"].as_array() {
                        for ev in events {
                            if let Some(fixed) = ev["fixed"].as_str() {
                                remediation = Some(format!("Upgrade {} to v{} or higher", dep_name, fixed));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Finding {
        tool: "OSV".to_string(),
        severity,
        message,
        location: Some(format!("requirements.txt:{}", dep_name)),
        remediation,
    })
}

fn fallback_finding(id: &str, dep_name: &str, dep_version: &str) -> Finding {
    Finding {
        tool: "OSV".to_string(),
        severity: "HIGH".to_string(),
        message: format!("Vulnerability {} found in package {}=={}", id, dep_name, dep_version),
        location: Some(format!("requirements.txt:{}", dep_name)),
        remediation: None,
    }
}
