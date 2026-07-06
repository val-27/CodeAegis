use crate::engine::ScanEngine;
use crate::cache::ScanResult;
use anyhow::{Result, Context};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde_json::json;

pub async fn run_directory_scan(
    engine: Arc<ScanEngine>,
    dir: PathBuf,
    report_path: Option<PathBuf>,
) -> Result<()> {
    println!("Scanning directory: {}", dir.display());

    let mut results = Vec::new();

    let walker = WalkBuilder::new(&dir)
        .hidden(true)
        .git_ignore(true)
        .filter_entry(|entry| {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name == "target" || name == "node_modules" || name == ".git" {
                    return false;
                }
            }
            true
        })
        .build();

    for result in walker {
        let entry = result?;
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let path = entry.path();
            
            // Skip binary files and those that are too large (> 1MB)
            if is_binary(path) || entry.metadata()?.len() > 1024 * 1024 {
                continue;
            }

            let code = match tokio::fs::read_to_string(path).await {
                Ok(c) => c,
                Err(_) => continue, // Skip files we can't read as UTF-8
            };

            let rel_path = path.strip_prefix(&dir).unwrap_or(path).to_string_lossy();
            
            print!("  Scanning {}... ", rel_path);
            match engine.scan(&code, Some(&rel_path)).await {
                Ok(scan_res) => {
                    println!("{}", scan_res.risk_tier);
                    if scan_res.risk_tier != "None" {
                        results.push((rel_path.to_string(), scan_res));
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }
    }

    print_summary(&results);

    if let Some(path) = report_path {
        generate_sarif(&results, &path)?;
    }

    Ok(())
}

fn is_binary(path: &Path) -> bool {
    // Expanded list of non-code extensions to skip
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        return matches!(ext.as_str(), 
            "bin" | "exe" | "obj" | "o" | "so" | "dll" | "dylib" | // Binaries
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "svg" | "mp4" | "mov" | "mp3" | "wav" | // Media
            "pdf" | "zip" | "gz" | "tar" | "7z" | "rar" | // Archives
            "sqlite" | "db" | "sqlite-wal" | "sqlite-shm" | "lock" | "plist" | // DB/System
            "woff" | "woff2" | "ttf" | "eot" // Fonts
        );
    }
    
    // Check for common noisy filenames without extensions
    if let Some(name) = path.file_name() {
        let name = name.to_string_lossy().to_lowercase();
        return matches!(name.as_str(), ".ds_store" | "thumbs.db");
    }

    false
}

fn print_summary(results: &[(String, ScanResult)]) {
    println!("\n--- Scan Summary ---");
    if results.is_empty() {
        println!("No vulnerabilities found!");
        return;
    }

    for (path, res) in results {
        println!("\nFile: {}", path);
        println!("Risk Tier: {}", res.risk_tier);
        println!("Summary: {}", res.summary);
        for finding in &res.findings {
            println!("  [{}] {}: {}", finding.tool, finding.severity, finding.message);
        }
    }
}

fn generate_sarif(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let mut sarif_results = Vec::new();

    for (rel_path, res) in results {
        for finding in &res.findings {
            sarif_results.push(json!({
                "ruleId": finding.tool,
                "level": severity_to_sarif(&finding.severity),
                "message": {
                    "text": finding.message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_path
                            }
                        }
                    }
                ]
            }));
        }
    }

    let sarif = json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeAegis",
                        "version": "0.1.0"
                    }
                },
                "results": sarif_results
            }
        ]
    });

    let content = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(path, content).context("Failed to write SARIF report")?;
    println!("\nSARIF report written to: {}", path.display());

    Ok(())
}

fn severity_to_sarif(sev: &str) -> &str {
    match sev.to_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        "LOW" => "note",
        _ => "none",
    }
}
