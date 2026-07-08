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
    recursive: bool,
    no_fail: bool,
    severity_threshold: String,
    format: String,
    report_format: Option<String>,
) -> Result<()> {
    let is_json = format == "json";
    
    if !is_json {
        println!("Scanning directory: {} (recursive: {})", dir.display(), recursive);
    }

    let mut results = Vec::new();

    let mut builder = WalkBuilder::new(&dir);
    builder.hidden(true);
    builder.git_ignore(true);
    builder.filter_entry(|entry| {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name == "target" || name == "node_modules" || name == ".git" {
                return false;
            }
        }
        true
    });

    if !recursive {
        builder.max_depth(Some(1));
    }

    let walker = builder.build();

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
            
            if !is_json {
                print!("  Scanning {}... ", rel_path);
            }
            match engine.scan(&code, Some(&rel_path)).await {
                Ok(scan_res) => {
                    if !is_json {
                        if scan_res.summary == "Skipped (Excluded by configuration)" {
                            println!("Skipped (Excluded)");
                        } else {
                            println!("{}", format_risk_tier(&scan_res.risk_tier));
                        }
                    }
                    if scan_res.summary != "Skipped (Excluded by configuration)" && scan_res.risk_tier != "None" {
                        results.push((rel_path.to_string(), scan_res));
                    }
                }
                Err(e) => {
                    if !is_json {
                        println!("Error: {}", e);
                    }
                }
            }
        }
    }

    if is_json {
        let json_output = json!({
            "scanned_directory": dir.to_string_lossy(),
            "findings_count": results.len(),
            "results": results.iter().map(|(path, res)| {
                json!({
                    "file": path,
                    "risk_tier": res.risk_tier,
                    "summary": res.summary,
                    "findings": res.findings
                })
            }).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        print_summary(&results);
    }

    if let Some(path) = report_path {
        generate_report(&results, &path, report_format.as_deref())?;
    }

    if !no_fail && should_fail_build(&results, &severity_threshold) {
        return Err(anyhow::anyhow!(
            "Security scan failed: vulnerabilities found exceeding threshold '{}'",
            severity_threshold
        ));
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

fn format_risk_tier(tier: &str) -> String {
    match tier.to_lowercase().as_str() {
        "critical" => "\x1b[1;31m🔴 Critical\x1b[0m".to_string(),
        "high" => "\x1b[1;91m🟠 High\x1b[0m".to_string(),
        "medium" => "\x1b[1;33m🟡 Medium\x1b[0m".to_string(),
        "low" => "\x1b[1;34m🔵 Low\x1b[0m".to_string(),
        "none" => "\x1b[1;32m🟢 None\x1b[0m".to_string(),
        _ => tier.to_string(),
    }
}

fn format_severity(sev: &str) -> String {
    match sev.to_lowercase().as_str() {
        "critical" => "\x1b[1;31mCRITICAL\x1b[0m".to_string(),
        "high" => "\x1b[1;91mHIGH\x1b[0m".to_string(),
        "medium" => "\x1b[1;33mMEDIUM\x1b[0m".to_string(),
        "low" => "\x1b[1;34mLOW\x1b[0m".to_string(),
        _ => sev.to_string(),
    }
}

fn print_code_snippet(file_path: &str, line_num: usize) {
    if line_num == 0 { return; }
    if let Ok(content) = std::fs::read_to_string(file_path) {
        let lines: Vec<&str> = content.lines().collect();
        if line_num <= lines.len() {
            let line = lines[line_num - 1];
            // Context line before
            if line_num > 1 {
                println!("    \x1b[90m{:>4} | {}\x1b[0m", line_num - 1, lines[line_num - 2]);
            }
            // The offending line
            println!("    \x1b[1;31m{:>4} | {}\x1b[0m", line_num, line);
            // Red indicator pointer
            let lead_spaces = line.chars().take_while(|c| c.is_whitespace()).count();
            let pointer_indent = " ".repeat(9 + lead_spaces);
            println!("{}\x1b[1;31m^^^^^^^^^^^^^^^^^^^^^^^^^\x1b[0m", pointer_indent);
            // Context line after
            if line_num < lines.len() {
                println!("    \x1b[90m{:>4} | {}\x1b[0m", line_num + 1, lines[line_num]);
            }
        }
    }
}

fn should_fail_build(results: &[(String, ScanResult)], threshold: &str) -> bool {
    let threshold_num = match threshold.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0, // "none": fail on any finding
    };

    for (_, res) in results {
        let risk_num = match res.risk_tier.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        if risk_num >= threshold_num && risk_num > 0 {
            return true;
        }
    }
    false
}

fn print_summary(results: &[(String, ScanResult)]) {
    println!("\n\x1b[1;36m==================================================\x1b[0m");
    println!("\x1b[1;36m🔍 CodeAegis Scan Summary\x1b[0m");
    println!("\x1b[1;36m==================================================\x1b[0m");

    if results.is_empty() {
        println!("\x1b[1;32m🟢 No vulnerabilities found! Code is clean.\x1b[0m");
        return;
    }

    for (path, res) in results {
        let risk_badge = format_risk_tier(&res.risk_tier);
        println!("\n📂 \x1b[1mFile:\x1b[0m \x1b[4m{}\x1b[0m", path);
        println!("⚠️  \x1b[1mRisk Tier:\x1b[0m {}", risk_badge);
        println!("ℹ️  \x1b[1mCritic Summary:\x1b[0m {}", res.summary);
        
        println!("\n\x1b[1mFindings:\x1b[0m");
        for finding in &res.findings {
            let sev_badge = format_severity(&finding.severity);
            println!("  • \x1b[1m[{}]\x1b[0m ({}): {}", finding.tool, sev_badge, finding.message);
            
            if let Some(loc) = &finding.location {
                if let Some(last_part) = loc.split(':').last() {
                    if let Ok(line_num) = last_part.trim().parse::<usize>() {
                        print_code_snippet(path, line_num);
                    }
                }
            }
        }
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
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
    println!("SARIF report written to: {}", path.display());

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

fn generate_json(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let json_output = json!({
        "results": results.iter().map(|(rel_path, res)| {
            json!({
                "file": rel_path,
                "risk_tier": res.risk_tier,
                "summary": res.summary,
                "findings": res.findings
            })
        }).collect::<Vec<_>>()
    });
    let data = serde_json::to_string_pretty(&json_output)?;
    std::fs::write(path, data)?;
    println!("JSON report written to: {}", path.display());
    Ok(())
}

fn generate_junit(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<testsuites name=\"CodeAegis Security Scan\">\n");
    
    let total_tests = results.len();
    let total_failures = results.iter().filter(|(_, res)| res.risk_tier != "None" && !res.findings.is_empty()).count();
    
    xml.push_str(&format!(
        "  <testsuite name=\"Static Security Analysis\" tests=\"{}\" failures=\"{}\" errors=\"0\">\n",
        total_tests, total_failures
    ));
    
    for (file_path, res) in results {
        let safe_file = file_path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        if res.findings.is_empty() {
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"CodeAegis.Security\"/>\n",
                safe_file
            ));
        } else {
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"CodeAegis.Security\">\n",
                safe_file
            ));
            for f in &res.findings {
                let safe_msg = f.message.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                let rem_str = f.remediation.as_deref().unwrap_or("No remediation hint available.");
                let safe_rem = rem_str.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                xml.push_str(&format!(
                    "      <failure message=\"[{}] {}\">\n",
                    f.severity, safe_msg
                ));
                xml.push_str(&format!(
                    "Tool: {}\nSeverity: {}\nLocation: {:?}\nRemediation: {}\n",
                    f.tool, f.severity, f.location, safe_rem
                ));
                xml.push_str("      </failure>\n");
            }
            xml.push_str("    </testcase>\n");
        }
    }
    
    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");
    
    std::fs::write(path, xml)?;
    println!("JUnit XML report written to: {}", path.display());
    Ok(())
}

fn generate_markdown(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let mut md = String::new();
    md.push_str("# 🛡️ CodeAegis Security Scan Report\n\n");
    md.push_str("## Summary\n\n");
    md.push_str("| File | Risk Tier | Findings Count | Summary |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for (file_path, res) in results {
        md.push_str(&format!(
            "| `{}` | **{}** | {} | {} |\n",
            file_path, res.risk_tier, res.findings.len(), res.summary
        ));
    }
    
    md.push_str("\n## Detailed Findings\n\n");
    if results.iter().all(|(_, res)| res.findings.is_empty()) {
        md.push_str("🟢 No vulnerabilities detected in this scan.\n");
    } else {
        for (file_path, res) in results {
            if res.findings.is_empty() { continue; }
            md.push_str(&format!("### 📂 `{}`\n", file_path));
            md.push_str(&format!("**Risk Level:** {}\n\n", res.risk_tier));
            for f in &res.findings {
                md.push_str(&format!("*   **[{}] {}**\n", f.severity, f.message));
                md.push_str(&format!("    *   **Tool:** {}\n", f.tool));
                if let Some(loc) = &f.location {
                    md.push_str(&format!("    *   **Location:** `{}`\n", loc));
                }
                if let Some(rem) = &f.remediation {
                    md.push_str(&format!("    *   **Remediation:** {}\n", rem));
                }
                md.push_str("\n");
            }
        }
    }
    
    std::fs::write(path, md)?;
    println!("Markdown report written to: {}", path.display());
    Ok(())
}

fn generate_csv(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let mut csv = String::new();
    csv.push_str("File,Risk Tier,Tool,Severity,Message,Location,Remediation\n");
    for (file_path, res) in results {
        if res.findings.is_empty() {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"\",\"\",\"\",\"\",\"\"\n",
                file_path.replace('"', "\"\""),
                res.risk_tier.replace('"', "\"\"")
            ));
        } else {
            for f in &res.findings {
                let loc = f.location.as_deref().unwrap_or("");
                let rem = f.remediation.as_deref().unwrap_or("");
                csv.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                    file_path.replace('"', "\"\""),
                    res.risk_tier.replace('"', "\"\""),
                    f.tool.replace('"', "\"\""),
                    f.severity.replace('"', "\"\""),
                    f.message.replace('"', "\"\""),
                    loc.replace('"', "\"\""),
                    rem.replace('"', "\"\"")
                ));
            }
        }
    }
    std::fs::write(path, csv)?;
    println!("CSV report written to: {}", path.display());
    Ok(())
}

fn generate_html(results: &[(String, ScanResult)], path: &Path) -> Result<()> {
    let mut html = String::new();
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeAegis Security Scan Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f6f8fa;
            color: #24292f;
            margin: 0;
            padding: 24px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #d0d7de;
            border-radius: 6px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        h1 {
            font-size: 28px;
            margin-top: 0;
            border-bottom: 1px solid #d0d7de;
            padding-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .summary-card {
            background: #f6f8fa;
            border: 1px solid #d0d7de;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 24px;
        }
        .file-section {
            margin-top: 24px;
            border: 1px solid #d0d7de;
            border-radius: 6px;
            overflow: hidden;
        }
        .file-header {
            background-color: #f6f8fa;
            padding: 12px 16px;
            font-weight: bold;
            border-bottom: 1px solid #d0d7de;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-body {
            padding: 16px;
        }
        .finding-item {
            border-left: 4px solid #cf222e;
            background: #fff8f8;
            padding: 12px;
            margin-bottom: 12px;
            border-radius: 0 6px 6px 0;
        }
        .finding-item.low { border-left-color: #0969da; background: #f0f7ff; }
        .finding-item.medium { border-left-color: #d46b08; background: #fffbe6; }
        .finding-item.high { border-left-color: #bc1e28; background: #fff5f5; }
        .badge {
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge.critical { background: #ffebe9; color: #cf222e; }
        .badge.high { background: #ffebe9; color: #cf222e; }
        .badge.medium { background: #fff8c5; color: #9a6700; }
        .badge.low { background: #ddf4ff; color: #0969da; }
        .badge.none { background: #dafbe1; color: #1a7f37; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CodeAegis Security Scan Report</h1>
        <div class="summary-card">
            <strong>Scan Summary:</strong> Total files scanned: "#);
    html.push_str(&format!("{}", results.len()));
    html.push_str(r#".
        </div>
    "#);
    
    for (file_path, res) in results {
        let badge_class = res.risk_tier.to_lowercase();
        html.push_str(&format!(
            r#"<div class="file-section">
                <div class="file-header">
                    <span>📂 {}</span>
                    <span class="badge {}">{}</span>
                </div>
                <div class="file-body">
                    <p><strong>Critic Verdict:</strong> {}</p>
            "#,
            file_path, badge_class, res.risk_tier, res.summary
        ));
        
        if res.findings.is_empty() {
            html.push_str("<p style=\"color: #1a7f37;\">🟢 No vulnerabilities found in this file.</p>");
        } else {
            for f in &res.findings {
                let f_class = f.severity.to_lowercase();
                let rem_str = f.remediation.as_deref().unwrap_or("No remediation hint available.");
                html.push_str(&format!(
                    r#"<div class="finding-item {}">
                        <strong>[{}] {}</strong> (Severity: {})<br>
                        <span style="font-size: 13px; color: #57606a;">Location: {}</span><br>
                        <p style="margin-top: 8px; margin-bottom: 0;"><strong>💡 Remediation:</strong> {}</p>
                    </div>"#,
                    f_class, f.tool, f.message, f.severity, f.location.as_deref().unwrap_or(""), rem_str
                ));
            }
        }
        
        html.push_str("</div></div>");
    }
    
    html.push_str("</div></body></html>");
    std::fs::write(path, html)?;
    println!("HTML report written to: {}", path.display());
    Ok(())
}

pub fn generate_report(results: &[(String, ScanResult)], path: &Path, format_opt: Option<&str>) -> Result<()> {
    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase());

    let format = if let Some(fmt) = format_opt {
        fmt.to_lowercase()
    } else if let Some(ext) = extension {
        match ext.as_str() {
            "sarif" => "sarif".to_string(),
            "json" => "json".to_string(),
            "xml" => "junit".to_string(),
            "md" | "markdown" => "markdown".to_string(),
            "csv" => "csv".to_string(),
            "html" | "htm" => "html".to_string(),
            _ => "sarif".to_string(),
        }
    } else {
        "sarif".to_string()
    };

    match format.as_str() {
        "json" => generate_json(results, path),
        "junit" | "xml" => generate_junit(results, path),
        "markdown" | "md" => generate_markdown(results, path),
        "csv" => generate_csv(results, path),
        "html" => generate_html(results, path),
        _ => generate_sarif(results, path),
    }
}

pub fn handle_init(dir: &Path) -> Result<()> {
    let skill_dir = dir.join(".agent/skills/codeaegis");
    std::fs::create_dir_all(&skill_dir)
        .context(format!("Failed to create skill directory: {}", skill_dir.display()))?;

    let skill_file_path = skill_dir.join("SKILL.md");
    
    let skill_content = r#"---
name: codeaegis
description: Protects the codebase by running real-time security verification on code changes. Use this skill whenever you write or modify code to verify there are no secrets, vulnerable dependencies, or insecure configurations.
---

# CodeAegis Security Scanner Skill

This skill allows you to run real-time security verification on code changes using the local `codeaegis` command-line scanner.

## Triggering

This skill is automatically activated when you write or modify code files (such as Rust, Python, JavaScript, Terraform, etc.). You should use the `codeaegis` binary to scan any code you produce.

## Commands and Usage

You can run the following shell commands in the project directory:

### 1. Scan a specific file or directory
```bash
codeaegis scan <PATH>
```

Example:
```bash
codeaegis scan ./src/main.rs
```

### 2. Scan the entire workspace
```bash
codeaegis scan .
```

### 3. Scan and generate a security report
To generate a SARIF report of findings:
```bash
codeaegis scan . --report report.sarif
```

## How to Handle Scan Results

- **Risk Tier: None**: The code is safe to propose or apply.
- **Risk Tier: Low / Medium / High / Critical**:
  1. Review the printed findings and the summary provided by the CodeAegis Critic (LLM Judge).
  2. Fix the issues identified (e.g. remove hardcoded secrets, update insecure dependencies, or fix IaC misconfigurations).
  3. Re-run `codeaegis scan` to confirm the code is clean before presenting it to the user.
"#;

    std::fs::write(&skill_file_path, skill_content)
        .context(format!("Failed to write SKILL.md to {}", skill_file_path.display()))?;

    println!("Initialized Workspace Agent Skill for CodeAegis at: {}", skill_file_path.display());
    Ok(())
}

pub fn handle_setup() -> Result<()> {
    use std::io::{self, Write};
    
    println!("\n\x1b[1;36m==================================================\x1b[0m");
    println!("\x1b[1;36m🚀 CodeAegis Interactive Setup Wizard\x1b[0m");
    println!("\x1b[1;36m==================================================\x1b[0m");
    println!("This wizard will help you set up credentials, exclusion rules, and workspace skills.\n");

    // 1. LLM Credentials Setup
    let providers = vec!["gemini", "openai", "grok"];
    for provider in providers {
        print!("🔑 Would you like to configure the API key for '{}'? [y/N]: ", provider);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() == "y" {
            crate::auth::handle_login(provider)?;
        }
    }

    // 2. Exclusions Setup
    print!("\n🚫 Would you like to configure default file exclusions? [y/N]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() == "y" {
        print!("Enter file/directory pattern to exclude (e.g. node_modules/**, secrets.key): ");
        io::stdout().flush()?;
        let mut pattern = String::new();
        io::stdin().read_line(&mut pattern)?;
        let pattern = pattern.trim();
        if !pattern.is_empty() {
            crate::exclusions::handle_exclude(pattern, "all")?;
        }
    }

    // 3. Workspace Skill Setup
    print!("\n🛠️  Would you like to initialize the Workspace Agent Skill (SKILL.md) in the current directory? [y/N]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() == "y" {
        handle_init(&PathBuf::from("."))?;
    }

    // 4. Print Status
    println!("\n\x1b[1;32m==================================================\x1b[0m");
    println!("\x1b[1;32m✅ CodeAegis Setup Complete!\x1b[0m");
    println!("\x1b[1;32m==================================================\x1b[0m");
    crate::auth::handle_status()?;

    Ok(())
}
