use crate::cache::{ResultCache, ScanResult, Finding};
use crate::critic::Critic;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::broadcast;
use anyhow::Result;

pub struct ScanEngine {
    cache: Arc<ResultCache>,
    critic: Arc<Critic>,
    active_scans: DashMap<String, broadcast::Sender<ScanResult>>,
    pub enable_logs: std::sync::atomic::AtomicBool,
    enabled_scanners: Option<Vec<String>>,
    disabled_scanners: Option<Vec<String>>,
}

impl ScanEngine {
    pub fn new(
        cache: Arc<ResultCache>,
        critic: Arc<Critic>,
        enabled_scanners: Option<Vec<String>>,
        disabled_scanners: Option<Vec<String>>,
    ) -> Self {
        Self {
            cache,
            critic,
            active_scans: DashMap::new(),
            enable_logs: std::sync::atomic::AtomicBool::new(false),
            enabled_scanners,
            disabled_scanners,
        }
    }

    pub fn set_logging(&self, enabled: bool) {
        self.enable_logs.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn scan(&self, code: &str, file_path: Option<&str>) -> Result<ScanResult> {
        let hash = self.compute_hash(code);

        // 0. Exclusions Check
        let mut skip_all = false;
        let mut file_skips = Vec::new();
        if let Some(path) = file_path {
            if let Ok(config) = crate::exclusions::load_exclusions() {
                for excl in &config.exclusions {
                    if crate::exclusions::is_pattern_match(path, &excl.pattern) {
                        if excl.scanners.iter().any(|s| s == "all" || s == "all") {
                            skip_all = true;
                            break;
                        } else {
                            file_skips.extend(excl.scanners.clone());
                        }
                    }
                }
            }
        }

        if skip_all {
            return Ok(ScanResult {
                hash,
                findings: Vec::new(),
                risk_tier: "None".to_string(),
                summary: "Skipped (Excluded by configuration)".to_string(),
            });
        }

        // 1. Cache Check
        if let Some(result) = self.cache.get(&hash).await {
            return Ok(result);
        }

        // 2. Single-Flight Lock
        // Check if a scan is already in progress for this hash
        let (tx, mut rx) = {
            if let Some(sender) = self.active_scans.get(&hash) {
                // Subscribe to existing scan
                (None, sender.subscribe())
            } else {
                // Start a new scan
                let (tx, rx) = broadcast::channel(1);
                self.active_scans.insert(hash.clone(), tx.clone());
                (Some(tx), rx)
            }
        };

        if let Some(tx) = tx {
            // I am the Lead Task
            let result = self.execute_scans(hash.clone(), code, file_path, file_skips).await?;
            
            // 3. Cache the result
            self.cache.insert(hash.clone(), result.clone()).await;

            // 4. Notify subscribers
            let _ = tx.send(result.clone());

            // 5. Cleanup active scan
            self.active_scans.remove(&hash);

            Ok(result)
        } else {
            // I am a subscriber
            // Wait for the result from the Lead Task
            let result = rx.recv().await?;
            Ok(result)
        }
    }

    fn compute_hash(&self, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }

    async fn execute_scans(
        &self,
        hash: String,
        code: &str,
        file_path: Option<&str>,
        file_skips: Vec<String>,
    ) -> Result<ScanResult> {
        use crate::scanners::{trufflehog, osv, trivy, opengrep};

        let run_truffle = self.is_scanner_enabled("trufflehog") && !file_skips.contains(&"trufflehog".to_string());
        let run_osv = self.is_scanner_enabled("osv") && !file_skips.contains(&"osv".to_string());
        let run_trivy = self.is_scanner_enabled("trivy") && !file_skips.contains(&"trivy".to_string());
        let run_opengrep = self.is_scanner_enabled("opengrep") && !file_skips.contains(&"opengrep".to_string());

        // Run scanners in parallel
        let (truffle_res, osv_res, trivy_res, opengrep_res) = tokio::join!(
            async { if run_truffle { trufflehog::scan(code, file_path).await } else { Ok(vec![]) } },
            async { if run_osv { osv::scan(code, file_path).await } else { Ok(vec![]) } },
            async { if run_trivy { trivy::scan(code, file_path).await } else { Ok(vec![]) } },
            async { if run_opengrep { opengrep::scan(code, file_path).await } else { Ok(vec![]) } }
        );

        let mut all_findings = Vec::new();
        let mut active_scanners = Vec::new();
        
        if let Ok(findings) = truffle_res { 
            if !findings.is_empty() { active_scanners.push("TruffleHog"); }
            all_findings.extend(findings); 
        }
        if let Ok(findings) = osv_res { 
            if !findings.is_empty() { active_scanners.push("OSV"); }
            all_findings.extend(findings); 
        }
        if let Ok(findings) = trivy_res { 
            if !findings.is_empty() { active_scanners.push("Trivy"); }
            all_findings.extend(findings); 
        }
        if let Ok(findings) = opengrep_res { 
            if !findings.is_empty() { active_scanners.push("Opengrep"); }
            all_findings.extend(findings); 
        }

        // Apply inline suppression filter
        let all_findings = filter_ignored_findings(code, all_findings);

        if all_findings.is_empty() {
            return Ok(ScanResult {
                hash,
                findings: Vec::new(),
                risk_tier: "None".to_string(),
                summary: "No vulnerabilities found by static scanners.".to_string(),
            });
        }

        // If the critic is disabled, we map raw scanner findings to a default risk tier
        if !self.critic.is_enabled() {
            let mut enriched_findings = all_findings;
            for f in &mut enriched_findings {
                if f.remediation.is_none() {
                    let tool = f.tool.to_lowercase();
                    let msg = f.message.to_lowercase();
                    let suggestion = if tool.contains("trufflehog") || msg.contains("secret") || msg.contains("key") || msg.contains("password") || msg.contains("token") {
                        "Do not commit plain-text credentials. Use environment variables (e.g. process.env, std::env) loaded via a gitignored file (.env) or retrieve secrets from a secure cloud secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)."
                    } else if tool.contains("trivy") || tool.contains("osv") || msg.contains("vulnerab") || msg.contains("cve") {
                        "Upgrade this package dependency version to its latest non-vulnerable release. Run package manager security upgrades (e.g., npm audit fix, cargo update)."
                    } else if tool.contains("opengrep") || msg.contains("injection") || msg.contains("eval") || msg.contains("exec") || msg.contains("xss") {
                        "Avoid unvalidated user input inside execution sinks. Use parameterized SQL queries, context-aware HTML encoding/escaping libraries, and avoid direct OS shell spawners if safer native language APIs are available."
                    } else {
                        "Analyze the source code at this location to ensure proper input validation, secure defaults, and robust credential storage configurations."
                    };
                    f.remediation = Some(suggestion.to_string());
                }
            }
            let risk_tier = determine_raw_risk_tier(&enriched_findings);
            let summary = format!(
                "Static scanners found {} vulnerability/ies (Critic LLM Judge bypassed due to missing API key).",
                enriched_findings.len()
            );
            let final_result = ScanResult {
                hash,
                findings: enriched_findings,
                risk_tier,
                summary,
            };

            if self.enable_logs.load(std::sync::atomic::Ordering::Relaxed) {
                let scanners_list = if active_scanners.is_empty() { "None".to_string() } else { active_scanners.join(", ") };
                tracing::warn!(
                    "🔍 Scan Result (Static Only): Scanners[{}] | Risk[{}] | Summary: {}",
                    scanners_list,
                    final_result.risk_tier,
                    final_result.summary
                );
            }
            return Ok(final_result);
        }

        // Agentic CRITIC Check
        let final_result = self.critic.judge(hash, code, all_findings, file_path).await?;

        if self.enable_logs.load(std::sync::atomic::Ordering::Relaxed) {
            let scanners_list = if active_scanners.is_empty() { "None".to_string() } else { active_scanners.join(", ") };
            tracing::warn!(
                "🔍 Scan Result: Scanners[{}] | Critic[{}] | Summary: {}",
                scanners_list,
                final_result.risk_tier,
                final_result.summary
            );
        }

        Ok(final_result)
    }

    fn is_scanner_enabled(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        
        if let Some(disabled) = &self.disabled_scanners {
            if disabled.iter().any(|s| s.to_lowercase() == name_lower) {
                return false;
            }
        }
        
        if let Some(enabled) = &self.enabled_scanners {
            return enabled.iter().any(|s| s.to_lowercase() == name_lower);
        }
        
        true
    }
}

fn determine_raw_risk_tier(findings: &[Finding]) -> String {
    let mut highest = "None";
    for f in findings {
        let severity = f.severity.to_uppercase();
        match severity.as_str() {
            "CRITICAL" => return "Critical".to_string(),
            "HIGH" => highest = "High",
            "MEDIUM" if highest != "High" => highest = "Medium",
            "LOW" if highest != "High" && highest != "Medium" => highest = "Low",
            _ => {}
        }
    }
    
    match highest {
        "High" => "High".to_string(),
        "Medium" => "Medium".to_string(),
        "Low" => "Low".to_string(),
        _ => "None".to_string(),
    }
}

fn filter_ignored_findings(code: &str, findings: Vec<Finding>) -> Vec<Finding> {
    let lines: Vec<&str> = code.lines().collect();
    let mut filtered = Vec::new();

    for f in findings {
        let mut ignored = false;
        
        if let Some(loc) = &f.location {
            if let Some(last_part) = loc.split(':').last() {
                if let Ok(line_num) = last_part.trim().parse::<usize>() {
                    if line_num > 0 && line_num <= lines.len() {
                        let current_line = lines[line_num - 1];
                        
                        // Check same-line ignore
                        if current_line.contains("codeaegis:ignore") {
                            ignored = true;
                        }
                        
                        // Check ignore-next-line on preceding line
                        if line_num > 1 {
                            let prev_line = lines[line_num - 2];
                            if prev_line.contains("codeaegis:ignore-next-line") {
                                ignored = true;
                            }
                        }
                    }
                }
            }
        }
        
        if !ignored {
            filtered.push(f);
        }
    }

    filtered
}
