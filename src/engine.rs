use crate::cache::{ResultCache, ScanResult};
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
}

impl ScanEngine {
    pub fn new(cache: Arc<ResultCache>, critic: Arc<Critic>) -> Self {
        Self {
            cache,
            critic,
            active_scans: DashMap::new(),
            enable_logs: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn set_logging(&self, enabled: bool) {
        self.enable_logs.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn scan(&self, code: &str, file_path: Option<&str>) -> Result<ScanResult> {
        let hash = self.compute_hash(code);

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
            let result = self.execute_scans(hash.clone(), code, file_path).await?;
            
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

    async fn execute_scans(&self, hash: String, code: &str, file_path: Option<&str>) -> Result<ScanResult> {
        use crate::scanners::{trufflehog, osv, trivy};

        // Run scanners in parallel
        let (truffle_res, osv_res, trivy_res) = tokio::join!(
            trufflehog::scan(code, file_path),
            osv::scan(code, file_path),
            trivy::scan(code, file_path)
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

        if all_findings.is_empty() {
            return Ok(ScanResult {
                hash,
                findings: Vec::new(),
                risk_tier: "None".to_string(),
                summary: "No vulnerabilities found by static scanners.".to_string(),
            });
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
}
