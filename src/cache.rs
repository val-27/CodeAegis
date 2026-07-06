use moka::future::Cache;
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub hash: String,
    pub findings: Vec<Finding>,
    pub risk_tier: String, // e.g., "Critical", "High", "Medium", "Low", "None"
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub tool: String,
    pub severity: String,
    pub message: String,
    pub location: Option<String>,
}

pub struct ResultCache {
    cache: Cache<String, ScanResult>,
}

impl ResultCache {
    pub fn new(capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        Self { cache }
    }

    pub async fn get(&self, hash: &str) -> Option<ScanResult> {
        self.cache.get(hash).await
    }

    pub async fn insert(&self, hash: String, result: ScanResult) {
        self.cache.insert(hash, result).await;
    }
}
