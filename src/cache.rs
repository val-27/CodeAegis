use moka::future::Cache;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use std::collections::HashMap;

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
    pub remediation: Option<String>,
}

pub struct ResultCache {
    cache: Cache<String, ScanResult>,
    cache_file: PathBuf,
}

impl ResultCache {
    pub fn new(capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();

        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let cache_file = PathBuf::from(home).join(".codeaegis-cache.json");

        let cache_instance = Self { cache, cache_file };
        
        // Load existing cache from file
        if let Ok(data) = std::fs::read_to_string(&cache_instance.cache_file) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, ScanResult>>(&data) {
                let cache_clone = cache_instance.cache.clone();
                tokio::spawn(async move {
                    for (hash, val) in map {
                        cache_clone.insert(hash, val).await;
                    }
                });
            }
        }

        cache_instance
    }

    pub async fn get(&self, hash: &str) -> Option<ScanResult> {
        self.cache.get(hash).await
    }

    pub async fn insert(&self, hash: String, result: ScanResult) {
        self.cache.insert(hash.clone(), result.clone()).await;

        // Persist cache entry to file asynchronously
        let cache_file = self.cache_file.clone();
        tokio::spawn(async move {
            let mut map: HashMap<String, ScanResult> = HashMap::new();
            if let Ok(data) = std::fs::read_to_string(&cache_file) {
                if let Ok(existing) = serde_json::from_str::<HashMap<String, ScanResult>>(&data) {
                    map = existing;
                }
            }
            map.insert(hash, result);
            if let Ok(serialized) = serde_json::to_string_pretty(&map) {
                let _ = std::fs::write(&cache_file, serialized);
            }
        });
    }
}
