use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExclusionEntry {
    pub pattern: String,
    pub scanners: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ExclusionsConfig {
    pub exclusions: Vec<ExclusionEntry>,
}

pub fn load_exclusions() -> Result<ExclusionsConfig> {
    let path = Path::new(".agent/skills/codeaegis/exclusions.json");
    if !path.exists() {
        return Ok(ExclusionsConfig::default());
    }
    let data = std::fs::read_to_string(path)?;
    let config: ExclusionsConfig = serde_json::from_str(&data)?;
    Ok(config)
}

pub fn save_exclusions(config: &ExclusionsConfig) -> Result<()> {
    let dir = Path::new(".agent/skills/codeaegis");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("exclusions.json");
    let data = serde_json::to_string_pretty(config)?;
    std::fs::write(path, data)?;
    Ok(())
}

pub fn handle_exclude(pattern: &str, scanners_str: &str) -> Result<()> {
    let mut config = load_exclusions()?;

    let scanners: Vec<String> = scanners_str
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();

    if let Some(entry) = config.exclusions.iter_mut().find(|e| e.pattern == pattern) {
        entry.scanners = scanners.clone();
        println!(
            "🔄 Updated exclusion pattern '{}' with scanners: {:?}",
            pattern, scanners
        );
    } else {
        config.exclusions.push(ExclusionEntry {
            pattern: pattern.to_string(),
            scanners: scanners.clone(),
        });
        println!(
            "➕ Added exclusion pattern '{}' with scanners: {:?}",
            pattern, scanners
        );
    }

    save_exclusions(&config)?;
    Ok(())
}

pub fn is_pattern_match(path_str: &str, pattern: &str) -> bool {
    let path_str = path_str.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");

    if let Some(suffix) = pattern.strip_prefix("**/") {
        return path_str.ends_with(suffix)
            || path_str.contains(&format!("/{}/", suffix))
            || path_str.contains(&format!("/{}", suffix));
    }

    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return path_str.starts_with(prefix);
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return path_str.starts_with(parts[0]) && path_str.ends_with(parts[1]);
        }
    }

    path_str == pattern || path_str.contains(&format!("/{}", pattern))
}
