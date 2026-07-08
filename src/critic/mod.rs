pub mod prompts;
use crate::cache::{Finding, ScanResult};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CriticProvider {
    Ollama,
    OpenAI,
    Grok,
    Gemini,
}

impl std::fmt::Display for CriticProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CriticProvider::Ollama => write!(f, "ollama"),
            CriticProvider::OpenAI => write!(f, "openai"),
            CriticProvider::Grok => write!(f, "grok"),
            CriticProvider::Gemini => write!(f, "gemini"),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CriticConfig {
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    pub model: String,
}

impl CriticConfig {
    pub fn infer_provider(&self) -> CriticProvider {
        let model = self.model.to_lowercase();
        if model.starts_with("gemini") {
            CriticProvider::Gemini
        } else if model.starts_with("gpt") || model.contains("openai") {
            CriticProvider::OpenAI
        } else if model.starts_with("grok") {
            CriticProvider::Grok
        } else {
            CriticProvider::Ollama
        }
    }
}

impl Default for CriticConfig {
    fn default() -> Self {
        Self {
            api_url: None,
            api_key: None,
            model: "gemini-1.5-flash".to_string(),
        }
    }
}

pub struct Critic {
    config: CriticConfig,
    client: reqwest::Client,
    enabled: bool,
}

impl Critic {
    pub fn new(model_override: Option<String>) -> Result<Self> {
        let mut config = CriticConfig::default();

        let mut using_env = false;
        if env::var("CODEAEGIS_MODEL").is_ok() || env::var("CODEAEGIS_API_KEY").is_ok() {
            let env_config: CriticConfig = envy::prefixed("CODEAEGIS_")
                .from_env::<CriticConfig>()
                .map_err(|e| anyhow!("Invalid CODEAEGIS_ configuration: {}", e))?;
            config = env_config;
            using_env = true;
        }

        if let Some(model) = model_override {
            config.model = model;
            config.api_url = None; // Reset URL to use provider default for the new model
        } else if !using_env {
            // Try to find a provider and key in the keychain in one pass to minimize prompts
            if let Some((provider, key)) = crate::auth::get_any_stored_key() {
                config.model = match provider.as_str() {
                    "gemini" => "gemini-1.5-flash".to_string(),
                    "openai" => "gpt-4o-mini".to_string(),
                    "grok" => "grok-beta".to_string(),
                    _ => config.model,
                };
                config.api_key = Some(key);
                config.api_url = None;
            }
        }

        let provider = config.infer_provider();

        // Fallback to keychain if API key is missing and wasn't already loaded
        if config.api_key.is_none() && provider != CriticProvider::Ollama {
            if let Some(key) = crate::auth::get_api_key(&provider.to_string()) {
                config.api_key = Some(key);
            }
        }

        let enabled = if provider == CriticProvider::Ollama {
            true
        } else {
            config.api_key.is_some()
        };

        if enabled {
            tracing::info!("Using Critic Model: {} (Provider: {})", config.model, provider);
        } else {
            tracing::warn!("Critic LLM API key is missing for provider '{}'. Skipping critic validation phase (running in static-only mode).", provider);
        }

        let critic = Self {
            config,
            client: reqwest::Client::new(),
            enabled,
        };

        Ok(critic)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn judge(&self, hash: String, code: &str, findings: Vec<Finding>, file_path: Option<&str>) -> Result<ScanResult> {
        let provider = self.config.infer_provider();
        let file_rules = prompts::get_rules_for_file(file_path.unwrap_or("general"));
        
        let system_prompt = format!(
            "{}\n{}\n{}",
            prompts::BASE_SYSTEM_PROMPT,
            file_rules,
            prompts::RESPONSE_FORMAT
        );

        let user_prompt = format!(
            "File Context: {}\n\nCode to Analyze:\n```\n{}\n```\n\nRaw Scanner Findings:\n{:?}",
            file_path.unwrap_or("Unknown File"),
            code,
            findings
        );

        match provider {
            CriticProvider::Ollama => self.call_ollama(&system_prompt, &user_prompt, hash).await,
            CriticProvider::OpenAI => self.call_openai(&system_prompt, &user_prompt, hash).await,
            CriticProvider::Grok => self.call_grok(&system_prompt, &user_prompt, hash).await,
            CriticProvider::Gemini => self.call_gemini(&system_prompt, &user_prompt, hash).await,
        }
    }

    async fn call_ollama(&self, system_prompt: &str, user_prompt: &str, hash: String) -> Result<ScanResult> {
        let url = self.config.api_url.as_deref().unwrap_or("http://localhost:11434/api/generate");
        
        let response = self.client.post(url)
            .json(&serde_json::json!({
                "model": self.config.model,
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": false,
                "format": "json"
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await?;
            return Err(anyhow!("Ollama API Error ({}): {}", status, err_text));
        }

        let res_body: serde_json::Value = response.json().await?;
        let response_text = res_body["response"].as_str().ok_or_else(|| anyhow!("Ollama: Missing response field"))?;
        
        self.parse_judge_json(response_text, hash)
    }

    async fn call_openai(&self, system_prompt: &str, user_prompt: &str, hash: String) -> Result<ScanResult> {
        let url = self.config.api_url.as_deref().unwrap_or("https://api.openai.com/v1/chat/completions");
        let api_key = self.config.api_key.as_ref().ok_or_else(|| anyhow!("OpenAI API key missing"))?;

        let response = self.client.post(url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "response_format": { "type": "json_object" }
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await?;
            return Err(anyhow!("OpenAI API Error ({}): {}", status, err_text));
        }

        let res_body: serde_json::Value = response.json().await?;
        let response_text = res_body["choices"][0]["message"]["content"].as_str().ok_or_else(|| anyhow!("OpenAI: Missing content field"))?;
        
        self.parse_judge_json(response_text, hash)
    }

    async fn call_grok(&self, system_prompt: &str, user_prompt: &str, hash: String) -> Result<ScanResult> {
        let url = self.config.api_url.as_deref().unwrap_or("https://api.x.ai/v1/chat/completions");
        let api_key = self.config.api_key.as_ref().ok_or_else(|| anyhow!("Grok API key missing"))?;

        let response = self.client.post(url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "response_format": { "type": "json_object" }
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await?;
            return Err(anyhow!("Grok API Error ({}): {}", status, err_text));
        }

        let res_body: serde_json::Value = response.json().await?;
        let response_text = res_body["choices"][0]["message"]["content"].as_str().ok_or_else(|| anyhow!("Grok: Missing content field"))?;
        
        self.parse_judge_json(response_text, hash)
    }

    async fn call_gemini(&self, system_prompt: &str, user_prompt: &str, hash: String) -> Result<ScanResult> {
        let api_key = self.config.api_key.as_ref().ok_or_else(|| anyhow!("Gemini API key missing"))?;
        let url = self.config.api_url.as_deref().unwrap_or("https://generativelanguage.googleapis.com/v1beta/models");
        let full_url = format!("{}/{}:generateContent?key={}", url, self.config.model, api_key);

        let response = self.client.post(full_url)
            .json(&serde_json::json!({
                "contents": [{
                    "parts": [{
                        "text": format!("{}\n\n{}", system_prompt, user_prompt)
                    }]
                }],
                "generationConfig": {
                    "response_mime_type": "application/json"
                }
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await?;
            return Err(anyhow!("Gemini API Error ({}): {}", status, err_text));
        }

        let res_body: serde_json::Value = response.json().await?;
        
        let response_text = res_body["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| anyhow!("Gemini: Unexpected response structure or blocked by safety filters. Response: {}", res_body))?;
        
        self.parse_judge_json(response_text, hash)
    }

    fn parse_judge_json(&self, text: &str, hash: String) -> Result<ScanResult> {
        #[derive(Deserialize)]
        struct JudgeOutput {
            risk_tier: String,
            summary: String,
            pruned_findings: Vec<Finding>,
        }

        let output: JudgeOutput = serde_json::from_str(text)?;

        Ok(ScanResult {
            hash,
            findings: output.pruned_findings,
            risk_tier: output.risk_tier,
            summary: output.summary,
        })
    }
}
