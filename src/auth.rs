use keyring::Entry;
use anyhow::{Result, anyhow};
use std::io::{self, Write};

pub fn get_keychain_entry(provider: &str) -> Result<Entry> {
    let service = format!("codeaegis-{}", provider.to_lowercase());
    let user = "api-key";
    Entry::new(&service, user).map_err(|e| anyhow!("Failed to access keychain: {}", e))
}

pub fn handle_login(provider: &str) -> Result<()> {
    print!("🔒 Enter API Key for {}: ", provider);
    io::stdout().flush()?;
    
    let key = rpassword::read_password()?;
    
    if key.trim().is_empty() {
        return Err(anyhow!("API Key cannot be empty"));
    }

    let entry = get_keychain_entry(provider)?;
    entry.set_password(key.trim()).map_err(|e| anyhow!("Failed to save key: {}", e))?;
    
    println!("✅ Successfully saved {} API key to OS Keychain.", provider);
    Ok(())
}

pub fn handle_logout(provider: &str) -> Result<()> {
    let entry = get_keychain_entry(provider)?;
    match entry.delete_password() {
        Ok(_) => println!("✅ Successfully removed {} API key from OS Keychain.", provider),
        Err(keyring::Error::NoEntry) => println!("ℹ️ No key found for {} in the keychain.", provider),
        Err(e) => return Err(anyhow!("Failed to remove key: {}", e)),
    }
    Ok(())
}

pub fn handle_status() -> Result<()> {
    println!("--- CodeAegis Keychain Status ---");
    let providers = vec!["gemini", "openai", "grok"];
    
    for provider in providers {
        let entry = get_keychain_entry(provider)?;
        match entry.get_password() {
            Ok(key) => {
                let masked = if key.len() > 8 {
                    format!("{}...{}", &key[..4], &key[key.len()-4..])
                } else {
                    "********".to_string()
                };
                println!("  {}: [SET] ({})", provider, masked);
            }
            Err(_) => println!("  {}: [NOT SET]", provider),
        }
    }
    Ok(())
}

pub fn get_api_key(provider: &str) -> Option<String> {
    get_keychain_entry(provider).ok()?.get_password().ok()
}

pub fn get_any_stored_key() -> Option<(String, String)> {
    let providers = vec!["gemini", "openai", "grok"];
    for provider in providers {
        if let Some(key) = get_api_key(provider) {
            return Some((provider.to_string(), key));
        }
    }
    None
}

pub fn handle_auth_flag(model_override: Option<String>) -> Result<()> {
    let model = model_override
        .or_else(|| std::env::var("CODEAEGIS_MODEL").ok())
        .unwrap_or_else(|| "gemini-1.5-flash".to_string());

    let model_lower = model.to_lowercase();
    let provider = if model_lower.starts_with("gemini") {
        "gemini"
    } else if model_lower.starts_with("gpt") || model_lower.contains("openai") {
        "openai"
    } else if model_lower.starts_with("grok") {
        "grok"
    } else {
        "ollama"
    };

    println!("--- CodeAegis LLM Configuration Info ---");
    println!("Active Model: {}", model);
    println!("Inferred Provider: {}", provider);

    if provider == "ollama" {
        println!("Authorization Status: Ollama provider typically runs locally and does not require an API key.");
        return Ok(());
    }

    let env_key = std::env::var("CODEAEGIS_API_KEY").ok();
    let keychain_key = get_api_key(provider);

    match (&env_key, &keychain_key) {
        (Some(_), _) => {
            println!("Authorization Status: Configured (via environment variable CODEAEGIS_API_KEY)");
        }
        (None, Some(key)) => {
            let masked = if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len()-4..])
            } else {
                "********".to_string()
            };
            println!("Authorization Status: Configured (via OS Keychain: {})", masked);
        }
        (None, None) => {
            println!("Authorization Status: Missing (neither CODEAEGIS_API_KEY is set nor is a key stored in OS Keychain)");
        }
    }

    print!("\nWould you like to configure/update the API key for '{}' in the OS Keychain? [y/N]: ", provider);
    io::stdout().flush()?;
    
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if response.trim().to_lowercase() == "y" {
        handle_login(provider)?;
    }

    Ok(())
}
