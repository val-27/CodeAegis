use keyring::Entry;
use anyhow::{Result, anyhow};
use std::io::{self, Write};

pub fn get_keychain_entry(provider: &str) -> Result<Entry> {
    let service = format!("codeaegis-mcp-{}", provider.to_lowercase());
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
