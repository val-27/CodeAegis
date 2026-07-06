# CodeAegis MCP

**CodeAegis MCP** is an ultra-lightweight, local-first security scanning gate designed for AI-driven development. It intercepts agentic code modifications via the Model Context Protocol (MCP) and executes real-time security verification before the code is applied.

## The Problem
As AI agents (like Cursor, Windsurf, or custom CLI agents) become more autonomous, they often propose code changes that can introduce:
- **Hardcoded Secrets:** Accidentally committing API keys or credentials.
- **Vulnerable Dependencies:** Adding packages with known CVEs.
- **Insecure Infrastructure:** Proposing IaC changes (Terraform, Docker) with security flaws.
- **Policy Violations:** Deviating from organization-specific security best practices.

AI agents are optimized for *completion*, not necessarily for *security*. Manual review is slow and error-prone.

## The CodeAegis Solution
CodeAegis MCP acts as a "Security Sidecar" for your AI agent. It provides a standardized MCP tool (`verify_code`) that agents can call—or that can be automatically triggered—to validate code snippets.

### Key Features:
- **Local-First:** No data leaves your machine. All scans run against local binaries.
- **Single-Flight Coalescing:** If an agent fires multiple concurrent requests for the same file state, CodeAegis runs the scan once and broadcasts the result to all callers.
- **Multi-Scanner Orchestration:** Simultaneously runs **TruffleHog** (secrets), **OSV-Scanner** (dependencies), and **Trivy** (IaC).
- **Agentic CRITIC Layer:** Uses a localized LLM "Judge" to analyze raw tool output, prune false positives, and assign a normalized risk tier (Critical, High, Medium, Low, None).
- **High Performance:** Built in Rust with an async Tokio runtime and in-memory caching.

## Configuration

CodeAegis is configured via environment variables. The "Critic" layer requires an LLM provider to adjudicate scanner results. The provider is **automatically inferred** based on the model name.

| Variable | Description | Default |
|----------|-------------|---------|
| `CODEAEGIS_MODEL` | The model name (e.g., `gemini-1.5-pro`, `gpt-4o`, `grok-beta`) | `llama3` |
| `CODEAEGIS_API_URL` | Endpoint for the provider | Ollama default |
| `CODEAEGIS_API_KEY` | API Key (optional if using OS Keychain) | None |

### Provider Inference Rules:
- Starts with `gemini` -> **Gemini**
- Starts with `gpt` or contains `openai` -> **OpenAI**
- Starts with `grok` -> **Grok**
- Default -> **Ollama**

## Authentication & Keychain

For local development, you can store your API keys securely in the OS Keychain instead of using environment variables.

```bash
# Save your key securely
codeaegis auth login gemini

# Check which keys are stored
codeaegis auth status

# Remove a key
codeaegis auth logout gemini
```

## CLI Usage

CodeAegis is a unified binary that supports both MCP and direct CLI scanning.

### Subcommands:
- `mcp`: Starts the JSON-RPC server (default).
- `scan [DIR]`: Performs a recursive security audit of a directory.

### Flags:
- `--logs`: Enable high-quality, single-line logs showing scanner findings and critic decisions.
- `--report <PATH>.sarif`: Output findings to a SARIF-compliant file.

### Examples:
```bash
# Scan a directory with quality logs
codeaegis scan ./src --logs

# Generate a SARIF report for a CI pipeline
codeaegis scan . --report results.sarif
```

## Setup & Usage

### Prerequisites
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [OSV-Scanner](https://github.com/google/osv-scanner)
- [Trivy](https://github.com/aquasecurity/trivy)

### Building from Source
```bash
cargo build --release
# The binary is now available as 'codeaegis'
./target/release/codeaegis --help
```

### Installation
For macOS users, you can view the documentation locally after building:
```bash
man ./man/codeaegis.1
```

### Configuration for AI Clients (e.g., Cursor/Claude Desktop)
Add the following to your MCP configuration file:

```json
{
  "mcpServers": {
    "codeaegis": {
      "command": "/absolute/path/to/codeaegis",
      "args": ["mcp", "--logs"],
      "env": {
        "CODEAEGIS_MODEL": "gemini-1.5-pro"
      }
    }
  }
}
```

## License
Open Source under the MIT License.
