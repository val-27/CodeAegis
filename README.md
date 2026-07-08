# CodeAegis: Local Security Scanner

**CodeAegis** is an ultra-lightweight, local-first security scanning gate designed for AI-driven development. It intercepts agentic code modifications and executes real-time security verification—either locally via a Workspace Agent Skill or via the Language Server Protocol (LSP).

## The Problem
As AI agents (like Cursor, Windsurf, or custom CLI agents) become more autonomous, they often propose code changes that can introduce:
- **Hardcoded Secrets:** Accidentally committing API keys or credentials.
- **Vulnerable Dependencies:** Adding packages with known CVEs.
- **Insecure Infrastructure:** Proposing IaC changes (Terraform, Docker) with security flaws.
- **Policy Violations:** Deviating from organization-specific security best practices.

AI agents are optimized for *completion*, not necessarily for *security*. Manual review is slow and error-prone.

## The CodeAegis Solution
CodeAegis acts as a "Security Sidecar" for your AI agent. It provides multiple integration modes to validate code changes:
1. **Workspace Agent Skill (Recommended):** Setup a local skill folder `.agent/skills/codeaegis` in any directory. The skill instructs active agents to run CLI verification before finalizing edits.
2. **Language Server (LSP):** Runs as a background LSP server publishing real-time editor diagnostics.
3. **Watchdog Mode:** Monitors directories for modifications, creating alerts and optionally reverting vulnerable changes.

### Key Features:
- **Local-First:** No data leaves your machine. All scans run against local binaries.
- **Single-Flight Coalescing:** If an agent fires multiple concurrent requests for the same file state, CodeAegis runs the scan once and broadcasts the result to all callers.
- **Multi-Scanner Orchestration:** Simultaneously runs **TruffleHog** (secrets), **OSV-Scanner** (dependencies), **Trivy** (IaC), and **Opengrep** (SAST).
- **Agentic CRITIC Layer:** Uses a localized LLM "Judge" to analyze raw tool output, prune false positives, and assign a normalized risk tier (Critical, High, Medium, Low, None).
- **High Performance:** Built in Rust with an async Tokio runtime and in-memory caching.

## Configuration

CodeAegis is configured via environment variables. The "Critic" layer requires an LLM provider to adjudicate scanner results. The provider is **automatically inferred** based on the model name.

| Variable | Description | Default |
|----------|-------------|---------|
| `CODEAEGIS_MODEL` | The model name (e.g., `gemini-1.5-flash`, `gpt-4o-mini`, `grok-beta`) | `gemini-1.5-flash` |
| `CODEAEGIS_API_URL` | Endpoint for the provider | Ollama/Gemini/OpenAI default |
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

CodeAegis is a unified binary that supports workspace initialization, direct scans, directory monitoring, and editor servers.

### Subcommands:
- `init [DIR]`: Initializes a Workspace Agent Skill (`.agent/skills/codeaegis/SKILL.md`) in the target directory (defaults to current directory).
- `scan [DIR_OR_FILE]`: Performs a recursive security audit of a directory or specific file.
- `watch [DIR]`: Monitors a directory for real-time file changes to scan them automatically. Has a `--strict` flag to automatically revert files if a vulnerability is detected.
- `lsp`: Runs the CodeAegis Language Server (LSP) to show findings directly in your editor.
- `auth`: Manages LLM authentication credentials in the OS keychain.
- `exclude <PATTERN> [--scanners <SCANNERS>]`: Excludes files/directories matching a glob pattern (e.g. `*.min.js` or `vendor/**`) from specific scanners or `all` scanners completely. Configuration is saved in `.agent/skills/codeaegis/exclusions.json`.

### Flags:
- `--logs`: Enable high-quality, single-line logs showing scanner findings and critic decisions.
- `--report <PATH>`: Output findings to a report file. The format is auto-detected from the file extension (supports `.sarif`, `.json`, `.xml` (JUnit), `.md`, `.csv`, `.html`).
- `--report-format <FORMAT>`: Explicitly override the report format (`sarif`, `json`, `junit`, `markdown`, `csv`, `html`).
- `-m`, `--model`: Override the LLM Critic model.
- `--auth`: Setup LLM authorization or view current LLM config info.
- `--scanners <SCANNERS>`: Comma-separated list of scanners to run (trufflehog, osv, trivy, opengrep). If omitted, all run.
- `--skip-scanners <SCANNERS>`: Comma-separated list of scanners to exclude.

### Examples:
```bash
# Setup or view LLM config and authentication
codeaegis --auth

# Run only TruffleHog and Opengrep scans
codeaegis --scanners trufflehog,opengrep scan .

# Initialize a workspace agent skill
codeaegis init

# Exclude vendor directory from all scans, and backup file from trufflehog
codeaegis exclude "vendor/**" --scanners all
codeaegis exclude "secrets_backup.py" --scanners trufflehog

# Scan a directory or specific file
codeaegis scan ./src/main.rs --logs

# Monitor a directory and automatically revert vulnerabilities
codeaegis watch . --strict

# Generate a SARIF report for a CI pipeline
codeaegis scan . --report results.sarif
```

## Setup & Usage

### Prerequisites
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [OSV-Scanner](https://github.com/google/osv-scanner)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Opengrep](https://github.com/opengrep/opengrep)

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

### Configuration as Workspace Agent Skill
Simply run `codeaegis init` in your repository. AI agents like Claude and Vertex will automatically detect `.agent/skills/codeaegis/SKILL.md` and verify all proposed code changes using the local CLI binary.

## License
Open Source under the MIT License.
