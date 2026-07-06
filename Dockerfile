# --- Build Stage ---
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /usr/src/codeaegis
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

# --- Final Stage ---
FROM debian:bookworm-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install OSV-Scanner
RUN curl -L https://github.com/google/osv-scanner/releases/download/v1.7.2/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/codeaegis/target/release/codeaegis /usr/local/bin/codeaegis

# Set execution environment
ENV PATH="/usr/local/bin:${PATH}"

# MCP runs over stdio, so no EXPOSE is needed by default
# unless you bridge it to a port.

ENTRYPOINT ["codeaegis"]
