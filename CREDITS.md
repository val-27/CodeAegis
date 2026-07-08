# Third-Party Credits & Licenses

CodeAegis orchestrates several industry-standard security tools. This project is a harness that invokes these tools externally and does not modify their source code.

## Core Security Scanners

### [TruffleHog](https://github.com/trufflesecurity/trufflehog)
*   **Purpose:** Secret scanning and credential detection.
*   **License:** [GNU Affero General Public License v3.0 (AGPL-3.0)](https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE)
*   **Attribution:** Copyright (C) Truffle Security Co.

### [Trivy](https://github.com/aquasecurity/trivy)
*   **Purpose:** Vulnerability, misconfiguration, and IaC scanning.
*   **License:** [Apache License 2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE)
*   **Attribution:** Copyright (C) Aqua Security Software Ltd.

### [OSV-Scanner](https://github.com/google/osv-scanner)
*   **Purpose:** Dependency vulnerability scanning using the Open Source Vulnerabilities (OSV) database.
*   **License:** [Apache License 2.0](https://github.com/google/osv-scanner/blob/main/LICENSE)
*   **Attribution:** Copyright (C) Google LLC.

## Rust Dependencies

This project also utilizes the following major open-source libraries:

*   **Tokio:** MIT License. Copyright (C) Tokio Authors.
*   **Clap:** MIT/Apache 2.0. Copyright (C) Clap Authors.
*   **Keyring-rs:** MIT/Apache 2.0. Copyright (C) keyring-rs Authors.
*   **Moka:** MIT/Apache 2.0. Copyright (C) Moka Authors.
*   **Serde:** MIT/Apache 2.0. Copyright (C) Serde Authors.
*   **Anyhow/Thiserror:** MIT/Apache 2.0. Copyright (C) David Tolnay.

---

*Note: CodeAegis is distributed under the MIT License. Use of the third-party scanners listed above is subject to their respective licenses. Users are responsible for installing and maintaining these tools locally.*
