use crate::engine::ScanEngine;
use dashmap::DashMap;
use std::sync::Arc;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

pub struct CodeAegisBackend {
    client: Client,
    engine: Arc<ScanEngine>,
    documents: DashMap<Url, String>,
}

#[tower_lsp::async_trait]
impl LanguageServer for CodeAegisBackend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "CodeAegis LSP Server Initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.documents.insert(
            params.text_document.uri.clone(),
            params.text_document.text.clone(),
        );
        self.validate_document(params.text_document.uri, params.text_document.text)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.first() {
            let content = change.text.clone();
            self.documents
                .insert(params.text_document.uri.clone(), content.clone());
            self.validate_document(params.text_document.uri, content)
                .await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        if let Some(content_ref) = self.documents.get(&params.text_document.uri) {
            let content = content_ref.value().clone();
            self.validate_document(params.text_document.uri, content)
                .await;
        }
    }
}

impl CodeAegisBackend {
    async fn validate_document(&self, uri: Url, content: String) {
        let path_str = uri
            .to_file_path()
            .ok()
            .map(|p: std::path::PathBuf| p.to_string_lossy().into_owned());

        match self.engine.scan(&content, path_str.as_deref(), false).await {
            Ok(result) => {
                let mut diagnostics = Vec::new();

                for finding in result.findings {
                    let severity = match finding.severity.to_lowercase().as_str() {
                        "critical" | "high" => Some(DiagnosticSeverity::ERROR),
                        "medium" => Some(DiagnosticSeverity::WARNING),
                        _ => Some(DiagnosticSeverity::INFORMATION),
                    };

                    // Rudimentary location parsing - try to find line number in the string
                    let line = finding
                        .location
                        .as_deref()
                        .and_then(|l| l.split(':').next())
                        .and_then(|l| l.parse::<u32>().ok())
                        .map(|l| l.saturating_sub(1)) // LSP is 0-indexed
                        .unwrap_or(0);

                    diagnostics.push(Diagnostic {
                        range: Range::new(Position::new(line, 0), Position::new(line, 80)),
                        severity,
                        code: Some(NumberOrString::String(finding.tool.clone())),
                        source: Some("CodeAegis".to_string()),
                        message: finding.message,
                        ..Default::default()
                    });
                }

                self.client
                    .publish_diagnostics(uri, diagnostics, None)
                    .await;
            }
            Err(e) => {
                self.client
                    .log_message(MessageType::ERROR, format!("Scan failed: {}", e))
                    .await;
            }
        }
    }
}

pub async fn run_lsp_server(engine: Arc<ScanEngine>) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| CodeAegisBackend {
        client,
        engine,
        documents: DashMap::new(),
    });

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
