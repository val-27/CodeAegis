use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::engine::ScanEngine;
use std::sync::Arc;
use anyhow::Result;
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
#[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
#[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

pub struct McpServer {
    engine: Arc<ScanEngine>,
}

impl McpServer {
    pub fn new(engine: Arc<ScanEngine>) -> Self {
        Self { engine }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();

        while let Some(line) = reader.next_line().await? {
            let response = self.handle_line(&line).await;
            let response_json = serde_json::to_string(&response)?;
            println!("{}", response_json);
        }

        Ok(())
    }

    async fn handle_line(&self, line: &str) -> JsonRpcResponse {
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                };
            }
        };

        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request).await,
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", request.method),
                    data: None,
                }),
            },
        }
    }

    fn handle_initialize(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "codeaegis",
                    "version": "0.1.0"
                }
            })),
            error: None,
        }
    }

    fn handle_tools_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: Some(serde_json::json!({
                "tools": [
                    {
                        "name": "verify_code",
                        "description": "Scans code for security vulnerabilities, secrets, and policy violations.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "The code snippet to scan"
                                },
                                "file_path": {
                                    "type": "string",
                                    "description": "Optional local file path for context"
                                }
                            },
                            "required": ["code"]
                        }
                    }
                ]
            })),
            error: None,
        }
    }

    async fn handle_tools_call(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let params = request.params.as_ref().and_then(|p| p.as_object());
        let name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());
        let arguments = params.and_then(|p| p.get("arguments"));

        match name {
            Some("verify_code") => {
                let code = arguments
                    .and_then(|a| a.get("code"))
                    .and_then(|c| c.as_str());
                let file_path = arguments
                    .and_then(|a| a.get("file_path"))
                    .and_then(|f| f.as_str());
                
                if let Some(code) = code {
                    match self.engine.scan(code, file_path).await {
                        Ok(result) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: Some(serde_json::json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&result).unwrap()
                                    }
                                ]
                            })),
                            error: None,
                        },
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32000,
                                message: format!("Scan error: {}", e),
                                data: None,
                            }),
                        },
                    }
                } else {
                    JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: "Missing 'code' argument".to_string(),
                            data: None,
                        }),
                    }
                }
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Tool not found: {:?}", name),
                    data: None,
                }),
            },
        }
    }
}
