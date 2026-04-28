use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrowserProfile {
    pub name: String,
    pub user_agent: String,
    pub tls: TlsConfig,
    pub http2: Http2Config,
    pub headers: HeaderConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub min_version: String,
    pub max_version: String,
    pub cipher_suites: Vec<String>,
    pub curves: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Config {
    pub settings: Http2Settings,
    pub window_update: u32,
    pub pseudo_header_order: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Settings {
    #[serde(rename = "HEADER_TABLE_SIZE", default)]
    pub header_table_size: Option<u32>,
    #[serde(rename = "ENABLE_PUSH", default)]
    pub enable_push: Option<u32>,
    #[serde(rename = "INITIAL_WINDOW_SIZE", default)]
    pub initial_window_size: Option<u32>,
    #[serde(rename = "MAX_FRAME_SIZE", default)]
    pub max_frame_size: Option<u32>,
    #[serde(rename = "MAX_CONCURRENT_STREAMS", default)]
    pub max_concurrent_streams: Option<u32>,
    #[serde(rename = "MAX_HEADER_LIST_SIZE", default)]
    pub max_header_list_size: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderConfig {
    pub accept: String,
    pub accept_language: String,
    pub accept_encoding: String,
    #[serde(default)]
    pub order: Vec<String>,
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl BrowserProfile {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}
