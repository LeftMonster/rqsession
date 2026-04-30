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
    /// Enable TLS GREASE (RFC 8701). Chromium browsers send GREASE; Firefox/Safari do not.
    #[serde(default)]
    pub grease: bool,
    /// ALPS protocols (application_settings TLS extension, id 17513).
    /// Chromium sends this for each h2/h3 ALPN protocol it negotiates.
    /// Firefox/Safari do not send ALPS.
    #[serde(default)]
    pub alps: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PriorityFrameSpec {
    pub stream_id: u32,
    pub dependency: u32,
    pub weight: u8,
    #[serde(default)]
    pub exclusive: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Config {
    pub settings: Http2Settings,
    pub window_update: u32,
    pub pseudo_header_order: Vec<String>,
    /// SETTINGS parameter names in the order they appear on the wire.
    /// e.g. ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE"]
    /// Empty = use h2 crate default order (for backwards compatibility).
    #[serde(default)]
    pub settings_order: Vec<String>,
    /// PRIORITY frames sent after SETTINGS during H2 handshake (browser fingerprint).
    /// Empty = no PRIORITY frames (Firefox, Safari behaviour).
    #[serde(default)]
    pub priority_frames: Vec<PriorityFrameSpec>,
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
