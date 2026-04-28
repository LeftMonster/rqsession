use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RustResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub url: String,
}
