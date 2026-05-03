use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RustResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub url: String,
    pub cookies: HashMap<String, String>,
    pub history: Vec<RustResponse>,
}

/// Parse cookies from a slice of raw Set-Cookie header values (one element per header line).
/// Splitting on ',' is intentionally avoided — Expires values contain commas.
pub fn parse_cookies(set_cookie_headers: &[String]) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for header_value in set_cookie_headers {
        let name_value = header_value.split(';').next().unwrap_or("").trim();
        if let Some((name, value)) = name_value.split_once('=') {
            cookies.insert(name.trim().to_owned(), value.trim().to_owned());
        }
    }
    cookies
}
