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

pub fn parse_cookies(headers: &HashMap<String, String>) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    let sc = headers
        .get("set-cookie")
        .or_else(|| headers.get("Set-Cookie"));
    if let Some(sc) = sc {
        for cookie in sc.split(',') {
            if let Some((name_val, _)) = cookie.split_once(';') {
                if let Some((name, value)) = name_val.split_once('=') {
                    cookies.insert(name.trim().to_owned(), value.trim().to_owned());
                }
            }
        }
    }
    cookies
}
