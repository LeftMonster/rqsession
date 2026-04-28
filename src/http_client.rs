use std::collections::HashMap;
use std::io::Read;

use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::profile::BrowserProfile;
use crate::response::RustResponse;
use crate::tls_builder::build_ssl_connector;

const MAX_REDIRECTS: usize = 10;

pub async fn execute(
    method: &str,
    url: &str,
    extra_headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    profile: &BrowserProfile,
    proxy: Option<&str>,
    verify: bool,
    ca_bundle: Option<&str>,
) -> Result<RustResponse, Error> {
    let mut current_url = url.to_owned();
    let mut redirects = 0;
    let mut current_method = method.to_owned();
    let mut current_body = body;

    loop {
        let resp = send_once(
            &current_method,
            &current_url,
            extra_headers.as_slice(),
            current_body.clone(),
            profile,
            proxy,
            verify,
            ca_bundle,
        )
        .await?;

        let status = resp.status_code;

        // Handle redirects
        if matches!(status, 301 | 302 | 303 | 307 | 308) && redirects < MAX_REDIRECTS {
            let location = resp
                .headers
                .get("location")
                .or_else(|| resp.headers.get("Location"))
                .cloned()
                .ok_or_else(|| Error::Http("redirect without Location header".into()))?;

            // Resolve relative redirect URL
            current_url = resolve_url(&current_url, &location)?;
            redirects += 1;

            // 303 always becomes GET; 301/302 become GET for POST
            if status == 303 || (matches!(status, 301 | 302) && current_method == "POST") {
                current_method = "GET".to_owned();
                current_body = None;
            }
            continue;
        }

        return Ok(resp);
    }
}

async fn send_once(
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<Vec<u8>>,
    profile: &BrowserProfile,
    proxy: Option<&str>,
    verify: bool,
    ca_bundle: Option<&str>,
) -> Result<RustResponse, Error> {
    let uri: Uri = url.parse().map_err(|e| Error::InvalidUrl(format!("{e}")))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    let host = uri
        .host()
        .ok_or_else(|| Error::InvalidUrl("missing host".into()))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });

    let tcp = match proxy {
        Some(p) => connect_via_proxy(p, &host, port).await?,
        None => TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(|e| Error::Io(e.to_string()))?,
    };

    if scheme == "https" {
        let connector = build_ssl_connector(&profile.tls, verify, ca_bundle)?;
        let mut config = connector
            .configure()
            .map_err(|e| Error::Tls(e.to_string()))?;
        config
            .set_hostname(&host)
            .map_err(|e| Error::Tls(e.to_string()))?;

        let tls = tokio_boring::connect(config, &host, tcp)
            .await
            .map_err(|e| Error::Tls(e.to_string()))?;

        let use_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);

        if use_h2 {
            do_h2(method, &uri, extra_headers, body, io, profile).await
        } else {
            do_h1(method, &uri, extra_headers, body, io).await
        }
    } else {
        let io = TokioIo::new(tcp);
        do_h1(method, &uri, extra_headers, body, io).await
    }
}

async fn do_h1<IO>(
    method: &str,
    uri: &Uri,
    extra_headers: &[(String, String)],
    body: Option<Vec<u8>>,
    io: TokioIo<IO>,
) -> Result<RustResponse, Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = build_request(method, uri, extra_headers, body)?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    collect_response(resp, uri).await
}

async fn do_h2<IO>(
    method: &str,
    uri: &Uri,
    extra_headers: &[(String, String)],
    body: Option<Vec<u8>>,
    io: TokioIo<IO>,
    profile: &BrowserProfile,
) -> Result<RustResponse, Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let s = &profile.http2.settings;
    let mut builder = http2::Builder::new(TokioExecutor::new());

    if let Some(v) = s.initial_window_size {
        builder.initial_stream_window_size(v);
    }
    builder.initial_connection_window_size(profile.http2.window_update);
    if let Some(v) = s.max_frame_size {
        builder.max_frame_size(v);
    }
    if let Some(v) = s.max_header_list_size {
        builder.max_header_list_size(v);
    }

    let (mut sender, conn) = builder
        .handshake(io)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = build_request(method, uri, extra_headers, body)?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    collect_response(resp, uri).await
}

fn build_request(
    method: &str,
    uri: &Uri,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> Result<Request<Full<Bytes>>, Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let body_bytes = body.unwrap_or_default();
    builder
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| Error::Http(e.to_string()))
}

async fn collect_response<B>(
    resp: hyper::Response<B>,
    uri: &Uri,
) -> Result<RustResponse, Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let status = resp.status().as_u16();
    let headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();

    let raw = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
        .to_bytes()
        .to_vec();

    let encoding = headers
        .get("content-encoding")
        .map(|s| s.as_str())
        .unwrap_or("");
    let body = decompress(raw, encoding)?;

    Ok(RustResponse {
        status_code: status,
        headers,
        body,
        url: uri.to_string(),
    })
}

fn decompress(raw: Vec<u8>, encoding: &str) -> Result<Vec<u8>, Error> {
    match encoding.to_lowercase().trim() {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| Error::Http(format!("gzip decompress: {e}")))?;
            Ok(out)
        }
        "deflate" => {
            let mut decoder = flate2::read::ZlibDecoder::new(&raw[..]);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| Error::Http(format!("deflate decompress: {e}")))?;
            Ok(out)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(&raw[..], 4096);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| Error::Http(format!("br decompress: {e}")))?;
            Ok(out)
        }
        "zstd" => zstd::decode_all(&raw[..])
            .map_err(|e| Error::Http(format!("zstd decompress: {e}"))),
        _ => Ok(raw),
    }
}

/// HTTP CONNECT tunnel through a proxy.
async fn connect_via_proxy(proxy: &str, target_host: &str, target_port: u16) -> Result<TcpStream, Error> {
    let proxy_uri: Uri = proxy
        .parse()
        .map_err(|e| Error::InvalidUrl(format!("proxy: {e}")))?;
    let proxy_host = proxy_uri.host().ok_or_else(|| Error::InvalidUrl("proxy missing host".into()))?;
    let proxy_port = proxy_uri
        .port_u16()
        .unwrap_or(if proxy_uri.scheme_str() == Some("https") { 443 } else { 8080 });

    let mut tcp = TcpStream::connect(format!("{proxy_host}:{proxy_port}"))
        .await
        .map_err(|e| Error::Io(e.to_string()))?;

    // Send CONNECT
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let connect_req = format!("CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n");
    tcp.write_all(connect_req.as_bytes())
        .await
        .map_err(|e| Error::Io(e.to_string()))?;

    // Read response until \r\n\r\n
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        tcp.read_exact(&mut tmp)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 4096 {
            return Err(Error::Http("proxy CONNECT response too large".into()));
        }
    }

    let status_line = std::str::from_utf8(&buf)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("");
    if !status_line.contains("200") {
        return Err(Error::Http(format!("proxy CONNECT failed: {}", status_line)));
    }

    Ok(tcp)
}

fn resolve_url(base: &str, location: &str) -> Result<String, Error> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    let base_uri: Uri = base
        .parse()
        .map_err(|e| Error::InvalidUrl(format!("{e}")))?;
    let scheme = base_uri.scheme_str().unwrap_or("https");
    let authority = base_uri
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("");

    let path = if location.starts_with('/') {
        location.to_owned()
    } else {
        let base_path = base_uri.path();
        let dir = base_path.rfind('/').map(|i| &base_path[..=i]).unwrap_or("/");
        format!("{}{}", dir, location)
    };

    Ok(format!("{}://{}{}", scheme, authority, path))
}
