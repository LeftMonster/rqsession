use std::collections::HashMap;
use std::io::Read;

use bytes::{Bytes, BytesMut, BufMut};
use http::{Request, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use foreign_types_shared::ForeignTypeRef;

use crate::error::Error;
use crate::profile::BrowserProfile;
use crate::response::{parse_cookies, RustResponse};
use crate::tls_builder::build_ssl_connector;

/// Add ALPS (Application-Layer Protocol Settings, TLS extension 17513) per-connection.
/// Chrome/Chromium calls SSL_add_application_settings for each ALPN protocol it supports.
/// The settings payload is empty (Chrome advertises the extension with no extra data).
fn configure_alps(ssl: &boring::ssl::SslRef, protocols: &[String]) {
    for proto in protocols {
        let bytes = proto.as_bytes();
        let ret = unsafe {
            boring_sys::SSL_add_application_settings(
                ssl.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                std::ptr::null(),
                0,
            )
        };
        if ret != 1 {
            eprintln!("[rqsession] WARN: SSL_add_application_settings failed for {proto:?} (ret={ret})");
        }
    }
}

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
    let mut history: Vec<RustResponse> = Vec::new();

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
            history.push(resp);
            continue;
        }

        return Ok(RustResponse { history, ..resp });
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

        // ALPS per-connection setup (Chrome/Chromium only; no-op when alps is empty)
        if !profile.tls.alps.is_empty() {
            configure_alps(&*config, &profile.tls.alps);
        }

        let tls = tokio_boring::connect(config, &host, tcp)
            .await
            .map_err(|e| Error::Tls(e.to_string()))?;

        let use_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");

        if use_h2 {
            do_h2(method, &uri, extra_headers, body, tls, profile).await
        } else {
            let io = TokioIo::new(tls);
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
    io: IO,
    profile: &BrowserProfile,
) -> Result<RustResponse, Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // ── 1. Build the SETTINGS frame with configured values and wire order ──

    let s = &profile.http2.settings;
    let mut settings = h2::frame::Settings::default();

    if let Some(v) = s.header_table_size {
        settings.set_header_table_size(Some(v));
    }
    if let Some(v) = s.enable_push {
        settings.set_enable_push(v != 0);
    }
    if let Some(v) = s.max_concurrent_streams {
        settings.set_max_concurrent_streams(Some(v));
    }
    if let Some(v) = s.initial_window_size {
        settings.set_initial_window_size(Some(v));
    }
    if let Some(v) = s.max_frame_size {
        settings.set_max_frame_size(Some(v));
    }
    if let Some(v) = s.max_header_list_size {
        settings.set_max_header_list_size(Some(v));
    }

    // Map setting name strings → wire IDs, preserve order from profile.
    if !profile.http2.settings_order.is_empty() {
        let order: Vec<u16> = profile.http2.settings_order.iter()
            .filter_map(|name| match name.as_str() {
                "HEADER_TABLE_SIZE"      => Some(1),
                "ENABLE_PUSH"            => Some(2),
                "MAX_CONCURRENT_STREAMS" => Some(3),
                "INITIAL_WINDOW_SIZE"    => Some(4),
                "MAX_FRAME_SIZE"         => Some(5),
                "MAX_HEADER_LIST_SIZE"   => Some(6),
                _                        => None,
            })
            .collect();
        settings.set_settings_order(order);
    }

    // ── 2. Set the pseudo-header emission order (thread-local) ──

    let pseudo_order = build_pseudo_order(&profile.http2.pseudo_header_order);
    h2::frame::set_pseudo_header_order(pseudo_order);

    // ── 3. Build PRIORITY frames from profile spec ──

    let priority_frames: Vec<h2::frame::Priority> = profile.http2.priority_frames.iter()
        .map(|spec| {
            let stream_id: h2::frame::StreamId = spec.stream_id.into();
            let dep_id: h2::frame::StreamId = spec.dependency.into();
            let dep = h2::frame::StreamDependency::new(dep_id, spec.weight, spec.exclusive);
            h2::frame::Priority::new(stream_id, dep)
        })
        .collect();

    // ── 4. Handshake ──

    let mut builder = h2::client::Builder::new();
    // profile.http2.window_update is the exact WINDOW_UPDATE increment the browser sends.
    // h2 Builder's initial_connection_window_size sets the *target* and sends
    // increment = target - 65535 (the H2 default). So we add 65535 back to get the
    // correct on-wire value.
    const H2_DEFAULT_CONN_WINDOW: u32 = 65535;
    builder.initial_connection_window_size(H2_DEFAULT_CONN_WINDOW + profile.http2.window_update);
    if let Some(v) = s.initial_window_size {
        builder.initial_window_size(v);
    }
    let (client, conn) = builder
        .settings_frame(settings)
        .priority_frames(priority_frames)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    tokio::spawn(async move { let _ = conn.await; });

    // ── 5. Build and send the request ──

    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri.clone())
        .version(Version::HTTP_2);

    for (k, v) in extra_headers {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }

    let has_body = body.is_some();
    let request = req_builder
        .body(())
        .map_err(|e| Error::Http(e.to_string()))?;

    let mut client = client.ready().await.map_err(|e| Error::Http(e.to_string()))?;
    let (response_fut, mut send_stream) = client
        .send_request(request, !has_body)
        .map_err(|e| Error::Http(e.to_string()))?;

    if let Some(data) = body {
        send_stream
            .send_data(Bytes::from(data), true)
            .map_err(|e| Error::Http(e.to_string()))?;
    }

    // ── 6. Collect response ──

    let response = response_fut.await.map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status().as_u16();

    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();

    let mut body_stream = response.into_body();
    let mut raw = BytesMut::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| Error::Http(e.to_string()))?;
        raw.put_slice(&chunk);
        let _ = body_stream.flow_control().release_capacity(chunk.len());
    }

    let encoding = headers
        .get("content-encoding")
        .map(|s| s.as_str())
        .unwrap_or("");
    let body_bytes = decompress(raw.to_vec(), encoding)?;

    let cookies = parse_cookies(&headers);
    Ok(RustResponse {
        status_code: status,
        headers,
        body: body_bytes,
        url: uri.to_string(),
        cookies,
        history: Vec::new(),
    })
}

/// Map profile pseudo_header_order strings to the [u8; 4] thread-local format.
/// Values: 1=:method  2=:scheme  3=:authority  4=:path
fn build_pseudo_order(order: &[String]) -> [u8; 4] {
    let mut result = [1u8, 2, 3, 4]; // default
    let mapped: Vec<u8> = order.iter()
        .filter_map(|s| match s.as_str() {
            ":method"    => Some(1),
            ":scheme"    => Some(2),
            ":authority" => Some(3),
            ":path"      => Some(4),
            _            => None,
        })
        .collect();
    if mapped.len() == 4 {
        result.copy_from_slice(&mapped);
    }
    result
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

    let cookies = parse_cookies(&headers);
    Ok(RustResponse {
        status_code: status,
        headers,
        body,
        url: uri.to_string(),
        cookies,
        history: Vec::new(),
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
