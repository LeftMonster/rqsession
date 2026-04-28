use boring::ssl::{SslConnector, SslMethod, SslVersion};
use crate::cipher_map::{encode_alpn, split_cipher_lists, curves_to_groups_list};
use crate::error::Error;
use crate::profile::TlsConfig;

pub fn build_ssl_connector(config: &TlsConfig, verify: bool, ca_bundle: Option<&str>) -> Result<SslConnector, Error> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| Error::Tls(e.to_string()))?;

    // --- TLS version range ---
    let min = parse_version(&config.min_version);
    let max = parse_version(&config.max_version);
    builder
        .set_min_proto_version(min)
        .map_err(|e| Error::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(max)
        .map_err(|e| Error::Tls(e.to_string()))?;

    // --- TLS 1.2 cipher suites ---
    // BoringSSL manages TLS 1.3 ciphers (AES-128/256-GCM, CHACHA20) internally;
    // set_cipher_list only applies to TLS 1.2 and below.
    let (tls12_list, _tls13_list) = split_cipher_lists(&config.cipher_suites);
    if !tls12_list.is_empty() {
        builder
            .set_cipher_list(&tls12_list)
            .map_err(|e| Error::Tls(e.to_string()))?;
    }

    // --- Supported groups (curves) ---
    let groups = curves_to_groups_list(&config.curves);
    if !groups.is_empty() {
        builder
            .set_curves_list(&groups)
            .map_err(|e| Error::Tls(e.to_string()))?;
    }

    // --- ALPN ---
    if !config.alpn.is_empty() {
        let alpn_wire = encode_alpn(&config.alpn);
        builder
            .set_alpn_protos(&alpn_wire)
            .map_err(|e| Error::Tls(e.to_string()))?;
    }

    // --- Signature algorithms ---
    if !config.signature_algorithms.is_empty() {
        let sigalgs = config.signature_algorithms.join(":");
        builder
            .set_sigalgs_list(&sigalgs)
            .map_err(|e| Error::Tls(e.to_string()))?;
    }

    // --- Certificate verification ---
    if !verify {
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    } else if let Some(path) = ca_bundle {
        builder
            .set_ca_file(path)
            .map_err(|e| Error::Tls(format!("CA bundle '{}': {}", path, e)))?;
    } else {
        // Fall back to OpenSSL env vars (SSL_CERT_FILE / SSL_CERT_DIR) or compiled-in defaults.
        // On Windows this usually finds nothing; callers should provide ca_bundle explicitly.
        let _ = builder.set_default_verify_paths();
    }

    Ok(builder.build())
}

fn parse_version(v: &str) -> Option<SslVersion> {
    match v {
        "1.0" => Some(SslVersion::TLS1),
        "1.1" => Some(SslVersion::TLS1_1),
        "1.2" => Some(SslVersion::TLS1_2),
        "1.3" => Some(SslVersion::TLS1_3),
        _     => None,
    }
}
