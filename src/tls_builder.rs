use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVersion,
};
use crate::cipher_map::{encode_alpn, split_cipher_lists, curves_to_groups_list};
use crate::error::Error;
use crate::profile::TlsConfig;

struct ZlibCertDecompressor;

impl CertificateCompressor for ZlibCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use std::io::Read;
        let mut d = flate2::read::ZlibDecoder::new(input);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf)?;
        output.write_all(&buf)
    }
}

struct BrotliCertDecompressor;

impl CertificateCompressor for BrotliCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use std::io::Read;
        let mut d = brotli::Decompressor::new(input, 4096);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf)?;
        output.write_all(&buf)
    }
}

pub fn build_ssl_connector(config: &TlsConfig, verify: bool, ca_bundle: Option<&str>) -> Result<SslConnector, Error> {
    let mut builder = SslConnector::builder(SslMethod::tls())
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

    // --- GREASE (RFC 8701) ---
    if config.grease {
        builder.set_grease_enabled(true);
    }

    // --- OCSP stapling (status_request, ext 5) ---
    if config.ocsp_stapling {
        builder.enable_ocsp_stapling();
    }

    // --- Signed certificate timestamps (SCT, ext 18) ---
    if config.sct {
        builder.enable_signed_cert_timestamps();
    }

    // --- Certificate compression (compress_certificate, ext 27) ---
    for alg in &config.cert_compression {
        match alg.as_str() {
            "zlib" => builder
                .add_certificate_compression_algorithm(ZlibCertDecompressor)
                .map_err(|e| Error::Tls(e.to_string()))?,
            "brotli" => builder
                .add_certificate_compression_algorithm(BrotliCertDecompressor)
                .map_err(|e| Error::Tls(e.to_string()))?,
            other => return Err(Error::Tls(format!("unsupported cert compression: {other}"))),
        }
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
