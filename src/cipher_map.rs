/// Returns (tls12_ciphers_openssl, tls13_ciphers_openssl) from IANA cipher name list.
/// TLS 1.2 ciphers → colon-separated OpenSSL string for set_cipher_list
/// TLS 1.3 ciphers → colon-separated string for set_ciphersuites
pub fn split_cipher_lists(names: &[String]) -> (String, String) {
    let mut tls12 = Vec::new();
    let mut tls13 = Vec::new();

    for name in names {
        if is_tls13(name) {
            tls13.push(name.as_str().to_owned());
        } else if let Some(ossl) = iana_to_openssl(name) {
            tls12.push(ossl.to_owned());
        } else if !is_grease_cipher(name) {
            eprintln!("[rqsession] WARN: unsupported cipher suite dropped: {name:?}");
        }
    }

    (tls12.join(":"), tls13.join(":"))
}

fn is_grease_cipher(name: &str) -> bool {
    // GREASE cipher names like "TLS_GREASE (0x0A0A)" or raw hex patterns
    name.contains("GREASE") || name.contains("grease")
}

fn is_tls13(name: &str) -> bool {
    matches!(
        name,
        "TLS_AES_128_GCM_SHA256"
            | "TLS_AES_256_GCM_SHA384"
            | "TLS_CHACHA20_POLY1305_SHA256"
    )
}

fn iana_to_openssl(name: &str) -> Option<&'static str> {
    match name {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"       => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"         => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"       => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"         => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"   => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"            => Some("ECDHE-RSA-AES128-SHA"),
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"            => Some("ECDHE-RSA-AES256-SHA"),
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"          => Some("ECDHE-ECDSA-AES128-SHA"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"          => Some("ECDHE-ECDSA-AES256-SHA"),
        "TLS_RSA_WITH_AES_128_GCM_SHA256"               => Some("AES128-GCM-SHA256"),
        "TLS_RSA_WITH_AES_256_GCM_SHA384"               => Some("AES256-GCM-SHA384"),
        "TLS_RSA_WITH_AES_128_CBC_SHA"                  => Some("AES128-SHA"),
        "TLS_RSA_WITH_AES_256_CBC_SHA"                  => Some("AES256-SHA"),
        "TLS_RSA_WITH_AES_128_CBC_SHA256"               => Some("AES128-SHA256"),
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"                 => Some("DES-CBC3-SHA"),
        _ => None,
    }
}

/// Map curve name to BoringSSL group list string entry
pub fn curves_to_groups_list(curves: &[String]) -> String {
    curves
        .iter()
        .filter_map(|c| {
            let mapped = curve_name_to_group(c);
            if mapped.is_none() && !is_grease_curve(c) {
                eprintln!("[rqsession] WARN: unsupported curve dropped: {c:?}");
            }
            mapped
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn curve_name_to_group(name: &str) -> Option<&'static str> {
    match name {
        "x25519"    => Some("X25519"),
        "secp256r1" | "prime256v1" | "P-256" => Some("P-256"),
        "secp384r1" | "P-384"                => Some("P-384"),
        "secp521r1" | "P-521"                => Some("P-521"),
        "x448"      => Some("X448"),
        // Post-quantum / hybrid KEM (Chrome 124-130)
        "x25519kyber768draft00" | "x25519kyber768" => Some("X25519Kyber768Draft00"),
        // Post-quantum / hybrid KEM (Chrome 131+, boring 5.x required)
        "x25519mlkem768" => Some("X25519MLKEM768"),
        _ => None,
    }
}

fn is_grease_curve(name: &str) -> bool {
    name.contains("grease") || name.contains("GREASE")
}

/// Encode ALPN protocols as the wire format expected by BoringSSL:
/// each entry is length-prefixed, all concatenated.
pub fn encode_alpn(protocols: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in protocols {
        let bytes = p.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out
}
