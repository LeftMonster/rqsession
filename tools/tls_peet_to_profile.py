#!/usr/bin/env python3
"""
Convert tls.peet.ws/api/all JSON output to a rqsession BrowserProfile JSON.

Usage:
    # From saved JSON file:
    python tools/tls_peet_to_profile.py input.json -n chrome136_windows

    # Save directly to builtin profiles dir:
    python tools/tls_peet_to_profile.py input.json -n chrome136_windows --install

    # Read from stdin:
    curl https://tls.peet.ws/api/all | python tools/tls_peet_to_profile.py -n chrome136_windows --install
"""

import json
import sys
import re
import argparse
from pathlib import Path

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

_TLS_VERSION_MAP = {
    "769": "1.0", "770": "1.1", "771": "1.2", "772": "1.3",
    "TLS 1.0": "1.0", "TLS 1.1": "1.1", "TLS 1.2": "1.2", "TLS 1.3": "1.3",
}

_H2_SETTING_ID_MAP = {
    "1": "HEADER_TABLE_SIZE",
    "2": "ENABLE_PUSH",
    "3": "MAX_CONCURRENT_STREAMS",
    "4": "INITIAL_WINDOW_SIZE",
    "5": "MAX_FRAME_SIZE",
    "6": "MAX_HEADER_LIST_SIZE",
}

_PSEUDO_ABBREV = {"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}

_CURVE_MAP = {
    "x25519": "x25519",
    "p-256": "secp256r1",
    "p-384": "secp384r1",
    "p-521": "secp521r1",
    "x448": "x448",
    "ffdhe2048": "ffdhe2048",
    "ffdhe3072": "ffdhe3072",
}

# Headers that map to named fields in the profile struct (not put in `extra`)
_NAMED_HEADERS = {"user-agent", "accept", "accept-language", "accept-encoding"}

# --------------------------------------------------------------------------- #
# TLS extraction
# --------------------------------------------------------------------------- #

def _parse_curve(raw: str) -> str:
    """'X25519 (29)' → 'x25519',  'P-256 (23)' → 'secp256r1'"""
    name = raw.split("(")[0].strip().lower()
    return _CURVE_MAP.get(name, name)


def _parse_tls_version(raw: str) -> str:
    return _TLS_VERSION_MAP.get(raw.strip(), "1.3")


def _extract_tls(tls: dict) -> dict:
    cipher_suites = tls.get("ciphers", [])
    curves, sig_algs, alpn = [], [], []

    for ext in tls.get("extensions", []):
        name = ext.get("name", "")
        if "supported_groups" in name:
            curves = [_parse_curve(g) for g in ext.get("supported_groups", [])]
        elif "signature_algorithms" in name:
            sig_algs = ext.get("signature_algorithms", [])
        elif "application_layer_protocol_negotiation" in name:
            alpn = ext.get("protocols", [])

    # Determine TLS version range from supported_versions extension if present
    sv_versions = []
    for ext in tls.get("extensions", []):
        if "supported_versions" in ext.get("name", ""):
            sv_versions = [_parse_tls_version(v) for v in ext.get("versions", [])]

    if sv_versions:
        min_ver = min(sv_versions, key=lambda v: float(v))
        max_ver = max(sv_versions, key=lambda v: float(v))
    else:
        min_ver = _parse_tls_version(tls.get("tls_version_record", "771"))
        max_ver = _parse_tls_version(tls.get("tls_version_negotiated", "772"))

    return {
        "min_version": min_ver,
        "max_version": max_ver,
        "cipher_suites": cipher_suites,
        "curves": curves,
        "signature_algorithms": sig_algs,
        "alpn": alpn or ["h2", "http/1.1"],
    }

# --------------------------------------------------------------------------- #
# HTTP/2 extraction
# --------------------------------------------------------------------------- #

def _parse_akamai(fp: str):
    """
    Parse the akamai_fingerprint string as a fallback source for H2 settings.
    Format: 'SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_ORDER'
    Example: '1:65536;2:0;4:6291456|15663105|0|m,a,s,p'
    Chrome:  '1:65536;2:0;4:6291456|15663105|0:0:0:201,3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,a,s,p'
    PRIORITY segment format per entry: stream_id:exclusive:dep_id:weight (weight is 1-256 RFC value)
    """
    parts = fp.split("|")
    settings = {}
    settings_order = []
    if parts:
        for pair in parts[0].split(";"):
            if ":" in pair:
                k, v = pair.split(":", 1)
                key = _H2_SETTING_ID_MAP.get(k.strip())
                if key:
                    try:
                        settings[key] = int(v.strip())
                        settings_order.append(key)
                    except ValueError:
                        pass

    window_update = 15663105
    if len(parts) >= 2:
        try:
            window_update = int(parts[1])
        except ValueError:
            pass

    priority_frames = []
    if len(parts) >= 3 and parts[2] and parts[2] != "0":
        for entry in parts[2].split(","):
            fields = entry.split(":")
            if len(fields) == 4:
                try:
                    sid   = int(fields[0])
                    excl  = fields[1] == "1"
                    dep   = int(fields[2])
                    # akamai weight is 1-256 RFC value; h2 crate uses 0-255 so subtract 1
                    wt    = max(0, int(fields[3]) - 1)
                    if sid != 0:  # stream 0 entry is a placeholder, skip
                        priority_frames.append({"stream_id": sid, "dependency": dep,
                                                "weight": wt, "exclusive": excl})
                except ValueError:
                    pass

    pseudo_order = [":method", ":authority", ":scheme", ":path"]
    if len(parts) >= 4:
        pseudo_order = [
            _PSEUDO_ABBREV.get(c.strip(), f":{c.strip()}")
            for c in parts[3].split(",")
        ]

    return settings, settings_order, window_update, priority_frames, pseudo_order


def _extract_http2(http2: dict) -> dict:
    settings = {}
    settings_order = []
    window_update = 15663105
    pseudo_order = [":method", ":authority", ":scheme", ":path"]
    priority_frames = []

    frames = http2.get("sent_frames", [])

    for frame in frames:
        ftype = frame.get("frame_type", "")

        if ftype == "SETTINGS":
            for s in frame.get("settings", []):
                # Format: "ENABLE_PUSH = 0"
                if " = " in s:
                    k, v = s.split(" = ", 1)
                    k = k.strip()
                    if k in set(_H2_SETTING_ID_MAP.values()):
                        try:
                            settings[k] = int(v.strip())
                            if k not in settings_order:
                                settings_order.append(k)
                        except ValueError:
                            pass

        elif ftype == "WINDOW_UPDATE" and frame.get("stream_id", 0) == 0:
            window_update = frame.get("increment", window_update)

        elif ftype == "PRIORITY":
            sid  = frame.get("stream_id", 0)
            dep  = frame.get("stream_dependency", frame.get("depends_on", 0))
            excl = frame.get("exclusive", False)
            # tls.peet.ws reports weight as the raw wire value (0-255)
            wt   = frame.get("weight", 0)
            if sid != 0:
                priority_frames.append({"stream_id": sid, "dependency": dep,
                                        "weight": wt, "exclusive": excl})

        elif ftype == "HEADERS":
            pseudo_order = []
            for h in frame.get("headers", []):
                if not h.startswith(":"):
                    break  # pseudo-headers always come first
                name = h.split(": ")[0] if ": " in h else h.rstrip(":")
                if name not in pseudo_order:
                    pseudo_order.append(name)

    # Fallback: parse from akamai_fingerprint string
    if not settings and "akamai_fingerprint" in http2:
        settings, settings_order, window_update, priority_frames, pseudo_order = \
            _parse_akamai(http2["akamai_fingerprint"])

    return {
        "settings": settings,
        "settings_order": settings_order,
        "window_update": window_update,
        "priority_frames": priority_frames,
        "pseudo_header_order": pseudo_order,
    }

# --------------------------------------------------------------------------- #
# Header extraction
# --------------------------------------------------------------------------- #

def _extract_headers(http2: dict) -> dict:
    order = []
    extra = {}
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    accept_language = "en-US,en;q=0.9"
    accept_encoding = "gzip, deflate, br"

    for frame in http2.get("sent_frames", []):
        if frame.get("frame_type") != "HEADERS":
            continue
        for h in frame.get("headers", []):
            if ": " not in h or h.startswith(":"):
                continue  # skip pseudo-headers and malformed entries
            name, value = h.split(": ", 1)
            name = name.lower().strip()

            if name in ("cookie", "host"):
                continue  # managed at runtime

            if name not in order:
                order.append(name)

            if name == "accept":
                accept = value
            elif name == "accept-language":
                accept_language = value
            elif name == "accept-encoding":
                accept_encoding = value
            elif name not in _NAMED_HEADERS:
                extra[name] = value

    return {
        "accept": accept,
        "accept_language": accept_language,
        "accept_encoding": accept_encoding,
        "order": order,
        "extra": extra,
    }

# --------------------------------------------------------------------------- #
# Main conversion
# --------------------------------------------------------------------------- #

def convert(data: dict, profile_name: str) -> dict:
    user_agent = data.get("user_agent", "")

    tls = _extract_tls(data.get("tls", {}))
    h2_raw = _extract_http2(data.get("http2", {}))
    headers = _extract_headers(data.get("http2", {}))

    h2 = {
        "settings": h2_raw["settings"],
        "settings_order": h2_raw["settings_order"],
        "window_update": h2_raw["window_update"],
        "pseudo_header_order": h2_raw["pseudo_header_order"],
    }
    if h2_raw["priority_frames"]:
        h2["priority_frames"] = h2_raw["priority_frames"]

    return {
        "name": profile_name,
        "user_agent": user_agent,
        "tls": tls,
        "http2": h2,
        "headers": headers,
    }

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_BUILTIN_DIR = (
    Path(__file__).parent.parent
    / "rqsession" / "rust_session" / "profiles" / "builtin"
)


def main():
    parser = argparse.ArgumentParser(
        description="Convert tls.peet.ws/api/all JSON to a rqsession BrowserProfile JSON.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input", nargs="?",
        help="Path to the tls.peet.ws JSON file. Omit to read from stdin.",
    )
    parser.add_argument(
        "-n", "--name", required=True,
        help="Profile name, e.g. chrome136_windows",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path. Defaults to stdout.",
    )
    parser.add_argument(
        "--install", action="store_true",
        help=f"Write directly to the builtin profiles dir ({_BUILTIN_DIR}).",
    )
    args = parser.parse_args()

    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    profile = convert(data, args.name)
    output_text = json.dumps(profile, indent=2, ensure_ascii=False)

    if args.install:
        dest = _BUILTIN_DIR / f"{args.name}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(output_text, encoding="utf-8")
        print(f"Installed: {dest}", file=sys.stderr)
    elif args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output_text)


if __name__ == "__main__":
    main()
