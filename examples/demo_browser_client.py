"""
同步 BrowserClient 使用示例
验证 TLS 指纹是否与真实浏览器一致
"""
import sys
import json
import warnings

sys.path.insert(0, "D:/ownrepo-github/requestsession/rqsession")

# Chrome120/Chrome119 的 JA3 含 TLS 1.3 ciphers，curl_cffi 不支持自定义，
# 会自动 fallback 到 impersonate 模式，属于预期行为，不需要看到这条警告。
warnings.filterwarnings("ignore", category=UserWarning, module="browser_forge")

from browser_forge import BrowserClient, Chrome120, Edge142


PROXY = "http://127.0.0.1:7890"


def check_tls_fingerprint(proxy: str = None) -> dict:
    """
    访问 tls.peet.ws，服务端会返回它看到的 TLS ClientHello 信息。
    可用于验证指纹是否与真实浏览器匹配。
    """
    with BrowserClient(Chrome120, proxy=proxy, verify=False) as client:
        resp = client.get("https://tls.peet.ws/api/all")
        resp.raise_for_status()
        return resp.json()


def print_fingerprint_summary(data: dict):
    tls = data.get("tls", {})
    http2 = data.get("http2", {})

    print("=== TLS Fingerprint ===")
    print(f"  JA3  : {tls.get('ja3', 'N/A')}")
    print(f"  JA3 hash : {tls.get('ja3_hash', 'N/A')}")
    print(f"  JA4  : {tls.get('ja4', 'N/A')}")
    print(f"  TLS version : {tls.get('tls_version_negotiated', 'N/A')}")
    print(f"  ALPN : {tls.get('alpn', 'N/A')}")

    ciphers = tls.get("ciphers", [])
    print(f"  Ciphers ({len(ciphers)}): {ciphers[:3]}{'...' if len(ciphers) > 3 else ''}")

    print("\n=== HTTP/2 Fingerprint ===")
    akamai = http2.get("akamai_fingerprint", "N/A")
    print(f"  Akamai : {akamai}")

    print("\n=== User-Agent (server-side) ===")
    ua = (data.get("http1") or {}).get("headers", {}).get("User-Agent", "N/A")
    if ua == "N/A":
        for frame in http2.get("sent_frames", []):
            for h in frame.get("headers", []):
                if h.lower().startswith("user-agent:"):
                    ua = h.split(":", 1)[1].strip()
                    break
    print(f"  {ua}")


if __name__ == "__main__":
    print("Running without proxy...\n")
    try:
        data = check_tls_fingerprint(proxy=None)
        print_fingerprint_summary(data)
    except Exception as e:
        print(f"No-proxy attempt failed: {e}")
        print("\nRetrying with proxy...\n")
        data = check_tls_fingerprint(proxy=PROXY)
        print_fingerprint_summary(data)
