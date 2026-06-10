"""验证补全后的 profile 字段是否生效，通过解析 tls.browserleaks.com 的 ja3_text"""
import asyncio, json
from rqsession import AsyncBrowserSession, Chrome138, Edge148, Firefox146, Safari17, Chrome120

PROXY = "http://127.0.0.1:7890"

# ja3_text format: version,ciphers,extensions,curves,point_formats
# extension IDs (decimal):
#   5  = status_request (OCSP stapling)
#   18 = signed_certificate_timestamp (SCT)
#   27 = compress_certificate
#   17613 = application_settings (ALPS, 0x44CD)
# GREASE extensions are stripped from JA3 — cannot be detected here

def parse_exts(ja3_text: str) -> set[int]:
    parts = ja3_text.split(",")
    if len(parts) < 3 or not parts[2]:
        return set()
    return {int(x) for x in parts[2].split("-") if x}

async def check(name, profile):
    session = AsyncBrowserSession(profile, proxy=PROXY)
    try:
        resp = await asyncio.wait_for(session.get("https://tls.browserleaks.com/json"), timeout=15)
        d = json.loads(resp.text)
        ja3_hash = d.get("ja3_hash", "?")[:16]
        ja3_text = d.get("ja3_text", "")
        exts = parse_exts(ja3_text)
        has_ocsp     = 5  in exts
        has_sct      = 18 in exts
        has_compress = 27 in exts
        has_alps     = 17613 in exts
        print(f"  {name:<28}  ja3={ja3_hash}  ocsp={int(has_ocsp)}  sct={int(has_sct)}  compress={int(has_compress)}  alps={int(has_alps)}")
    except Exception as e:
        print(f"  {name:<28}  ERROR: {e}")

async def main():
    print(f"{'Profile':<28}  {'ja3':16}  ocsp  sct  compress  alps")
    print("-" * 78)
    cases = [
        ("Chrome120 (基准)", Chrome120),
        ("Chrome138",        Chrome138),
        ("Edge148",          Edge148),
        ("Firefox146",       Firefox146),
        ("Safari17",         Safari17),
    ]
    for name, profile in cases:
        await check(name, profile)
        await asyncio.sleep(0.5)

asyncio.run(main())
