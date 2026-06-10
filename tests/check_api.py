import asyncio, json
from rqsession import AsyncBrowserSession, Chrome120

PROXY = "http://127.0.0.1:7890"

async def main():
    session = AsyncBrowserSession(Chrome120, proxy=PROXY)
    resp = await asyncio.wait_for(session.get("https://tls.browserleaks.com/json"), timeout=15)
    d = json.loads(resp.text)
    print(json.dumps(d, indent=2))

asyncio.run(main())
