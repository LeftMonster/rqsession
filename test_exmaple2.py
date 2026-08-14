import asyncio

import aiohttp

from new_rust_tls_req_web import session


async def main():
    session = aiohttp.ClientSession()
    url = "https://web.kick.com/api/v1/drops/progress"
    session.headers.update({
        "authorization": "Bearer xxx"
    })
    async with session.get(url) as response:
        data = await response.text()
        print(data)
        return data
    session.close()

if __name__ == '__main__':
    asyncio.run(main())