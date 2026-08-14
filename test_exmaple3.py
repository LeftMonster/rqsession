import asyncio
import aiohttp
import requests

from rqsession.rust_session import BrowserSession, Chrome120, Chrome138, Firefox133, Safari17, Edge141, Edge142, Edge147, Firefox146, Py37Aiohttp381, Tor128, AndroidChrome114,\
    MacosChrome140, AsyncBrowserSession,Android10Edge143, Chrome147
from curl_cffi.requests import AsyncSession


async def main():
    url = "https://www.kickscrew.com/en-US"
    # url = "https://accounts.krafton.com/v2/en/web/login-main"

    # Traditional
    # session = aiohttp.ClientSession()
    # async with session.get(url) as response:
    #     data = await response.text()
    #     print(response.status)
    #     return data
    # session.close()

    # Client
    # s = BrowserSession(Android10Edge143, proxy="http://127.0.0.1:7890")
    # s = BrowserSession(Edge147, proxy="http://127.0.0.1:7890")
    s = requests.Session()
    response = s.get(url)

    # curl cffi
    # session = AsyncSession(impersonate="chrome99_android")
    # response = await session.get(url)


    print(response.status_code)
    # print(response.cookies)
    print(s.cookies)

if __name__ == '__main__':
    asyncio.run(main())