"""
Async client usage examples for browser_forge
"""
import asyncio
import sys

from browser_forge import AsyncBrowserClient, Chrome119, Edge142, AsyncBrowserPool, fetch_all, BrowserClient, \
    JA3Generator, JA4Generator
from curl_cffi import AsyncSession

sys.path.insert(0, '/mnt/user-data/outputs')

#import AsyncBrowserClient, AsyncBrowserPool, fetch_all, Chrome119, Edge142


async def example_1_simple_async_request():
    """Example 1: Simple async request"""
    print("=== Example 1: Simple Async Request ===")

    async with AsyncBrowserClient(profile=Chrome119) as client:
        response = await client.get("https://httpbin.org/headers")
        print(f"Status: {response.status_code}")
        print(f"Headers: {response.json()}")


async def example_2_multiple_requests():
    """Example 2: Multiple sequential requests"""
    print("\n=== Example 2: Multiple Sequential Requests ===")

    urls = [
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
    ]

    async with AsyncBrowserClient(profile=Chrome119) as client:
        for i, url in enumerate(urls, 1):
            response = await client.get(url)
            print(f"Request {i}: {response.status_code}")


async def example_3_concurrent_requests():
    """Example 3: Concurrent requests with asyncio.gather"""
    print("\n=== Example 3: Concurrent Requests ===")

    urls = [
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/1",
    ]

    async def fetch(url):
        async with AsyncBrowserClient(profile=Chrome119) as client:
            response = await client.get(url)
            return response.status_code

    import time
    start = time.time()

    # Run concurrently
    results = await asyncio.gather(*[fetch(url) for url in urls])

    elapsed = time.time() - start
    print(f"Fetched {len(urls)} URLs in {elapsed:.2f}s")
    print(f"Results: {results}")


async def example_4_using_fetch_all():
    """Example 4: Using the fetch_all helper"""
    print("\n=== Example 4: Using fetch_all Helper ===")

    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/headers",
        "https://httpbin.org/user-agent",
        "https://httpbin.org/ip",
    ]

    import time
    start = time.time()

    # Fetch all URLs with max 10 concurrent requests
    responses = await fetch_all(
        urls,
        profile=Chrome119,
        max_concurrent=10
    )

    elapsed = time.time() - start

    print(f"Fetched {len(urls)} URLs in {elapsed:.2f}s")
    for i, response in enumerate(responses, 1):
        if isinstance(response, Exception):
            print(f"  {i}. Error: {response}")
        else:
            print(f"  {i}. Status: {response.status_code}")


async def example_5_connection_pool():
    """Example 5: Using AsyncBrowserPool"""
    print("\n=== Example 5: Using Connection Pool ===")

    async with AsyncBrowserPool(
            profile=Chrome119,
            pool_size=5  # Max 5 concurrent clients
    ) as pool:

        async def make_request(i):
            client = await pool.acquire()
            try:
                response = await client.get(f"https://httpbin.org/delay/1")
                print(f"Request {i}: {response.status_code}")
                return response.status_code
            finally:
                await pool.release(client)

        # Make 10 requests with pool of 5 clients
        tasks = [make_request(i) for i in range(1, 11)]
        await asyncio.gather(*tasks)


async def example_6_post_request():
    """Example 6: Async POST request"""
    print("\n=== Example 6: Async POST Request ===")

    async with AsyncBrowserClient(profile=Chrome119) as client:
        data = {
            "username": "testuser",
            "password": "testpass"
        }
        response = await client.post("https://httpbin.org/post", json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()['json']}")


async def example_7_with_proxy():
    """Example 7: Async request with proxy"""
    print("\n=== Example 7: With Proxy ===")

    proxy = "http://proxy.example.com:8080"  # Replace with real proxy

    try:
        async with AsyncBrowserClient(
                profile=Chrome119,
                proxy=proxy
        ) as client:
            response = await client.get("https://httpbin.org/ip")
            print(f"IP: {response.json()}")
    except Exception as e:
        print(f"Error (expected if proxy doesn't exist): {e}")


async def example_8_error_handling():
    """Example 8: Error handling in async requests"""
    print("\n=== Example 8: Error Handling ===")

    urls = [
        "https://httpbin.org/status/200",
        "https://httpbin.org/status/404",
        "https://httpbin.org/status/500",
        "https://invalid-url-that-does-not-exist.com",
    ]

    async def safe_fetch(url):
        try:
            async with AsyncBrowserClient(profile=Chrome119) as client:
                response = await client.get(url, timeout=5)
                return url, response.status_code, None
        except Exception as e:
            return url, None, str(e)

    results = await asyncio.gather(*[safe_fetch(url) for url in urls])

    for url, status, error in results:
        if error:
            print(f"❌ {url}: Error - {error}")
        else:
            print(f"✅ {url}: Status {status}")


async def example_9_rate_limiting():
    """Example 9: Rate limiting with semaphore"""
    print("\n=== Example 9: Rate Limiting ===")

    # Only allow 2 concurrent requests
    semaphore = asyncio.Semaphore(2)

    async def fetch_with_limit(url, i):
        async with semaphore:
            print(f"  Starting request {i}...")
            async with AsyncBrowserClient(profile=Chrome119) as client:
                response = await client.get(url)
                print(f"  Completed request {i}: {response.status_code}")
                return response.status_code

    urls = [f"https://httpbin.org/delay/1" for _ in range(6)]

    import time
    start = time.time()
    await asyncio.gather(*[fetch_with_limit(url, i) for i, url in enumerate(urls, 1)])
    elapsed = time.time() - start

    print(f"Total time: {elapsed:.2f}s (should be ~3s with 2 concurrent)")


async def example_10_batch_processing():
    """Example 10: Batch processing with results"""
    print("\n=== Example 10: Batch Processing ===")

    # Simulate processing multiple pages
    pages = range(1, 11)

    async def process_page(page_num):
        async with AsyncBrowserClient(profile=Chrome119) as client:
            response = await client.get(
                f"https://httpbin.org/anything",
                params={"page": page_num}
            )
            data = response.json()
            return {
                "page": page_num,
                "status": response.status_code,
                "url": data.get("url")
            }

    # Process in batches of 3
    batch_size = 3
    all_results = []

    for i in range(0, len(pages), batch_size):
        batch = pages[i:i + batch_size]
        print(f"Processing batch: {list(batch)}")

        results = await asyncio.gather(*[process_page(p) for p in batch])
        all_results.extend(results)

        # Optional: delay between batches
        if i + batch_size < len(pages):
            await asyncio.sleep(1)

    print(f"Processed {len(all_results)} pages")
    for result in all_results[:3]:  # Show first 3
        print(f"  Page {result['page']}: {result['status']}")

async def tls_check():
    print("\n=== Example11 tls check ===")
    show_fingerprint()
    url = "https://web.kick.com/api/v1/drops/campaigns"

    client_sync = BrowserClient(
        Edge142,
        proxy="http://127.0.0.1:7890"
    )
    resp = client_sync.get(url)
    print("sync:", resp.status_code)
    from browser_forge import AsyncRustTLSProxyClient
    async with AsyncRustTLSProxyClient(
            base_url="http://127.0.0.1:5005",
            default_profile="chrome_119_windows",
    ) as client:
        resp = await client.get("https://web.kick.com/api/v1/drops/campaigns")
        print(resp.status_code)
        print(resp.text[:300])

    # await tls_check_async_part(resp.cookies)

    async with AsyncBrowserClient(
        profile=Edge142,
        proxy="http://127.0.0.1:7890",   # ✅ 加上同样的代理
    ) as client:
        response = await client.get(url=url)
        print("async:", response.status_code)

def tls_check_sync_part():
    url = "https://web.kick.com/api/v1/drops/campaigns"
    client_sync = BrowserClient(
        Edge142,
        proxy="http://127.0.0.1:7890"
    )
    resp = client_sync.get(url)
    print("sync:", resp.status_code)
    return client_sync.cookies  # 返回 cookies

async def tls_check_async_part(cookies):
    url = "https://web.kick.com/api/v1/drops/campaigns"

    #async with AsyncBrowserClient(
    async with AsyncSession(impersonate="chrome120",
        #profile=Edge142,
        proxy="http://127.0.0.1:7890",
    ) as client:
        # 注意要在 __aenter__ 之后再设置 cookies
        client.cookies = cookies
        resp = await client.get(url)
        print("async with cookies:", resp.status_code)

def show_fingerprint():
    """
    同步异步不同情况生成指纹对比
    """
    ja3_str, ja3_hash = JA3Generator.generate_ja3(Edge142.tls_config)
    ja4_str = JA4Generator.generate_ja4(Edge142.tls_config)
    print("JA3:", ja3_str, ja3_hash)
    print("JA4:", ja4_str)

async def main():
    """Run all async examples"""
    print("=" * 60)
    print("Browser Forge - Async Client Examples")
    print("=" * 60)

    try:
        await tls_check()
        # await example_1_simple_async_request()
        # await example_2_multiple_requests()
        # await example_3_concurrent_requests()
        # await example_4_using_fetch_all()
        # await example_5_connection_pool()
        # await example_6_post_request()
        # await example_7_with_proxy()
        # await example_8_error_handling()
        # await example_9_rate_limiting()
        # await example_10_batch_processing()

        print("\n" + "=" * 60)
        print("✓ All async examples completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ Example failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())