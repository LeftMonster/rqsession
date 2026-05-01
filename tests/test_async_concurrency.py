"""
并发压测：AsyncBrowserSession 高并发请求测试。

运行全部：
    pytest tests/test_async_concurrency.py -v -s

跳过慢速 1000 并发测试：
    pytest tests/test_async_concurrency.py -v -s -m "not slow"
"""

import asyncio
import sys
import time
from collections import Counter

import pytest

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from rqsession.rust_session import AsyncBrowserSession, Chrome120, Edge142

TARGET_URL = "https://kick.com/api/search"
SEARCH_PARAMS = {"searched_word": "rust"}


async def _run_concurrent(profile, n: int) -> dict:
    """Fire n concurrent GET requests and collect stats."""

    async def fetch(s, idx):
        t0 = time.perf_counter()
        try:
            resp = await s.get(TARGET_URL, params=SEARCH_PARAMS)
            return {
                "idx": idx,
                "status": resp.status_code,
                "elapsed": time.perf_counter() - t0,
                "ok": resp.status_code == 200,
            }
        except Exception as e:
            return {
                "idx": idx,
                "status": -1,
                "elapsed": time.perf_counter() - t0,
                "ok": False,
                "error": str(e),
            }

    t_start = time.perf_counter()
    async with AsyncBrowserSession(profile) as s:
        results = await asyncio.gather(*[fetch(s, i) for i in range(n)])
    wall = time.perf_counter() - t_start

    times = sorted(r["elapsed"] for r in results)
    ok_count = sum(1 for r in results if r["ok"])
    status_dist = Counter(r["status"] for r in results)

    return {
        "n": n,
        "wall": wall,
        "ok": ok_count,
        "failed": n - ok_count,
        "success_rate": ok_count / n,
        "status_dist": dict(status_dist),
        "lat_min": times[0],
        "lat_p50": times[n // 2],
        "lat_p90": times[int(n * 0.90)],
        "lat_p95": times[int(n * 0.95)],
        "lat_max": times[-1],
        "failed_samples": [r for r in results if not r["ok"]][:5],
    }


def _print_report(label: str, s: dict) -> None:
    print(f"\n{'=' * 54}")
    print(f"  {label}")
    print(f"{'=' * 54}")
    print(f"  Total wall time : {s['wall']:.2f}s")
    print(f"  Requests        : {s['n']}")
    print(f"  Success (200)   : {s['ok']}  ({s['success_rate']*100:.1f}%)")
    print(f"  Failed          : {s['failed']}  ({s['failed']/s['n']*100:.1f}%)")
    print(f"  Status breakdown: {s['status_dist']}")
    print(f"  Latency (ms):")
    print(f"    min  {s['lat_min']*1000:.0f}")
    print(f"    p50  {s['lat_p50']*1000:.0f}")
    print(f"    p90  {s['lat_p90']*1000:.0f}")
    print(f"    p95  {s['lat_p95']*1000:.0f}")
    print(f"    max  {s['lat_max']*1000:.0f}")
    if s["failed_samples"]:
        print(f"  Failed samples (first {len(s['failed_samples'])}):")
        for r in s["failed_samples"]:
            print(f"    #{r['idx']:04d}  status={r['status']}  {r.get('error','')[:80]}")


# ── 100 并发（Chrome120）────────────────────────────────────────────────────

def test_concurrent_100_chrome120():
    """100 并发 Chrome120，期望全部成功。"""
    stats = asyncio.run(_run_concurrent(Chrome120, 100))
    _print_report("100 concurrent — Chrome120", stats)

    # 成功率应为 100%（100 并发对 kick.com 无压力）
    assert stats["success_rate"] == 1.0, (
        f"Expected 100% success, got {stats['ok']}/100. "
        f"Status dist: {stats['status_dist']}"
    )
    # 整批应在 30 秒内完成
    assert stats["wall"] < 30, f"Wall time {stats['wall']:.1f}s exceeded 30s limit"


# ── 1000 并发（Edge142）─────────────────────────────────────────────────────

@pytest.mark.slow
def test_concurrent_1000_edge142():
    """
    1000 并发 Edge142 压测。

    成功率下限设为 80%：1000 并发时本地代理 / OS 连接池可能成为瓶颈，
    TCP 超时失败属于基础设施限制，不代表指纹被封。
    判断标准：失败响应全部为连接超时（status=-1），不出现 403/429。
    """
    stats = asyncio.run(_run_concurrent(Edge142, 1000))
    _print_report("1000 concurrent — Edge142", stats)

    # 不应出现反爬响应（403 / 429 / 503）
    anti_bot_statuses = {403, 429, 503}
    blocked = {
        s for s in stats["status_dist"] if s in anti_bot_statuses
    }
    assert not blocked, (
        f"Anti-bot responses detected: {blocked}. "
        f"Full status dist: {stats['status_dist']}"
    )

    # 成功率不低于 80%（基础设施容量限制容忍 20% 连接超时）
    assert stats["success_rate"] >= 0.80, (
        f"Success rate {stats['success_rate']*100:.1f}% below 80% threshold. "
        f"Status dist: {stats['status_dist']}"
    )
