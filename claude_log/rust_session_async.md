# rust_session — AsyncBrowserSession 异步版本

**创建时间：** 2026-04-28  
**最后更新：** 2026-06-12（v0.4.6）

---

## 背景与决策

### 需求

用户需要在 `asyncio` 代码（如 `aiohttp` 风格）中直接 `async with` / `await` 使用 BrowserSession，而不是在 async 上下文里调用阻塞的同步接口。

### 方案评估

| 方案 | 原理 | 结论 |
|---|---|---|
| 方向一：`asyncio.to_thread` 包装同步版本 | 把同步 `BrowserSession.get()` 丢到线程池 | 不需要改 Rust，但每次请求都阻塞一个线程，无法利用 Tokio 事件循环的异步优势 |
| 方向二：`pyo3-async-runtimes` 暴露真正异步接口 | Rust async fn 通过 `future_into_py` 变成 Python coroutine | 真正异步，Tokio 事件循环驱动，支持高并发，**选定** |

### 关键决策

- **不修改同步版本**：`PyBrowserSession` / `BrowserSession` 完全保持不动
- **新增独立 Rust 结构体**：`PyAsyncBrowserSession`，无 `runtime` 字段（不需要自建 Runtime，用 pyo3-async-runtimes 的全局 Tokio Runtime）
- **全局 Runtime**：`pyo3-async-runtimes 0.22` 的 `tokio-runtime` feature 在第一次调用 `future_into_py` 时懒加载启动全局多线程 Tokio Runtime，无需显式初始化
- **Cookie 线程安全**：`session_cookies` 使用 `std::sync::Mutex`，在 async block 内的 lock 调用不跨 await 点，符合 Tokio 最佳实践

---

## 实现原理

### Rust 侧关键机制

```rust
// 方法签名：同步调用返回一个 Python coroutine 对象
fn get<'py>(
    &self,
    py: Python<'py>,
    url: String,
    ...
) -> PyResult<Bound<'py, PyAny>> {
    // 1. 同步阶段：在 Python 线程中构建好所有需要 move 进 future 的数据
    let final_url = append_params(&url, params.as_ref());
    let mut all_headers = self.build_default_headers_async(&final_url); // 同步读 cookies
    // 合并 user headers...

    // 2. 克隆所有 Arc/owned 数据，使 future 满足 'static + Send
    let profile = Arc::clone(&self.profile);
    let proxy = self.proxy.clone();
    let session_cookies = Arc::clone(&self.session_cookies);

    // 3. 把 Rust future 包装成 Python coroutine
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        // async block 拥有所有数据，borrow (&method, &final_url 等) 是内部借用
        let result = http_client::execute(&method, &final_url, ...).await?;

        // 4. 持久化 Set-Cookie（brief lock，不跨 await）
        if let Some(sc) = result.headers.get("set-cookie") { ... }

        // 5. 获取 GIL 创建 Python 对象
        Python::with_gil(|py| Py::new(py, PyResponse::from_rust(result)))
    })
}
```

### `'static + Send` 约束满足

`future_into_py` 要求 future 实现 `Send + 'static`：

- 所有 capture 的值（`String`、`Arc<BrowserProfile>`、`Arc<Mutex<...>>`、`bool`）均为 `Send + 'static` ✓
- async block 内部对 `&method`、`&final_url` 的借用是 block 内部借用，不逃逸 ✓
- `BrowserProfile` 是纯数据结构体（String + Vec），自动 `Send + Sync` ✓

### 两个 Tokio Runtime 并存

| 版本 | Runtime 来源 |
|---|---|
| 同步 `BrowserSession` | 每个实例自建 `tokio::runtime::Runtime`（`block_on` 驱动） |
| 异步 `AsyncBrowserSession` | pyo3-async-runtimes 全局共享 Runtime |

两者完全独立，不会互相干扰。**注意**：不要在 async 上下文（pyo3-async-runtimes Runtime 的 worker 线程）里调用同步版本的 `BrowserSession`，因为 `block_on` 在 Tokio worker 线程内调用会 panic（"Cannot start a runtime from within a runtime"）。

---

## Cargo 依赖变更

```toml
# Cargo.toml 新增
pyo3-async-runtimes = { version = "0.22", features = ["tokio-runtime"] }
```

版本对应关系：`pyo3-async-runtimes 0.22.x` 对应 `pyo3 0.22.x`（两者 major 版本同步）。

---

## 新增文件

```
src/lib.rs                             — 新增 PyAsyncBrowserSession struct + #[pymethods]
rqsession/rust_session/async_session.py  — Python 包装层（AsyncBrowserSession 类）
rqsession/rust_session/__init__.py      — 新增导出 AsyncBrowserSession
```

---

## Python API

```python
from rqsession.rust_session import AsyncBrowserSession, Chrome120

# 基本用法
async with AsyncBrowserSession(Chrome120) as s:
    resp = await s.get("https://example.com")
    print(resp.status_code, resp.json())

# 带代理
async with AsyncBrowserSession(Chrome120, proxy="http://127.0.0.1:7890") as s:
    resp = await s.get("https://example.com")

# 关闭 SSL 验证
async with AsyncBrowserSession(Chrome120, verify=False) as s:
    resp = await s.get("https://self-signed.example.com")

# 并发请求（真正异步，不阻塞线程）
import asyncio
results = await asyncio.gather(
    s.get("https://example.com/a"),
    s.get("https://example.com/b"),
    s.get("https://example.com/c"),
)

# POST
resp = await s.post(url, json={"key": "value"})
resp = await s.post(url, data=b"raw bytes")

# 通用请求
resp = await s.request("PUT", url, headers={"x-token": "abc"}, json={})

# allow_redirects（默认 True）
resp = await s.get(url, allow_redirects=False)  # 停在 3xx，Set-Cookie 仍入 session

# Cookie 管理
s.update_cookies({"session_id": "xyz"})  # 同步方法，设置后续请求自动携带

# Profile 信息
print(s.profile_name)
```

构造参数与同步版本一致：
```python
AsyncBrowserSession(
    profile,                  # 内置常量或 BrowserProfile 对象
    *,
    proxy=None,               # "http://host:port" 或 "http://user:pass@host:port"
    verify=True,              # False 跳过 SSL 验证
    ca_bundle=None,           # 自定义 CA 文件路径；None 时自动用 certifi
)
```

Response 对象与同步版本完全一致（`status_code`、`text`、`content`、`headers`、`json()`、`ok`、`raise_for_status()`）。

Session 附加属性：

```python
s.headers      # dict — 完整实际发送 headers（profile 基线 + session_headers + cookie header）
s.cookies      # dict — 当前 session cookies
s.profile_name # str  — 当前 profile 名称

# 修改接口（只读属性 headers 返回副本，不能直接修改；用以下方法变更）
s.update_headers({"x-custom": "value"})
s.update_cookies({"session_id": "abc"})

---

## Windows 注意事项

Python 3.8+ 在 Windows 上默认使用 `ProactorEventLoop`，与 pyo3-async-runtimes 存在兼容问题时，改用 `SelectorEventLoop`：

```python
import asyncio, sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

asyncio.run(main())
```

实测（Windows 10 + Python 3.12）使用默认事件循环也能正常工作，但遇到 "Event loop is closed" 类错误时第一步就改这个。

---

## ⚠️ 已知 Bug 修复

### v0.4.3 — 多协程共享实例死锁

**症状：** 大量协程共用同一个 `AsyncBrowserSession` 实例时程序永久卡死。

**根因：** `do_request` 的 async block 中，`session_cookies` MutexGuard `sc` 在声明后没有显式 drop，在 `Python::with_gil()` 调用时仍持有锁。

- Tokio 线程：持有 `session_cookies` mutex → `Python::with_gil()` → 等待 GIL
- Python 线程（持有 GIL）：调用另一协程的 `do_request` → `build_default_headers_async()` → `session_cookies.lock()` → 等待 mutex
- → **互相等待，永久卡死**

**修复：** 在 `src/lib.rs` 用 `{}` 作用域限定 MutexGuard，确保 mutex 在 `Python::with_gil()` 之前释放。

**通用规则（PyO3 项目）：** 在 Tokio async 任务中，凡调用 `Python::with_gil()` 前，必须确保所有 `std::sync::Mutex` 锁已经释放。

### v0.4.6 — sync BrowserSession HTTP 请求永久挂死

**症状：** `BrowserSession` 对明文 HTTP 端点的所有请求（含 `allow_redirects=False`）永久卡死；HTTPS 以前碰巧能工作。

**根因：** `PyBrowserSession::request` 持有 Python GIL 调用 `block_on`。Windows IOCP 需要在当前线程上投递 I/O 完成事件，而 GIL 导致 Tokio 的 I/O 驱动无法完成事件循环轮转，`TcpStream::connect` 永远不返回。

**修复：** 为 `get` / `post` / `request` 加 `py: Python<'_>` 参数，用 `py.allow_threads(|| { runtime.block_on(...) })` 包裹，在 I/O 期间释放 GIL。Python API 签名不变（`py` 由 PyO3 自动注入，对调用方不可见）。

### v0.4.6 — HTTP/1.1 请求行 absolute-form 错误

**症状：** 直连时发出 `GET http://host/path HTTP/1.1`（absolute-form），只有接受这种格式的服务端才正常响应；标准服务器会路由错误或返回 404/400。

**根因：** `build_request` 直接把完整 `Uri` 写入请求行，而 RFC 7230 规定非代理直连必须用 origin-form（`GET /path HTTP/1.1`）。

**修复：** 改用 `uri.path_and_query().as_str()` 作为请求行目标。不影响 TLS 指纹（TLS 握手在 HTTP 层之前完成）。

---

## 实测结果

并发用 4 个不同 profile 同时请求 kick.com/api/search，全部返回 200：

```
[Chrome120]  status=200
[Firefox133] status=200
[Safari17]   status=200
[Edge142]    status=200
```
