# rust_session — 构建环境与编译说明

**最后更新：** 2026-04-28

---

## 构建工具链要求

| 工具 | 版本 | 说明 |
|---|---|---|
| Rust | stable | `dtolnay/rust-toolchain@stable` |
| Python | 3.8+ | 本地开发用 3.12（Anaconda） |
| maturin | ≥1,<2 | PyO3 构建后端 |
| NASM | 任意 | BoringSSL 编译 ASM 优化代码必须 |
| LLVM/clang | 任意 | bindgen 生成 FFI 绑定必须（`libclang.dll`） |
| cmake | 任意 | BoringSSL 构建系统 |

Windows 下 NASM 和 LLVM 通过 winget 安装：
```bash
winget install NASM.NASM
winget install LLVM.LLVM
```

macOS 下 cmake 通过 brew 安装：
```bash
brew install cmake
```

---

## 关键 Cargo 依赖版本

```toml
pyo3                = { version = "0.22", features = ["extension-module"] }
pyo3-async-runtimes = { version = "0.22", features = ["tokio-runtime"] }  # 异步版本必须
boring              = "4"        # 实际解析到 4.21.2
tokio-boring        = "4"
hyper               = { version = "1", features = ["http1", "http2"] }
hyper-util          = { version = "0.1", features = ["tokio", "client", "http1", "http2"] }
flate2              = "1"        # gzip / deflate 解压
brotli              = "7"        # br 解压
zstd                = "0.13"     # zstd 解压
```

版本对应关系：`pyo3-async-runtimes` major 版本必须与 `pyo3` 一致（同为 0.22）。

---

## 本地开发安装

Anaconda 环境没有 `VIRTUAL_ENV` 或 `CONDA_PREFIX` 时，maturin 找不到环境，需要手动指定（PowerShell）：

```powershell
$env:CONDA_PREFIX = "D:\anaconda"
D:\anaconda\python.exe -m maturin develop --manifest-path D:\ownrepo-github\requestsession\Cargo.toml
```

注意事项：
- 用 `CONDA_PREFIX` 而不是 `VIRTUAL_ENV`（anaconda 用 CONDA_PREFIX，virtualenv 用 VIRTUAL_ENV）
- 必须加 `--manifest-path`，否则 maturin 可能误找到 `rust/Cargo.toml`（`rust_proxy_tls` 包，不含 pyo3/extension-module feature，会报错）
- 在 bash 环境里 `maturin` 命令找不到，必须用 `D:\anaconda\python.exe -m maturin`

安装成功后，`.pyd` 文件会出现在：
```
rqsession/_rust_core.cp312-win_amd64.pyd
```

---

## pyproject.toml 构建配置

从 `setuptools` 迁移到了 `maturin`：

```toml
[build-system]
requires = ["maturin>=1,<2"]
build-backend = "maturin"

[tool.maturin]
module-name = "rqsession._rust_core"
python-source = "."
features = ["pyo3/extension-module"]
```

`module-name = "rqsession._rust_core"` 确保编译产物放到 `rqsession/` 子包下，可以 `from rqsession._rust_core import ...`。

---

## rust/ 子目录隔离

`rust/Cargo.toml` 是旧的独立 Rust 代理服务，已经声明了 `[workspace]`，会被 Cargo workspace 解析隔离，不影响根目录的 maturin 构建。

但 maturin 在不加 `--manifest-path` 时可能误识别，因此**始终加 `--manifest-path Cargo.toml`**。

---

## 编译问题修复记录

### 问题 1：`SslCurve::PRIME256V1` 不存在

**boring 4.x 改动：** `SslCurve` 枚举的常量名改变，且整个 `SslCurve` API 被标记为 deprecated，推荐改用字符串接口。

**修复：** `tls_builder.rs` 放弃 `set_curves(&[SslCurve])` 接口，改用 `set_curves_list(&str)`，复用 `cipher_map::curves_to_groups_list()` 生成 `"X25519:P-256:P-384:..."` 格式字符串。

```rust
// 修复前（报错）
builder.set_curves(&[SslCurve::X25519, SslCurve::PRIME256V1, ...])?;

// 修复后
let groups = curves_to_groups_list(&config.curves);
if !groups.is_empty() {
    builder.set_curves_list(&groups).map_err(|e| Error::Tls(e.to_string()))?;
}
```

boring 4.x 的 `SslCurve` 命名参考（需要用时）：
- `SECP256R1`（不是 `PRIME256V1`）
- `SECP384R1`、`SECP521R1`、`X25519`

### 问题 2：PyO3 0.22 `into_pyobject` API

**PyO3 0.22 状态：** 已引入 `IntoPyObject` trait，但 `bool`、`i64`、`f64` 等基础类型**尚未实现** `IntoPyObject`，仍使用旧的 `IntoPy<PyObject>` trait（提供 `into_py(py)` 方法）。`&str`、`&bool` 等引用类型也没有 `into_pyobject`。

**修复：** `lib.rs` 的 `json_to_py` 函数改用 `into_py(py).into_bound(py)` 模式，类型构造器改用 `*_bound` 版本：

```rust
// bool（match 中 b: &bool）
serde_json::Value::Bool(b) => Ok((*b).into_py(py).into_bound(py)),

// 数字（i64/f64 owned，into_py 可用）
serde_json::Value::Number(n) => {
    if let Some(i) = n.as_i64() {
        Ok(i.into_py(py).into_bound(py))
    } else {
        Ok(n.as_f64().unwrap_or(f64::NAN).into_py(py).into_bound(py))
    }
}

// 字符串
serde_json::Value::String(s) => Ok(PyString::new_bound(py, s.as_str()).into_any()),

// 容器
serde_json::Value::Array(arr) => {
    let items: PyResult<Vec<_>> = arr.iter().map(|x| json_to_py(py, x)).collect();
    Ok(PyList::new_bound(py, items?).into_any())   // new_bound 不返回 Result，直接 .into_any()
}
serde_json::Value::Object(map) => {
    let dict = PyDict::new_bound(py);
    for (k, val) in map {
        dict.set_item(k, json_to_py(py, val)?)?;
    }
    Ok(dict.into_any())
}
```

PyO3 0.22 `*_bound` API 参考：
- `PyBool::new_bound(py, val)` → `Borrowed<'_, '_, PyBool>`（注意不是 `Bound`，`.into_any()` 前需 `.clone()` 或直接用 `into_py`）
- `PyString::new_bound(py, s)` → `Bound<'py, PyString>`
- `PyList::new_bound(py, iter)` → `Bound<'_, PyList>`（`T: ToPyObject`，iter 需 `ExactSizeIterator`）
- `PyDict::new_bound(py)` → `Bound<'_, PyDict>`

### 问题 3：`max_header_list_size` 类型错误

**hyper 1.x 改动：** `http2::Builder::max_header_list_size()` 接受 `u32`，不是 `u64`。

```rust
// 修复前
builder.max_header_list_size(v as u64);

// 修复后（v 本身已是 u32）
builder.max_header_list_size(v);
```

---

## 导入使用注意事项

editable install（`maturin develop`）会将包指向源码目录，`.pyd` 文件放在 `rqsession/` 下，**必须从项目目录运行**或将项目目录加入 `sys.path`：

```python
# 方式 1：在项目目录下运行脚本
# cd D:/ownrepo-github/requestsession && python script.py

# 方式 2：脚本内手动加路径
import sys
sys.path.insert(0, r"D:/ownrepo-github/requestsession")
from rqsession.rust_session import BrowserSession, Chrome120
```

从任意目录使用不受限制的方式：打包成 wheel（CI 自动构建）并用 pip 正式安装。

---

## CI/CD 构建矩阵

`.github/workflows/build-wheels.yml` 覆盖：

| 平台 | target | 说明 |
|---|---|---|
| Linux x86_64 | x86_64 | manylinux auto（yum/apt 安装 cmake） |
| Linux aarch64 | aarch64 | manylinux auto，交叉编译 |
| Windows x86_64 | x86_64 | — |
| macOS x86_64 | x86_64 | macos-13，brew install cmake |
| macOS arm64 | aarch64 | macos-14（M1/M2），brew install cmake |

触发条件：push `v*` tag 或手动 `workflow_dispatch`。tag 触发时额外运行 `release` job 上传 PyPI（需 `PYPI_API_TOKEN` secret）。
