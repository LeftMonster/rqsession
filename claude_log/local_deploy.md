# 本地部署到其他项目

## 前置条件

| 工具 | 说明 |
|---|---|
| Rust stable | `rustup show` 确认 |
| NASM | BoringSSL 编译必须，`nasm -v` 确认 |
| maturin | 装在 base env 即可，`python -m maturin --version` |

## 每次部署流程

### Step 1 — 构建 wheel

用 base env 的 maturin，`-i` 指向目标环境的 Python：

```powershell
D:\anaconda\python.exe -m maturin build --release `
  --manifest-path D:\ownrepo-github\requestsession\Cargo.toml `
  -i D:\anaconda\envs\<目标env名>\python.exe
```


产物在 `target\wheels\rqsession-x.x.x-cp3xx-cp3xx-win_amd64.whl`。

首次编译约 1 分钟（BoringSSL），后续增量编译 10~20 秒。

### Step 2 — 安装进目标环境

```powershell
D:\anaconda\envs\<目标env名>\python.exe -m pip install `
  D:\ownrepo-github\requestsession\target\wheels\rqsession-x.x.x-cp3xx-cp3xx-win_amd64.whl `
  --force-reinstall --no-deps
```


`--no-deps` 跳过依赖重装（`requests`、`curl-cffi` 等已存在时避免冲突）。  
首次安装去掉 `--no-deps`，让 pip 自动装依赖。

### Step 3 — 验证

从**非项目目录**运行（否则 Python 会优先加载源码树）：

```powershell
cd C:\Users\admin
D:\anaconda\envs\<目标env名>\python.exe -c "
from rqsession import BrowserSession, AsyncBrowserSession, Chrome120
print('OK')
"
```

---

## 注意事项

**wheel 与 Python 版本绑定**  
`cp310` wheel 只能装进 Python 3.10 的环境。目标环境换了 Python 版本，需重新执行 Step 1+2。

**不要从项目目录导入**  
`D:\ownrepo-github\requestsession` 下有 `rqsession/` 源码目录，Python 会优先找到它而不是 site-packages，导致加载旧的 `.pyd`。测试脚本放在其他目录或用绝对路径规避。

**源码树遗留 `.pyd` 的干扰**  
若源码树里有 `rqsession/_rust_core.cp3xx-win_amd64.pyd`（`maturin develop` 遗留），会在从项目目录运行时被误加载。发现后手动删除即可。

**只改了 Python 文件时**  
`.py` 文件修改不需要重新编译 Rust，但仍需重新 build wheel（maturin 会跳过 Rust 编译，几秒完成），再重新 pip install。

---

## 快速参考（twitchminer 环境）

```powershell
# 构建
D:\anaconda\python.exe -m maturin build --release `
  --manifest-path D:\ownrepo-github\requestsession\Cargo.toml `
  -i D:\anaconda\envs\<目标env名>\python.exe

# 安装（更新）
D:\anaconda\envs\<目标env名>\python.exe -m pip install `
  D:\ownrepo-github\requestsession\target\wheels\rqsession-0.3.2-cp310-cp310-win_amd64.whl `
  --force-reinstall --no-deps
```
