# 本地安装测试 & PyPI 发布指南

**最后更新：** 2026-04-30

---

## 一、在其他本地项目中安装使用

### 情况 A：其他项目也用 base Python（D:\anaconda）

`maturin develop` 已经将包装入 base，无需额外操作，直接导入即可：

```python
from rqsession.rust_session import BrowserSession, Chrome120
```

---

### 情况 B：其他项目用独立 conda env

**推荐方式：先 build wheel，再 pip install**

```powershell
# 1. 在 requestsession 目录 build release wheel
$env:CONDA_PREFIX = "D:\anaconda"
D:\anaconda\python.exe -m maturin build --release --manifest-path D:\ownrepo-github\requestsession\Cargo.toml

# 2. 产物在 dist/ 目录下，文件名类似：
#    rqsession-0.3.2-cp312-cp312-win_amd64.whl

# 3. 在目标 conda env 中安装
& "D:\anaconda\Scripts\conda.exe" run -n <目标env名> pip install D:\ownrepo-github\requestsession\dist\rqsession-0.3.2-cp312-cp312-win_amd64.whl
```

**备选方式：pip install 直接指向源码目录**

pip 会自动调用 maturin 编译后安装：

```powershell
& "D:\anaconda\Scripts\conda.exe" run -n <目标env名> pip install D:\ownrepo-github\requestsession\
```

> 缺点：目标 env 所在机器必须有完整 Rust / NASM 工具链，不如 wheel 方式可移植。

---

## 二、PyPI 发布（CI/CD）

### 发布触发方式

push 一个 `v*` 格式的 tag 即自动触发全平台构建 + 发布：

```bash
git tag v0.3.3
git push origin v0.3.3
```

也可在 GitHub Actions 页面手动触发（`workflow_dispatch`），此时只构建不发布。

---

### 当前 CI 覆盖平台

| 平台 | Runner | Python 版本覆盖 | 说明 |
|---|---|---|---|
| Linux x86_64 | ubuntu-latest (manylinux) | cp38–cp312 ✓ | 容器内置所有 CPython，`--find-interpreter` 全找到 |
| Linux aarch64 | ubuntu-latest (manylinux, 交叉编译) | cp38–cp312 ✓ | 同上 |
| Windows x86_64 | windows-latest | cp38–cp312 ✓ | Runner 预装所有 CPython |
| macOS x86_64 | macos-13 | **可能仅 cp311** | 见下方说明 |
| macOS arm64 | macos-14 | **可能仅 cp311** | 见下方说明 |

### macOS Python 版本问题

当前 YAML 用 `setup-python` 只装了 3.11，`--find-interpreter` 能找到的 Python 取决于 Runner 预装情况，不稳定。

如需保证 macOS 也覆盖 cp38–cp312，需将 macOS 条目改为 Python 版本矩阵：

```yaml
strategy:
  matrix:
    include:
      # macOS x86_64，每个 Python 版本单独一个 job
      - os: macos-13
        target: x86_64
        python: "3.8"
      - os: macos-13
        target: x86_64
        python: "3.9"
      - os: macos-13
        target: x86_64
        python: "3.10"
      - os: macos-13
        target: x86_64
        python: "3.11"
      - os: macos-13
        target: x86_64
        python: "3.12"
      # macOS arm64（macos-14 最低支持 Python 3.9）
      - os: macos-14
        target: aarch64
        python: "3.9"
      # ... 依此类推到 3.12

# setup-python 步骤改为：
- uses: actions/setup-python@v5
  with:
    python-version: ${{ matrix.python }}

# maturin args 去掉 --find-interpreter：
args: --release --out dist
```

**当前是否需要改？** 如果用户群主要在 Linux / Windows，现有 YAML 直接可用；macOS 用户需要从源码安装（sdist 已包含），待需求明确再改。

---

### Secret 配置（一次性设置）

在 GitHub repo → Settings → Secrets and variables → Actions 中添加：

| Secret 名 | 值 |
|---|---|
| `PYPI_API_TOKEN` | 在 PyPI 账号 → Account settings → API tokens 生成，scope 选该项目 |

---

### 版本号更新流程

每次发版前同步更新两处版本号（必须一致）：

```
pyproject.toml   → [project] version = "x.y.z"
Cargo.toml       → [package] version = "x.y.z"
```

然后 push tag 触发 CI。
