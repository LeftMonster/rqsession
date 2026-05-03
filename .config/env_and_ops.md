---
name: 开发环境与操作手册
description: CI/CD 触发模板、项目级环境说明——全局机器配置见 C:\Users\admin\.claude\CLAUDE.md
type: reference
---
# 开发环境与操作手册

> 机器级固定配置（Python路径、Shell规范、Git规范、GitHub账户）在全局文件：
> `C:\Users\admin\.claude\CLAUDE.md`
>
> 本文件记录：各项目 conda 环境对照、CI/CD 触发模板。

---

## 一、各项目 conda 环境

| 项目 | conda 环境名 | 备注 |
|---|---|---|
| requestsession | base（直接用 `D:\anaconda\python.exe`） | maturin 编译需要 base Python，不走 conda run |

> 新项目接入时在此表补充一行。若项目文档未指定 env，按全局文件优先级逻辑询问用户。

---

## 二、本地 Rust 编译（开发调试）

适用场景：修改了 `src/` 下的 Rust 代码后，需要重新编译让 `test_exmaple*.py` 等本地脚本生效。

**安装方式说明**：项目通过 `rqsession.pth` editable install，Python 直接读取项目目录，编译后的 `.pyd` 落在 `rqsession/` 目录，无需重装包。

```powershell
# NASM 装在 C:\Program Files\NASM\ 但未加入系统 PATH，每次编译前加一下
$env:PATH = "C:\Program Files\NASM;$env:PATH"
$env:CONDA_PREFIX = "D:\anaconda"
D:\anaconda\python.exe -m maturin develop --manifest-path D:\ownrepo-github\requestsession\Cargo.toml
```

编译完成后直接运行测试脚本即可，无需任何其他步骤：

```powershell
D:\anaconda\python.exe test_exmaple1.py
```

> `maturin develop` 产物为 debug 版 `.pyd`（无 LTO 优化，体积较大）。发布 wheel 走 CI/CD，不在本地执行。

---

## 三、CI/CD

**触发方式**：`workflow_dispatch`（手动或 API 触发），无自动触发。

### 2.1 {PROJECT_NAME}（具体项目，按需填写）

**仓库**：`{GITHUB_USER}/{REPO}`
**项目根**：当前工作目录

#### Workflow 文件

| 文件 | 构建方式 | 产物 zip 名 |
|------|---------|------------|
| `build-rust.yaml` | PyArmor + PyInstaller | `pyarmor-packed-files.zip` |
| `build-cython.yaml` | Cython + PyInstaller | `cython-packed-files.zip` |

#### 日常默认参数

```json
{
  "triggered_by": "claude",
  "run_py": "true",
  "build_with_release": "false",
  "upload_to_server": "false",
  "upload_to_aliyun_oss": "true"
}
```

#### OSS 路径规则

| 分支 | OSS 目标路径 |
|------|------------|
| `develop` | `oss://{BUCKET}/release/exe_test/run` |
| 其他 | `oss://{BUCKET}/release/exe/run` |

#### GitHub Secrets / Variables

| 名称 | 类型 | 用途 |
|------|------|------|
| `ALIYUN_OSS_ACCESS_KEY_ID` | Secret | OSS 访问密钥 ID |
| `ALIYUN_OSS_ACCESS_KEY_SECRET` | Secret | OSS 访问密钥 Secret |
| `ALIYUN_OSS_ENDPOINT` | Variable | OSS Endpoint 地址 |
| `DEPLOY_HOST` | Variable | 服务器地址（非默认不用） |
| `DEPLOY_USER` | Variable | 服务器用户名（非默认不用） |
| `DEPLOY_PASSWORD` | Secret | 服务器密码（非默认不用） |

#### 完整触发命令（PowerShell）

```powershell
$token = ((Get-Content "C:\Users\admin\.config\gh\hosts.yml") -match "oauth_token")[0].Split(": ")[1].Trim()

Invoke-RestMethod `
  -Uri "https://api.github.com/repos/{GITHUB_USER}/{REPO}/actions/workflows/build-rust.yaml/dispatches" `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github.v3+json"; "Content-Type" = "application/json" } `
  -Body '{"ref":"develop","inputs":{"triggered_by":"claude","run_py":"true","build_with_release":"false","upload_to_server":"false","upload_to_aliyun_oss":"true"}}'
```

---

### 2.2 新项目模板（占位符版）

> 新项目开始时复制此节，替换 `{...}` 占位符。

**仓库**：`{GITHUB_USER}/{REPO_NAME}`
**Python 环境**：`{CONDA_ENV_NAME}`（未指定则按全局优先级逻辑询问）

#### Workflow 文件

| 文件 | 构建方式 | 产物名 |
|------|---------|--------|
| `{WORKFLOW_FILE}` | {BUILD_TYPE} | `{ARTIFACT_NAME}` |

#### 日常默认参数

```json
{
  "triggered_by": "claude",
  {OTHER_INPUTS}
}
```

#### OSS 路径规则

| 分支 | OSS 目标路径 |
|------|------------|
| `develop` | `oss://{BUCKET}/{TEST_PATH}` |
| 其他 | `oss://{BUCKET}/{PROD_PATH}` |

#### GitHub Secrets / Variables

| 名称 | 类型 | 用途 |
|------|------|------|
| `{SECRET_NAME}` | Secret/Variable | {描述} |

#### 触发命令（PowerShell）

```powershell
$token = ((Get-Content "C:\Users\admin\.config\gh\hosts.yml") -match "oauth_token")[0].Split(": ")[1].Trim()

Invoke-RestMethod `
  -Uri "https://api.github.com/repos/{GITHUB_USER}/{REPO_NAME}/actions/workflows/{WORKFLOW_FILE}/dispatches" `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github.v3+json"; "Content-Type" = "application/json" } `
  -Body '{"ref":"develop","inputs":{"triggered_by":"claude",{OTHER_INPUTS_JSON}}}'
```