---
name: 开发环境与操作手册
description: Python环境、Shell规范、GitHub API调用、Git规范、CI/CD触发方式——新会话读此文件可立即上手，无需全局搜索
type: reference
originSessionId: 000305d5-b114-4d73-bb44-601895e3d204
---
# 开发环境与操作手册

## 一、Python 运行环境

- **Conda 可执行**：`D:\anaconda\Scripts\conda.exe`
- **默认项目环境**：`twitchminer`（Python 3.10.16）
- **其他项目**可能使用不同 conda 环境，以各项目说明为准

### 各项目 conda 环境

| 项目 | conda 环境名      | 备注 |
|---|----------------|---|
| requestsession（本项目） | `taskplatfrom` | 注意：拼写即如此（platform 少了 'a'），非笔误 |

### 运行命令（PowerShell）

```powershell
# 运行脚本
& "D:\anaconda\Scripts\conda.exe" run -n twitchminer python <script.py>

# 安装包
& "D:\anaconda\Scripts\conda.exe" run -n twitchminer pip install <package>

# 安装 requirements
& "D:\anaconda\Scripts\conda.exe" run -n twitchminer pip install -r requirements.txt
```

**注意**：`conda run` 会打印两行 `anaconda-cloud-auth pydantic` 警告，无害，忽略即可。
bash 里 `python3` / `py` 命令不可用，必须走 conda run 或先激活环境。

---

## 二、Shell 使用规范

- **优先使用 PowerShell**（5.1）执行 Windows 命令（路径、conda、git）
- bash（Git Bash）可用但 Windows 路径格式不一致，易出错
- PowerShell 5.1 不支持 `&&`，顺序执行用 `; if ($?) { ... }`

---

## 三、GitHub 账户 & API

- **用户名**：`LeftMonster`
- **邮箱**：`zhzhsgg@gmail.com`
- **无 gh CLI**，所有 GitHub 操作走 HTTP API

### Token 读取方式

Token 存储于 `C:\Users\admin\.config\gh\hosts.yml`，字段为 `oauth_token`。

```powershell
# 读取 token（PowerShell）
$token = ((Get-Content "C:\Users\admin\.config\gh\hosts.yml") -match "oauth_token")[0].Split(": ")[1].Trim()
```

### 通用 API 调用模板

```powershell
$token = ((Get-Content "C:\Users\admin\.config\gh\hosts.yml") -match "oauth_token")[0].Split(": ")[1].Trim()

Invoke-RestMethod `
  -Uri "https://api.github.com/repos/{OWNER}/{REPO}/actions/workflows/{WORKFLOW_FILE}/dispatches" `
  -Method Post `
  -Headers @{
    Authorization  = "Bearer $token"
    Accept         = "application/vnd.github.v3+json"
    "Content-Type" = "application/json"
  } `
  -Body '{...}'
```

---

## 四、Git 操作规范

- **默认提交分支**：`develop`
- **主分支**：`main`（不直接提交，仅 merge）
- **Remote 格式**：`git@github.com:LeftMonster/{REPO}.git`
- Git 可执行在系统 PATH：`D:\Ainstalled\Git\Git\cmd`，`git` 命令直接可用

---

## 五、CI/CD

**触发方式**：`workflow_dispatch`（手动或 API 触发），无自动触发。

### 5.1 twitch-drops-sys（具体值）

**仓库**：`LeftMonster/twitch-drops-sys`
**Remote**：`git@github.com:LeftMonster/twitch-drops-sys.git`
**项目路径**：`E:\github\twitch-drops-sys\`

#### Workflow 文件

| 文件 | 构建方式 | 产物 zip 名 |
|------|---------|------------|
| `build-rust.yaml` | PyArmor + PyInstaller | `pyarmor-packed-files.zip` |
| `build-cython.yaml` | Cython + PyInstaller | `cython-packed-files.zip` |

#### 日常默认参数（不发版、不上传服务器、只传 OSS + 构建 main.py）

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
| `develop` | `oss://normal-base/release/exe_test/run` |
| 其他 | `oss://normal-base/release/exe/run` |

#### GitHub Secrets / Variables（仓库设置中配置）

| 名称 | 类型 | 用途 |
|------|------|------|
| `ALIYUN_OSS_ACCESS_KEY_ID` | Secret | OSS 访问密钥 ID |
| `ALIYUN_OSS_ACCESS_KEY_SECRET` | Secret | OSS 访问密钥 Secret |
| `ALIYUN_OSS_ENDPOINT` | Variable | OSS Endpoint 地址 |
| `DEPLOY_HOST` | Variable | 服务器地址（非默认不用） |
| `DEPLOY_USER` | Variable | 服务器用户名（非默认不用） |
| `DEPLOY_PASSWORD` | Secret | 服务器密码（非默认不用） |

#### 完整触发命令（PowerShell，日常默认）

```powershell
$token = ((Get-Content "C:\Users\admin\.config\gh\hosts.yml") -match "oauth_token")[0].Split(": ")[1].Trim()

# 触发 build-rust.yaml（PyArmor 版）
Invoke-RestMethod `
  -Uri "https://api.github.com/repos/LeftMonster/twitch-drops-sys/actions/workflows/build-rust.yaml/dispatches" `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github.v3+json"; "Content-Type" = "application/json" } `
  -Body '{"ref":"develop","inputs":{"triggered_by":"claude","run_py":"true","build_with_release":"false","upload_to_server":"false","upload_to_aliyun_oss":"true"}}'

# 触发 build-cython.yaml（Cython 版）
Invoke-RestMethod `
  -Uri "https://api.github.com/repos/LeftMonster/twitch-drops-sys/actions/workflows/build-cython.yaml/dispatches" `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github.v3+json"; "Content-Type" = "application/json" } `
  -Body '{"ref":"develop","inputs":{"triggered_by":"claude","run_py":"true","build_with_release":"false","upload_to_server":"false","upload_to_aliyun_oss":"true"}}'
```

---

### 5.2 新项目模板（占位符版）

> 新项目开始时复制此节，替换 `{...}` 占位符。

**仓库**：`LeftMonster/{REPO_NAME}`
**Remote**：`git@github.com:LeftMonster/{REPO_NAME}.git`
**项目路径**：`E:\github\{REPO_NAME}\`
**Python 环境**：`{CONDA_ENV_NAME}`（默认 `twitchminer`，若不同请注明）

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
  -Uri "https://api.github.com/repos/LeftMonster/{REPO_NAME}/actions/workflows/{WORKFLOW_FILE}/dispatches" `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github.v3+json"; "Content-Type" = "application/json" } `
  -Body '{"ref":"develop","inputs":{"triggered_by":"claude",{OTHER_INPUTS_JSON}}}'
```
