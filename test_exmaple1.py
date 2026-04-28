from rqsession.rust_session import BrowserSession, Chrome120, Firefox133, Safari17

# 创建 session（默认 Chrome120 指纹）
s = BrowserSession(Chrome120)

# GET 请求
# resp = s.get("https://httpbin.org/get")
url = "https://kick.com/api/search"
params = {"searched_word": 'rust'}
headers = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "referer": f"https://kick.com/search/livestreams?query=rust",
}
url = "https://web.kick.com/api/v1/drops/campaigns"
resp = s.get(url, params=params)
print(resp.status_code)   # 200
print(resp.json())         # dict
# print(resp.text)         # dict

# POST JSON
resp = s.post(
    "https://httpbin.org/post",
    json={"key": "value"},
)
print(resp.text)

# 带代理
s = BrowserSession(Firefox133, proxy="http://127.0.0.1:7890")
resp = s.get("https://httpbin.org/ip")

# 跳过 SSL 验证
s = BrowserSession(Chrome120, verify=False)