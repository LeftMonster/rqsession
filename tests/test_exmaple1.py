from rqsession.rust_session import BrowserSession, Chrome120, Firefox133, Safari17

# 创建 session（默认 Chrome120 指纹）
s = BrowserSession(Chrome120)

# GET 请求
# resp = s.get("https://httpbin.org/get")
resp = s.get("https://web.kick.com/api/v1/drops/progress")
print(resp.status_code)   # 200
print(resp.json())         # dict

# # POST JSON
# resp = s.post(
#     "https://httpbin.org/post",
#     json={"key": "value"},
# )
# print(resp.text)
#
# # 带代理
# s = BrowserSession(Firefox133, proxy="http://127.0.0.1:7890")
# resp = s.get("https://httpbin.org/ip")
#
# # 跳过 SSL 验证
# s = BrowserSession(Chrome120, verify=False)