from rqsession.rust_session import BrowserSession, Chrome120, Chrome138, Firefox133, Safari17, Edge141, Edge142, Edge147, Firefox146, Py37Aiohttp381, Tor128, AndroidChrome114, MacosChrome140

# 创建 session（默认 Chrome120 指纹）
s = BrowserSession(MacosChrome140)

# GET 请求
# resp = s.get("https://httpbin.org/get")
# url = "https://kick.com/api/search"
# params = {"searched_word": 'rust'}
# headers = {
#     "accept": "application/json",
#     "accept-language": "en-US,en;q=0.9",
#     "referer": f"https://kick.com/search/livestreams?query=rust",
# }
# url = "https://web.kick.com/api/v1/drops/campaigns"
url = "https://web.kick.com/api/v1/drops/progress"
s.update_headers({
    "authorization": "Bearer 297461030%7CI9sw0HGYDF5Enber3HdVi5cFzxS91PlBlaP5vFnW"
})

resp = s.get(url)
print(resp.status_code)   # 200
print(resp.text)         # dict
# print(resp.json())         # dict

# POST JSON
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