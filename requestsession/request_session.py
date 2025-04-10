import requests
import random
import time
import json
import uuid
import os

from urllib.parse import urlparse
from http.cookiejar import Cookie

from requests import HTTPError, Timeout
from requests.exceptions import SSLError, ProxyError

from .logger import logger
from .config_util import get_config_ini


base_config = get_config_ini()

# 默认配置
DEFAULT_CONFIG = {
    "host": base_config["RequestSession"]["host"],
    "port": base_config["RequestSession"]["port"],
    "enabled": base_config["RequestSession"]["use_proxy"] == "1",
    "random_proxy": False,
    "print_log": base_config["RequestSession"]["log"] == "1",
    "proxy_file": "static/proxies.txt",
    "max_history_size": 100,
    "auto_headers": False,  # 设置默认的自动配置请求头、例如：Host、Referer、Origin 是否自动设置
    "user_agents_file": "static/useragents.txt",
    "languages_file": "static/language.txt",
    "work_path": "tmp/http_session"
}

os.makedirs(DEFAULT_CONFIG["work_path"], exist_ok=True)
os.makedirs(DEFAULT_CONFIG["work_path"] + "/log", exist_ok=True)


# import logging
# logger = logging.getLogger(__name__)
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s',
#     handlers=[
#         logging.StreamHandler(),  # 输出到控制台
#         logging.FileHandler(DEFAULT_CONFIG["work_path"] + '/log/access.log')  # 输出到文件
#     ]
# )
# logger.setLevel(logging.INFO)



class RequestSession(requests.Session):
    def __init__(self, proxy_method=None, proxy_file=None, config=None, **kwargs):
        """初始化请求会话

        Args:
            proxy_method: 自定义获取代理的方法
            proxy_file: 代理文件路径
            config: 配置字典，包含代理设置等
        """
        super().__init__()

        config = config or DEFAULT_CONFIG

        # 基本属性设置
        self._id = str(uuid.uuid4()).replace("-", "")
        self.file_name = self._id
        self.create_time = int(time.time())
        self.modify_time = int(time.time())
        self.work_dir = config.get("work_path", "tmp/http_session")

        # 代理设置
        default_host = config.get("host", "127.0.0.1")
        default_port = config.get("port", "7890")
        self.proxies_list = [f"http://{default_host}:{default_port}"]
        self.proxy_file = proxy_file
        self.proxy_method = proxy_method
        self.use_proxy = bool(config.get("enabled", False))
        self.random_proxy = bool(config.get("random_proxy", False))

        # 自动处理请求头设置
        self.auto_headers = bool(config.get("auto_headers", False))

        # 日志设置
        self.print_log = bool(config.get("print_log", True))

        # 请求历史
        self.request_history = []
        self.max_history_size = config.get("max_history_size", 100)

        # 资源文件路径
        self.user_agents_file = config.get("user_agents_file", "static/useragents.txt")
        self.languages_file = config.get("languages_file", "static/language.txt")

        # 如果提供了代理文件，加载代理
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, 'r', encoding='utf-8') as f:
                self.proxies_list = [line.strip() for line in f if line.strip()]

    def set_proxy(self, use_proxy=True, random_proxy=True):
        """设置代理的使用与否和获取方式"""
        self.use_proxy = use_proxy
        self.random_proxy = random_proxy

    def get_proxy(self):
        """获取代理"""

        # 自己配置的获取代理的方法、返回一个: http://xxxx:xx 这样的代理地址、可携带 username 与 password
        if self.proxy_method:
            return self.proxy_method()

        if self.proxies_list:
            if self.random_proxy and len(self.proxies_list) > 1:
                return random.choice(self.proxies_list)
            else:
                return self.proxies_list[0]
        return None

    def send(self, request, **kwargs):
        """重写send方法来控制是否使用代理并自动处理请求头"""
        try:
            # 自动设置请求头
            if self.auto_headers:
                parsed_url = urlparse(request.url)

                # 设置Host
                if 'Host' not in request.headers:
                    request.headers['Host'] = parsed_url.netloc

                # 设置Referer (如果没有提供)
                if 'Referer' not in request.headers and kwargs.get('auto_referer', True):
                    referer = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    request.headers['Referer'] = referer

                # 设置Origin (对POST请求特别有用)
                if request.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and 'Origin' not in request.headers:
                    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    request.headers['Origin'] = origin

            # 代理处理
            used_proxies = None
            if self.use_proxy:
                proxy = self.get_proxy()
                if proxy:
                    used_proxies = {'http': proxy, 'https': proxy}
                    kwargs['proxies'] = used_proxies

            # 记录请求开始时间
            request_start_time = time.time()

            # 发送请求
            response = super().send(request, **kwargs)

            # 计算请求耗时
            request_duration = time.time() - request_start_time

            # 记录请求和响应
            self.log_request_and_response(request, response, used_proxies, request_duration)

            return response
        except ProxyError as e:
            logger.error("代理连接失败: {}".format(e))
            raise e
        except (HTTPError, SSLError, ConnectionError) as e:
            logger.error("连接错误: {}".format(e))
            raise e
        except Timeout as e:
            logger.error("请求响应超时: {}".format(e))
            raise e
        except Exception as e:
            logger.error("网络请求其他错误: {}".format(e))
            raise e

    def initialize_session(self, headers=None, random_init=True):
        """初始化session的请求特征"""
        if headers:
            self.headers.update(headers)
            return

        # 初始化其他
        if random_init and headers is None:
            # 尝试从文件读取User-Agent列表
            user_agents = self._load_file_lines(self.user_agents_file, [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
            ])

            # 尝试从文件读取语言列表
            languages = self._load_file_lines(self.languages_file, [
                "en-US,en;q=0.9",
                "zh-CN,zh;q=0.9,en;q=0.8",
                "en-GB,en;q=0.9"
            ])

            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "*/*",
                "Accept-Language": random.choice(languages),
                # "Accept-Encoding": "gzip, deflate, br",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            self.headers.update(headers)
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-GB,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            self.headers.update(headers)


    def get_features(self):
        """获取当前session的所有特征"""
        return {
            'headers': dict(self.headers),
            'cookies': self.get_cookies_by_domain(),
            'proxies': getattr(self, 'proxies', None)
        }

    def get_cookies_by_domain(self):
        """获取按域名分组的cookie字典

        Returns:
            dict: 格式为 {domain: {name: value, ...}, ...}
        """
        domains = {}

        for cookie in self.cookies:
            domain = cookie.domain
            if domain not in domains:
                domains[domain] = {}

            # 存储当前cookie的详细信息
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value,
                'path': cookie.path,
                'secure': cookie.secure,
                'expires': cookie.expires,
                'domain': cookie.domain,
                'httponly': cookie.has_nonstandard_attr('httponly'),
                'rest': {'HttpOnly': cookie.has_nonstandard_attr('httponly')} if cookie.has_nonstandard_attr(
                    'httponly') else {},
            }

            domains[domain][cookie.name] = cookie_info

        return domains

    def save_session(self, filepath=None, _id=None):
        """序列化当前session"""
        if filepath:
            save_session_path = filepath
        elif self.file_name:
            save_session_path = f"{self.work_dir}/{self.file_name}.json"
        elif _id:
            save_session_path = f"{self.work_dir}/{_id}.json"
        elif self._id:
            save_session_path = f"{self.work_dir}/{self._id}.json"
        else:
            save_session_path = f"{self.work_dir}/{uuid.uuid4().hex}.json"

        # 确保目录存在
        os.makedirs(os.path.dirname(save_session_path), exist_ok=True)

        # 按域名组织的cookie
        domain_cookies = self.get_cookies_by_domain()

        with open(save_session_path, 'w', encoding='utf-8') as f:
            json.dump({
                '_id': self._id,
                'use_proxy': self.use_proxy,
                'work_dir': self.work_dir,
                'random_proxy': self.random_proxy,
                'auto_headers': self.auto_headers,
                'features': self.get_features(),
                'domain_cookies': domain_cookies,  # 按域名组织的cookie
                'create_time': self.create_time,
                'modify_time': int(time.time()),
                # 不保存请求历史，因为可能太大
            }, f, ensure_ascii=False, indent=2)

        return save_session_path

    @classmethod
    def load_session(cls, filepath):
        """反序列化为一个requests的session"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # print(data)
        session = cls()
        session._id = data.get('_id', str(uuid.uuid4()).replace("-", ""))
        session.file_name = filepath.split("/")[-1].split("\\")[-1].replace(".json", "")
        session.use_proxy = data.get("use_proxy", False)
        session.random_proxy = data.get("random_proxy", False)
        session.auto_headers = data.get("auto_headers", True)
        session.work_dir = data.get("work_dir", ".")
        session.create_time = data.get("create_time", int(time.time()))

        if 'features' in data and 'headers' in data['features']:
            session.headers.update(data['features']['headers'])

        # 按域名加载cookie
        if 'domain_cookies' in data:
            domain_cookies = data['domain_cookies']
            for domain, cookies in domain_cookies.items():
                for name, cookie_info in cookies.items():
                    session.add_cookie_from_dict(cookie_info)
        # 兼容旧格式
        elif 'cookies' in data:
            session.cookies.update(requests.utils.cookiejar_from_dict(data['cookies']))

        return session

    def add_cookie_from_dict(self, cookie_dict):
        """从字典中添加cookie到session

        Args:
            cookie_dict: 包含cookie信息的字典
        """
        # 提取必要参数
        name = cookie_dict.get('name')
        value = cookie_dict.get('value')
        domain = cookie_dict.get('domain')

        if not (name and domain):
            logger.warning(f"无法添加cookie: 缺少必要参数 name={name}, domain={domain}")
            return

        # 设置默认值
        path = cookie_dict.get('path', '/')
        expires = cookie_dict.get('expires')
        secure = cookie_dict.get('secure', False)

        # 创建Cookie对象
        cookie = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=bool(domain),
            domain_initial_dot=domain.startswith('.') if domain else False,
            path=path,
            path_specified=bool(path),
            secure=secure,
            expires=expires,
            discard=False,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': cookie_dict.get('httponly', False)},
            rfc2109=False
        )

        # 添加到cookiejar
        self.cookies.set_cookie(cookie)

    def set_cookies(self, cookies):
        """根据cookie字典列表或字典初始化到session的cookies中"""
        if isinstance(cookies, list):
            for cookie_dict in cookies:
                if isinstance(cookie_dict, dict) and 'name' in cookie_dict and 'value' in cookie_dict:
                    # 如果是完整的cookie信息字典
                    if 'domain' in cookie_dict:
                        self.add_cookie_from_dict(cookie_dict)
                    else:
                        self.cookies.set(**cookie_dict)
                else:
                    logger.warning(f"无法设置cookie: {cookie_dict}")
        elif isinstance(cookies, dict):
            # 如果是简单的name-value字典
            self.cookies.update(requests.utils.cookiejar_from_dict(cookies))
        elif isinstance(cookies, str):
            # 尝试从字符串解析
            self._set_cookies_from_string(cookies)

    def _set_cookies_from_string(self, cookie_string, domain=None):
        """从字符串设置cookies

        Args:
            cookie_string: Cookie字符串，例如 "name1=value1; name2=value2"
            domain: 可选，cookie所属的域名
        """
        if not cookie_string:
            return

        pairs = cookie_string.split(';')
        for pair in pairs:
            if '=' not in pair:
                continue

            name, value = pair.split('=', 1)
            name = name.strip()
            value = value.strip()

            if domain:
                self.cookies.set(name, value, domain=domain)
            else:
                self.cookies.set(name, value)

    def get_cookies_for_domain(self, domain):
        """获取指定域名下的cookie的字典对象"""
        return {cookie.name: cookie.value for cookie in self.cookies if domain in cookie.domain}

    def get_cookies_string(self, domain=None):
        """获取适合HTTP请求的Cookie字符串

        Args:
            domain: 可选，限制只返回指定域名的cookie

        Returns:
            str: 格式为 "name1=value1; name2=value2" 的cookie字符串
        """
        if domain:
            cookies = self.get_cookies_for_domain(domain)
            return '; '.join([f"{name}={value}" for name, value in cookies.items()])
        else:
            return '; '.join([f"{cookie.name}={cookie.value}" for cookie in self.cookies])

    def log_request_and_response(self, request, response, proxies=None, duration=None):
        """记录请求和响应信息，并添加到请求历史"""
        parsed_url = urlparse(request.url)
        path = parsed_url.path

        # 构建请求记录
        request_record = {
            'timestamp': time.time(),
            'method': request.method,
            'url': request.url,
            'path': path,
            'status_code': response.status_code,
            'response_url': response.url,
            'duration': round(duration, 3) if duration else None,
            'proxies': proxies,
            'redirects': len(response.history),
            'request_headers': dict(request.headers),
            'response_headers': dict(response.headers),
        }

        # 根据配置决定是否记录响应内容
        current_type = response.headers.get('content-type', "").lower()
        if self.print_log:
            # 限制响应内容长度避免内存问题
            max_text_length = 500
            try:
                if len(response.text) > max_text_length:
                    request_record['response_text'] = response.text[:max_text_length] + "..."
                else:
                    request_record['response_text'] = response.text
            except Exception as e:
                request_record['response_text'] = f"获取响应文本失败: {str(e)}"

        # 添加到历史记录
        self.request_history.append(request_record)

        # 限制历史记录大小
        if len(self.request_history) > self.max_history_size:
            self.request_history.pop(0)

        # 构建日志消息
        if proxies:
            log_msg = f"请求: {path}, 方法: {request.method}, 状态码: {response.status_code}, 代理: {proxies}"
        else:
            log_msg = f"请求: {path}, 方法: {request.method}, 状态码: {response.status_code}"

        if duration:
            log_msg += f", 耗时: {round(duration, 3)}s"

        if len(response.history) > 0:
            log_msg += f", 重定向次数: {len(response.history)}"

        # 记录响应文本（如果配置允许）
        if self.print_log and not ('text/html' in current_type or "application/javascript" in current_type):
            try:
                log_msg += f", 响应内容: {response.text[:200]}..."
            except:
                log_msg += ", 无法获取响应内容"
        if self.print_log:
            logger.info(log_msg)

    def get_request_history(self, limit=None, filter_func=None):
        """获取请求历史记录

        Args:
            limit: 限制返回的记录数量
            filter_func: 过滤函数，接收记录作为参数，返回True/False

        Returns:
            过滤和限制后的请求历史记录列表
        """
        history = self.request_history

        if filter_func:
            history = [record for record in history if filter_func(record)]

        if limit and limit < len(history):
            history = history[-limit:]

        return history

    def export_request_chain(self, filepath=None, limit=None):
        """导出请求链到文件

        Args:
            filepath: 导出文件路径，默认为"request_chain_{session_id}.json"
            limit: 限制导出的记录数量

        Returns:
            导出文件的路径
        """
        if not filepath:
            filepath = f"{self.work_dir}/request_chain_{self._id}.json"

        history = self.get_request_history(limit=limit)

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)

        return filepath

    def clear_history(self):
        """清除请求历史"""
        self.request_history = []

    def _load_file_lines(self, file_path, default_values=None):
        """从文件加载行数据，如果文件不存在则返回默认值

        Args:
            file_path: 文件路径
            default_values: 如果文件不存在或为空，返回的默认值列表

        Returns:
            从文件读取的行列表，或默认值列表
        """
        if default_values is None:
            default_values = []

        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f if line.strip()]
                if lines:
                    return lines
            return default_values
        except Exception as e:
            logger.warning(f"从文件 {file_path} 加载数据时出错: {e}")
            return default_values

    def set_print_log(self, print_log):
        """设置是否记录响应文本"""
        self.print_log = print_log


if __name__ == "__main__":
    # 示例：保存和加载带有域名分组cookie的会话
    session = RequestSession()
    session.initialize_session()
    session.set_proxy(use_proxy=True, random_proxy=False)
    print(session.proxies_list)
    logger.info(session.proxies_list)

    response = session.get("https://tls.peet.ws/api/all")

    response = session.get("https://www.twitch.tv")
    response = session.get("https://google.com")
    response = session.get("https://passport.twitch.tv")
    session.export_request_chain()
    # print(response.text)

    session.save_session()

    # # 设置不同域名的cookie
    # session.cookies.set('test_cookie1', 'value1', domain='example.com')
    # session.cookies.set('test_cookie2', 'value2', domain='example.com')
    # session.cookies.set('other_cookie', 'other_value', domain='other.com')

    # # 保存会话
    # saved_path = session.save_session(_id="test_session")
    # print(f"会话已保存到: {saved_path}")

    # # 加载会话
    # saved_path = "tmp/http_session/test_session.json"
    # loaded_session = RequestSession.load_session(saved_path)

    # # 验证cookie是否按域名加载
    # print("example.com的cookies:", loaded_session.get_cookies_for_domain('example.com'))
    # print("other.com的cookies:", loaded_session.get_cookies_for_domain('other.com'))


    def get_liking_users(tweet_id):
        # 初始化新建session
        session = RequestSession()
        session.print_log = True
        session.initialize_session(random_init=True)
        session.set_proxy(use_proxy=True, random_proxy=False)

        # # 加载已有session
        # saved_path = "tmp/http_session/test_x.json"
        # session = RequestSession.load_session(saved_path)
        session.get("https://twitter.com/")

        url = f"https://api.twitter.com/2/tweets/{tweet_id}/liking_users"
        headers = {
            "Authorization": "Bearer YOUR_ACCESS_TOKEN"
        }
        response = session.get(url, headers=headers)
        # session.save_session(_id="test_x")
        session.save_session()
        if response.status_code == 200:
            return response.json()['data']
        else:
            return "Error: " + response.text


    # # 使用示例
    # tweet_id = '1234567890123456789'  # 示例推文ID
    # liking_users = get_liking_users(tweet_id)
    # print(liking_users)