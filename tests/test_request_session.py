import os
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import requests
import responses

from rqsession.request_session import RequestSession


class TestRequestSession(unittest.TestCase):
    """测试 RequestSession 类的功能"""

    def setUp(self):
        """每个测试方法运行前的设置"""
        # 创建临时工作目录
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = self.temp_dir.name

        # 创建基本配置
        self.config = {
            "host": "127.0.0.1",
            "port": "8888",
            "enabled": False,
            "random_proxy": False,
            "print_log": False,
            "proxy_file": None,
            "max_history_size": 10,
            "auto_headers": False,
            "user_agents_file": None,
            "languages_file": None,
            "work_path": self.work_dir
        }

        # 初始化 RequestSession
        self.session = RequestSession(config=self.config)

    def tearDown(self):
        """每个测试方法运行后的清理"""
        self.temp_dir.cleanup()

    def test_initialization(self):
        """测试初始化参数是否正确设置"""
        self.assertEqual(self.session.proxies_list, ["http://127.0.0.1:8888"])
        self.assertFalse(self.session.use_proxy)
        self.assertFalse(self.session.random_proxy)
        self.assertFalse(self.session.print_log)
        self.assertEqual(self.session.max_history_size, 10)
        self.assertFalse(self.session.auto_headers)
        self.assertEqual(self.session.work_dir, self.work_dir)

    def test_set_proxy(self):
        """测试代理设置"""
        self.session.set_proxy(use_proxy=True, random_proxy=True)
        self.assertTrue(self.session.use_proxy)
        self.assertTrue(self.session.random_proxy)

    def test_get_proxy(self):
        """测试获取代理"""
        # 默认代理
        self.assertEqual(self.session.get_proxy(), "http://127.0.0.1:8888")

        # 使用自定义代理方法
        proxy_method = mock.MagicMock(return_value="http://custom.proxy:1234")
        session = RequestSession(proxy_method=proxy_method, config=self.config)
        self.assertEqual(session.get_proxy(), "http://custom.proxy:1234")

        # 多个代理随机选择
        proxies = ["http://proxy1:8080", "http://proxy2:8080"]
        session = RequestSession(config=self.config)
        session.proxies_list = proxies
        session.random_proxy = True
        proxy = session.get_proxy()
        self.assertIn(proxy, proxies)

    @responses.activate
    def test_send_request_with_auto_headers(self):
        """测试发送请求时自动设置头信息"""
        # 设置模拟响应
        responses.add(
            responses.GET,
            "https://example.com/test",
            json={"status": "ok"},
            status=200
        )

        # 创建自动设置头部的会话
        session = RequestSession(config={**self.config, "auto_headers": True})

        # 发送请求
        response = session.get("https://example.com/test")

        # 验证响应
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

        # 验证请求历史
        self.assertEqual(len(session.request_history), 1)
        self.assertEqual(session.request_history[0]["method"], "GET")
        self.assertEqual(session.request_history[0]["url"], "https://example.com/test")

        # 验证自动设置的标头
        last_request = responses.calls[0].request
        self.assertEqual(last_request.headers.get("Host"), "example.com")
        self.assertEqual(last_request.headers.get("Referer"), "https://example.com")

    def test_initialize_session(self):
        """测试会话初始化"""
        # 测试自定义头部
        custom_headers = {"User-Agent": "Custom UA", "X-Test": "Test Value"}
        self.session.initialize_session(headers=custom_headers)
        self.assertEqual(self.session.headers["User-Agent"], "Custom UA")
        self.assertEqual(self.session.headers["X-Test"], "Test Value")

        # 测试随机初始化
        with mock.patch("random.choice", return_value="Mozilla/5.0 Test"):
            self.session.initialize_session(random_init=True)
            self.assertEqual(self.session.headers["User-Agent"], "Mozilla/5.0 Test")

    def test_save_and_load_session(self):
        """测试保存和加载会话"""
        # 设置一些 cookies 和 headers
        self.session.headers.update({"X-Test": "Test Value"})
        self.session.cookies.set("test_cookie", "test_value", domain="example.com")

        # 保存会话
        save_path = self.session.save_session(_id="test_session")

        # 验证保存的文件存在
        self.assertTrue(os.path.exists(save_path))

        # 加载会话
        loaded_session = RequestSession.load_session(save_path)

        # 验证加载的会话
        self.assertEqual(loaded_session.headers.get("X-Test"), "Test Value")
        self.assertEqual(loaded_session.cookies.get("test_cookie", domain="example.com"), "test_value")

    def test_cookie_management(self):
        """测试 cookie 管理功能"""
        # 测试设置单个 cookie
        self.session.cookies.set("simple_cookie", "simple_value", domain="example.com")

        # 测试按域名获取 cookies
        domain_cookies = self.session.get_cookies_for_domain("example.com")
        self.assertEqual(domain_cookies["simple_cookie"], "simple_value")

        # 测试获取 cookie 字符串
        cookie_str = self.session.get_cookies_string(domain="example.com")
        self.assertEqual(cookie_str, "simple_cookie=simple_value")

        # 测试从字典设置 cookies
        self.session.set_cookies({"dict_cookie": "dict_value"})
        self.assertEqual(self.session.cookies.get("dict_cookie"), "dict_value")

        # 测试从字典列表设置 cookies
        cookie_list = [
            {
                "name": "list_cookie",
                "value": "list_value",
                "domain": "test.com",
                "path": "/",
                "secure": True
            }
        ]
        self.session.set_cookies(cookie_list)
        self.assertEqual(self.session.cookies.get("list_cookie", domain="test.com"), "list_value")

        # 测试从字符串设置 cookies
        self.session.set_cookies("string_cookie=string_value")
        self.assertEqual(self.session.cookies.get("string_cookie"), "string_value")

    def test_request_history(self):
        """测试请求历史记录功能"""
        # 模拟几个请求记录
        for i in range(5):
            self.session.request_history.append({
                "timestamp": 1000 + i,
                "method": "GET",
                "url": f"https://example.com/path{i}",
                "status_code": 200 if i % 2 == 0 else 404
            })

        # 测试获取所有历史
        self.assertEqual(len(self.session.get_request_history()), 5)

        # 测试限制数量
        limited_history = self.session.get_request_history(limit=2)
        self.assertEqual(len(limited_history), 2)
        self.assertEqual(limited_history[1]["url"], "https://example.com/path4")

        # 测试过滤功能
        successful_requests = self.session.get_request_history(
            filter_func=lambda r: r["status_code"] == 200
        )
        self.assertEqual(len(successful_requests), 3)

        # 测试导出请求链
        export_path = self.session.export_request_chain()
        self.assertTrue(os.path.exists(export_path))

        # 验证导出文件内容
        with open(export_path, 'r', encoding='utf-8') as f:
            exported_data = json.load(f)
            self.assertEqual(len(exported_data), 5)

        # 测试清除历史
        self.session.clear_history()
        self.assertEqual(len(self.session.request_history), 0)

    def test_max_history_size(self):
        """测试历史记录大小限制"""
        # 设置最大历史记录大小为 5
        self.session.max_history_size = 5

        # 添加 10 个记录
        for i in range(10):
            self.session.request_history.append({
                "timestamp": 1000 + i,
                "method": "GET",
                "url": f"https://example.com/path{i}",
                "status_code": 200
            })

        # 验证只保留了最新的 5 个
        self.assertEqual(len(self.session.request_history), 5)
        self.assertEqual(self.session.request_history[0]["url"], "https://example.com/path5")
        self.assertEqual(self.session.request_history[4]["url"], "https://example.com/path9")

    @responses.activate
    def test_log_request_and_response(self):
        """测试请求和响应日志记录"""
        # 设置模拟响应
        responses.add(
            responses.GET,
            "https://example.com/log_test",
            body="Test Response",
            status=200,
            adding_headers={"Content-Type": "text/plain"}
        )

        # 启用日志记录
        self.session.set_print_log(True)

        # 发送请求
        with mock.patch("rqsession.request_session.logger.info") as mock_logger:
            response = self.session.get("https://example.com/log_test")

            # 验证记录了日志
            mock_logger.assert_called()
            log_msg = mock_logger.call_args[0][0]
            self.assertIn("请求: /log_test", log_msg)
            self.assertIn("方法: GET", log_msg)
            self.assertIn("状态码: 200", log_msg)

        # 验证请求历史中包含响应文本
        self.assertEqual(len(self.session.request_history), 1)
        self.assertIn("response_text", self.session.request_history[0])
        self.assertEqual(self.session.request_history[0]["response_text"], "Test Response")

    @mock.patch("os.path.exists")
    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_load_file_lines(self, mock_open, mock_exists):
        """测试从文件加载行数据"""
        # 模拟文件存在
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "line1\n", "line2\n", "line3\n"
        ]

        # 调用方法
        lines = self.session._load_file_lines("test_file.txt", ["default"])

        # 验证结果
        self.assertEqual(lines, ["line1", "line2", "line3"])

        # 模拟文件不存在
        mock_exists.return_value = False
        lines = self.session._load_file_lines("test_file.txt", ["default"])
        self.assertEqual(lines, ["default"])


if __name__ == '__main__':
    unittest.main()