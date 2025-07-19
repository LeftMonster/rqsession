from .request_session import RequestSession
from .config_util import get_config_ini

# rqsession/__init__.py
"""
RequestSession - 高级HTTP请求会话管理库
支持代理管理、会话持久化、TLS指纹伪造和反检测
"""

__version__ = "0.3.0"
__author__ = "Sherlock"
__email__ = "zhzhsgg@gmail.com"

from .request_session import RequestSession
from .enhanced_request_session import EnhancedRequestSession

__all__ = [
    'RequestSession',
    'EnhancedRequestSession',
]

# 默认导出增强版作为主要接口
RqSession = EnhancedRequestSession