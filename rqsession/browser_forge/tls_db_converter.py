"""
TLS指纹数据库转换器

将 tls_fb_db/tls_json 目录下的指纹文件转换为 BrowserProfile 对象。

使用方法:
    from browser_forge.tls_db_converter import TlsDbConverter, FingerprintFilter

    # 加载所有指纹
    converter = TlsDbConverter()
    profiles = converter.load_all_profiles()

    # 按条件筛选
    chrome_profiles = converter.find_profiles(
        filter=FingerprintFilter(browser_type="chrome", tls_version="1.3")
    )

    # 随机获取一个Chrome指纹
    profile = converter.get_random_profile(browser_type="chrome")
"""
import json
import os
import re
import random
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Iterator

from .core.client import BrowserClient
from .profiles.models import (
    BrowserProfile, TlsConfig, H2Settings,
    HeaderProfile, BehaviorProfile
)


@dataclass
class FingerprintFilter:
    """指纹筛选条件"""
    browser_type: Optional[str] = None  # chrome, firefox, safari, edge, etc.
    min_version: Optional[int] = None   # 浏览器最小版本
    max_version: Optional[int] = None   # 浏览器最大版本
    tls_version: Optional[str] = None   # "1.2", "1.3"
    has_http2: Optional[bool] = None    # 是否包含HTTP/2指纹
    platform: Optional[str] = None      # windows, macos, linux, android, ios
    ja3_hash: Optional[str] = None      # 特定的JA3哈希


class TlsDbConverter:
    """
    TLS指纹数据库转换器

    TODO: 这个类负责将tls_fb_db中的原始JSON转换为可用的BrowserProfile
    """

    # Cipher suite名称到ID的映射
    # TODO: 可能需要扩展这个映射表
    CIPHER_NAME_TO_ID = {
        # TLS 1.3 ciphers
        "TLS_AES_128_GCM_SHA256": 4865,
        "TLS_AES_256_GCM_SHA384": 4866,
        "TLS_CHACHA20_POLY1305_SHA256": 4867,
        # TLS 1.2 ECDHE ciphers
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 49195,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 49199,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 49196,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 49200,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 52393,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 52392,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 49171,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 49172,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 49187,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 49191,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 49188,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 49192,
        # DHE ciphers
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 158,
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 159,
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 52394,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 103,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 107,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": 51,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": 57,
        # RSA ciphers
        "TLS_RSA_WITH_AES_128_GCM_SHA256": 156,
        "TLS_RSA_WITH_AES_256_GCM_SHA384": 157,
        "TLS_RSA_WITH_AES_128_CBC_SHA256": 60,
        "TLS_RSA_WITH_AES_256_CBC_SHA256": 61,
        "TLS_RSA_WITH_AES_128_CBC_SHA": 47,
        "TLS_RSA_WITH_AES_256_CBC_SHA": 53,
        # Special
        "TLS_EMPTY_RENEGOTIATION_INFO": 255,
    }

    # 曲线名称到ID的映射
    CURVE_NAME_TO_ID = {
        "X25519 (29)": 29,
        "X25519": 29,
        "x25519": 29,
        "P-256 (23)": 23,
        "P-256": 23,
        "secp256r1": 23,
        "P-384 (24)": 24,
        "P-384": 24,
        "secp384r1": 24,
        "P-521 (25)": 25,
        "P-521": 25,
        "secp521r1": 25,
        "X448 (30)": 30,
        "X448": 30,
        "x448": 30,
        "ffdhe2048": 256,
        "ffdhe3072": 257,
        "X25519MLKEM768 (4588)": 4588,
    }

    # 签名算法名称映射
    SIGALG_NAME_TO_ID = {
        "ecdsa_secp256r1_sha256": 0x0403,
        "ecdsa_secp384r1_sha384": 0x0503,
        "ecdsa_secp521r1_sha512": 0x0603,
        "ed25519": 0x0807,
        "ed448": 0x0808,
        "rsa_pss_pss_sha256": 0x0809,
        "rsa_pss_pss_sha384": 0x080a,
        "rsa_pss_pss_sha512": 0x080b,
        "rsa_pss_rsae_sha256": 0x0804,
        "rsa_pss_rsae_sha384": 0x0805,
        "rsa_pss_rsae_sha512": 0x0806,
        "rsa_pkcs1_sha256": 0x0401,
        "rsa_pkcs1_sha384": 0x0501,
        "rsa_pkcs1_sha512": 0x0601,
        "rsa_pkcs1_sha1": 0x0201,
        "ecdsa_sha1": 0x0203,
    }

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化转换器

        Args:
            db_path: tls_fb_db目录路径，默认使用相对路径
        """
        if db_path:
            self.db_path = Path(db_path)
        else:
            # 默认路径：当前文件所在目录下的tls_fb_db/tls_json
            self.db_path = Path(__file__).parent / "tls_fb_db" / "tls_json"

        self._cache: Dict[str, BrowserProfile] = {}

    def _list_json_files(self) -> List[Path]:
        """列出所有JSON文件"""
        if not self.db_path.exists():
            raise FileNotFoundError(f"TLS数据库目录不存在: {self.db_path}")

        return list(self.db_path.glob("*.json"))

    def _parse_user_agent(self, ua: str) -> Dict[str, Any]:
        """
        解析User-Agent字符串

        Returns:
            {
                "browser_type": "chrome"|"firefox"|"safari"|"edge"|"other",
                "browser_version": 120,
                "platform": "windows"|"macos"|"linux"|"android"|"ios"
            }
        """
        ua_lower = ua.lower()
        result = {
            "browser_type": "other",
            "browser_version": None,
            "platform": "unknown"
        }

        # 检测平台
        if "windows" in ua_lower:
            result["platform"] = "windows"
        elif "macintosh" in ua_lower or "mac os" in ua_lower:
            result["platform"] = "macos"
        elif "linux" in ua_lower and "android" not in ua_lower:
            result["platform"] = "linux"
        elif "android" in ua_lower:
            result["platform"] = "android"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            result["platform"] = "ios"

        # 检测浏览器类型和版本
        if "edg/" in ua_lower or "edge/" in ua_lower:
            result["browser_type"] = "edge"
            match = re.search(r'edg[e]?/(\d+)', ua_lower)
            if match:
                result["browser_version"] = int(match.group(1))
        elif "chrome/" in ua_lower and "chromium" not in ua_lower:
            result["browser_type"] = "chrome"
            match = re.search(r'chrome/(\d+)', ua_lower)
            if match:
                result["browser_version"] = int(match.group(1))
        elif "firefox/" in ua_lower:
            result["browser_type"] = "firefox"
            match = re.search(r'firefox/(\d+)', ua_lower)
            if match:
                result["browser_version"] = int(match.group(1))
        elif "safari/" in ua_lower and "chrome" not in ua_lower:
            result["browser_type"] = "safari"
            match = re.search(r'version/(\d+)', ua_lower)
            if match:
                result["browser_version"] = int(match.group(1))

        return result

    def _parse_tls_version(self, tls_data: Dict) -> str:
        """解析TLS版本"""
        # 检查negotiated version
        negotiated = tls_data.get("tls_version_negotiated", "")
        if negotiated == "772":
            return "1.3"
        elif negotiated == "771":
            return "1.2"
        elif negotiated == "770":
            return "1.1"

        # 从supported_versions扩展中获取
        extensions = tls_data.get("extensions", [])
        for ext in extensions:
            if ext.get("name", "").startswith("supported_versions"):
                versions = ext.get("versions", [])
                if "TLS 1.3" in str(versions):
                    return "1.3"
                elif "TLS 1.2" in str(versions):
                    return "1.2"

        return "1.2"  # 默认

    def _parse_ciphers(self, ciphers: List[str]) -> List[str]:
        """解析cipher suites列表"""
        result = []
        for cipher in ciphers:
            # 跳过GREASE
            if "GREASE" in cipher:
                continue
            result.append(cipher)
        return result

    def _parse_extensions(self, extensions: List[Dict]) -> List[int]:
        """
        从extensions列表中提取extension IDs

        TODO: 需要处理不同格式的extension数据
        """
        ids = []
        for ext in extensions:
            name = ext.get("name", "")

            # 跳过GREASE
            if "GREASE" in name:
                continue

            # 尝试从名称中提取ID，格式如 "server_name (0)"
            match = re.search(r'\((\d+)\)', name)
            if match:
                ids.append(int(match.group(1)))

        return ids

    def _parse_curves(self, extensions: List[Dict]) -> List[str]:
        """从extensions中提取supported_groups (curves)"""
        for ext in extensions:
            if "supported_groups" in ext.get("name", ""):
                groups = ext.get("supported_groups", [])
                # 过滤GREASE
                return [g for g in groups if "GREASE" not in g]
        return ["X25519 (29)", "P-256 (23)", "P-384 (24)"]  # 默认

    def _parse_signature_algorithms(self, extensions: List[Dict]) -> List[str]:
        """从extensions中提取signature_algorithms"""
        for ext in extensions:
            if "signature_algorithms" in ext.get("name", ""):
                return ext.get("signature_algorithms", [])
        return []

    def _parse_h2_settings(self, http2_data: Optional[Dict]) -> H2Settings:
        """解析HTTP/2设置"""
        if not http2_data:
            return H2Settings()

        # 从sent_frames中提取SETTINGS
        sent_frames = http2_data.get("sent_frames", [])
        settings = {}

        for frame in sent_frames:
            if frame.get("frame_type") == "SETTINGS":
                for setting in frame.get("settings", []):
                    if "HEADER_TABLE_SIZE" in setting:
                        match = re.search(r'= (\d+)', setting)
                        if match:
                            settings["header_table_size"] = int(match.group(1))
                    elif "ENABLE_PUSH" in setting:
                        settings["enable_push"] = "= 1" in setting
                    elif "INITIAL_WINDOW_SIZE" in setting:
                        match = re.search(r'= (\d+)', setting)
                        if match:
                            settings["initial_window_size"] = int(match.group(1))
                    elif "MAX_HEADER_LIST_SIZE" in setting:
                        match = re.search(r'= (\d+)', setting)
                        if match:
                            settings["max_header_list_size"] = int(match.group(1))
                    elif "MAX_FRAME_SIZE" in setting:
                        match = re.search(r'= (\d+)', setting)
                        if match:
                            settings["max_frame_size"] = int(match.group(1))
                    elif "MAX_CONCURRENT_STREAMS" in setting:
                        match = re.search(r'= (\d+)', setting)
                        if match:
                            settings["max_concurrent_streams"] = int(match.group(1))

        return H2Settings(**settings)

    def _parse_headers(self, http_data: Optional[Dict], http2_data: Optional[Dict]) -> HeaderProfile:
        """解析HTTP头部"""
        headers = {}

        # 从HTTP/1.1数据中提取
        if http_data:
            for header_line in http_data.get("headers", []):
                if ": " in header_line:
                    key, value = header_line.split(": ", 1)
                    headers[key.lower()] = value

        # 从HTTP/2数据中提取
        if http2_data:
            for frame in http2_data.get("sent_frames", []):
                if frame.get("frame_type") == "HEADERS":
                    for header_line in frame.get("headers", []):
                        if ": " in header_line and not header_line.startswith(":"):
                            key, value = header_line.split(": ", 1)
                            # 去除转义
                            value = value.replace('\\"', '"').strip('"')
                            headers[key.lower()] = value

        return HeaderProfile(
            accept=headers.get("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            accept_encoding=headers.get("accept-encoding", "gzip, deflate, br"),
            accept_language=headers.get("accept-language", "en-US,en;q=0.9"),
            cache_control=headers.get("cache-control"),
            sec_ch_ua=headers.get("sec-ch-ua"),
            sec_ch_ua_mobile=headers.get("sec-ch-ua-mobile"),
            sec_ch_ua_platform=headers.get("sec-ch-ua-platform"),
            sec_fetch_dest=headers.get("sec-fetch-dest"),
            sec_fetch_mode=headers.get("sec-fetch-mode"),
            sec_fetch_site=headers.get("sec-fetch-site"),
            sec_fetch_user=headers.get("sec-fetch-user"),
            upgrade_insecure_requests=headers.get("upgrade-insecure-requests"),
        )

    def convert_json_to_profile(self, json_data: Dict) -> BrowserProfile:
        """
        将单个JSON数据转换为BrowserProfile

        Args:
            json_data: 从tls_fb_db加载的原始JSON数据

        Returns:
            BrowserProfile对象
        """
        tls_data = json_data.get("tls", {})
        http1_data = json_data.get("http1")
        http2_data = json_data.get("http2")

        user_agent = json_data.get("user_agent", "")
        ua_info = self._parse_user_agent(user_agent)

        # 生成profile名称
        browser_type = ua_info["browser_type"]
        browser_version = ua_info["browser_version"] or "unknown"
        platform = ua_info["platform"]
        name = f"{browser_type}_{browser_version}_{platform}"

        # 解析TLS配置
        tls_version = self._parse_tls_version(tls_data)
        extensions = tls_data.get("extensions", [])

        tls_config = TlsConfig(
            # TODO: min_version设为1.2以兼容更多服务器
            min_version="1.2",
            max_version=tls_version,
            cipher_suites=self._parse_ciphers(tls_data.get("ciphers", [])),
            extensions=self._parse_extensions(extensions),
            curves=self._parse_curves(extensions),
            signature_algorithms=self._parse_signature_algorithms(extensions),
            alpn_protocols=["h2", "http/1.1"] if http2_data else ["http/1.1"],
        )

        # 解析HTTP/2设置
        h2_settings = self._parse_h2_settings(http2_data)

        # 解析头部
        headers = self._parse_headers(http1_data, http2_data)

        # 创建profile
        return BrowserProfile(
            name=name,
            user_agent=user_agent,
            tls_config=tls_config,
            h2_settings=h2_settings,
            headers=headers,
            behavior=BehaviorProfile(),
            ja3_fingerprint=tls_data.get("ja3"),
            ja4_fingerprint=tls_data.get("ja4"),
        )

    def load_profile_from_file(self, filepath: str) -> BrowserProfile:
        """
        从单个JSON文件加载BrowserProfile

        Args:
            filepath: JSON文件路径

        Returns:
            BrowserProfile对象
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return self.convert_json_to_profile(data)

    def load_all_profiles(self, use_cache: bool = True) -> List[BrowserProfile]:
        """
        加载所有指纹为BrowserProfile

        Args:
            use_cache: 是否使用缓存

        Returns:
            BrowserProfile列表
        """
        if use_cache and self._cache:
            return list(self._cache.values())

        profiles = []
        for filepath in self._list_json_files():
            try:
                profile = self.load_profile_from_file(str(filepath))
                self._cache[filepath.stem] = profile
                profiles.append(profile)
            except Exception as e:
                # 跳过解析失败的文件
                print(f"Warning: 无法解析 {filepath.name}: {e}")
                continue

        return profiles

    def iter_profiles(self) -> Iterator[BrowserProfile]:
        """
        迭代器方式加载profiles（内存友好）

        Yields:
            BrowserProfile对象
        """
        for filepath in self._list_json_files():
            try:
                yield self.load_profile_from_file(str(filepath))
            except Exception:
                continue

    def find_profiles(self, filter: FingerprintFilter) -> List[BrowserProfile]:
        """
        按条件筛选指纹

        Args:
            filter: 筛选条件

        Returns:
            符合条件的BrowserProfile列表
        """
        results = []

        for profile in self.iter_profiles():
            ua_info = self._parse_user_agent(profile.user_agent)

            # 浏览器类型筛选
            if filter.browser_type:
                if ua_info["browser_type"] != filter.browser_type.lower():
                    continue

            # 版本筛选
            if filter.min_version and ua_info["browser_version"]:
                if ua_info["browser_version"] < filter.min_version:
                    continue

            if filter.max_version and ua_info["browser_version"]:
                if ua_info["browser_version"] > filter.max_version:
                    continue

            # TLS版本筛选
            if filter.tls_version:
                if profile.tls_config.max_version != filter.tls_version:
                    continue

            # HTTP/2筛选
            if filter.has_http2 is not None:
                has_h2 = "h2" in profile.tls_config.alpn_protocols
                if has_h2 != filter.has_http2:
                    continue

            # 平台筛选
            if filter.platform:
                if ua_info["platform"] != filter.platform.lower():
                    continue

            # JA3哈希筛选
            if filter.ja3_hash:
                # JA3哈希是ja3字符串的MD5
                import hashlib
                if profile.ja3_fingerprint:
                    actual_hash = hashlib.md5(profile.ja3_fingerprint.encode()).hexdigest()
                    if actual_hash != filter.ja3_hash:
                        continue
                else:
                    continue

            results.append(profile)

        return results

    def get_random_profile(
            self,
            browser_type: Optional[str] = None,
            platform: Optional[str] = None,
            has_http2: bool = True
    ) -> Optional[BrowserProfile]:
        """
        随机获取一个指纹

        Args:
            browser_type: 可选的浏览器类型筛选
            platform: 可选的平台筛选
            has_http2: 是否需要HTTP/2支持

        Returns:
            随机选择的BrowserProfile，如果没有符合条件的返回None
        """
        filter = FingerprintFilter(
            browser_type=browser_type,
            platform=platform,
            has_http2=has_http2
        )
        profiles = self.find_profiles(filter)

        if not profiles:
            # 放宽条件再试
            filter.has_http2 = None
            profiles = self.find_profiles(filter)

        if profiles:
            return random.choice(profiles)
        return None

    def get_profile_by_ja3_hash(self, ja3_hash: str) -> Optional[BrowserProfile]:
        """
        根据JA3哈希获取指纹

        Args:
            ja3_hash: JA3指纹的MD5哈希

        Returns:
            对应的BrowserProfile，如果不存在返回None
        """
        profiles = self.find_profiles(FingerprintFilter(ja3_hash=ja3_hash))
        return profiles[0] if profiles else None

    def export_profile_as_code(self, profile: BrowserProfile) -> str:
        """
        将BrowserProfile导出为Python代码

        Args:
            profile: BrowserProfile对象

        Returns:
            可以直接粘贴到presets.py的Python代码
        """
        # 生成变量名
        var_name = profile.name.replace("-", "_").replace(".", "_").replace(" ", "_")
        var_name = re.sub(r'[^a-zA-Z0-9_]', '', var_name)

        code = f'''
# {profile.name}
{var_name} = BrowserProfile(
    name="{profile.name}",
    user_agent="{profile.user_agent}",
    tls_config=TlsConfig(
        min_version="{profile.tls_config.min_version}",
        max_version="{profile.tls_config.max_version}",
        cipher_suites={repr(profile.tls_config.cipher_suites)},
        extensions={repr(profile.tls_config.extensions)},
        curves={repr(profile.tls_config.curves)},
        signature_algorithms={repr(profile.tls_config.signature_algorithms)},
        alpn_protocols={repr(profile.tls_config.alpn_protocols)},
    ),
    h2_settings=H2Settings(
        header_table_size={profile.h2_settings.header_table_size},
        enable_push={profile.h2_settings.enable_push},
        max_concurrent_streams={profile.h2_settings.max_concurrent_streams},
        initial_window_size={profile.h2_settings.initial_window_size},
        max_frame_size={profile.h2_settings.max_frame_size},
        max_header_list_size={profile.h2_settings.max_header_list_size},
    ),
    headers=HeaderProfile(
        accept="{profile.headers.accept}",
        accept_encoding="{profile.headers.accept_encoding}",
        accept_language="{profile.headers.accept_language}",
        cache_control={repr(profile.headers.cache_control)},
        sec_ch_ua={repr(profile.headers.sec_ch_ua)},
        sec_ch_ua_mobile={repr(profile.headers.sec_ch_ua_mobile)},
        sec_ch_ua_platform={repr(profile.headers.sec_ch_ua_platform)},
        sec_fetch_dest={repr(profile.headers.sec_fetch_dest)},
        sec_fetch_mode={repr(profile.headers.sec_fetch_mode)},
        sec_fetch_site={repr(profile.headers.sec_fetch_site)},
        sec_fetch_user={repr(profile.headers.sec_fetch_user)},
        upgrade_insecure_requests={repr(profile.headers.upgrade_insecure_requests)},
        order=[],
    ),
    behavior=BehaviorProfile(),
    ja3_fingerprint={repr(profile.ja3_fingerprint)},
    ja4_fingerprint={repr(profile.ja4_fingerprint)},
)
'''
        return code

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取指纹库统计信息

        Returns:
            统计数据字典
        """
        stats = {
            "total_count": 0,
            "by_browser": {},
            "by_platform": {},
            "by_tls_version": {},
            "with_http2": 0,
        }

        for profile in self.iter_profiles():
            stats["total_count"] += 1

            ua_info = self._parse_user_agent(profile.user_agent)

            # 按浏览器统计
            browser = ua_info["browser_type"]
            stats["by_browser"][browser] = stats["by_browser"].get(browser, 0) + 1

            # 按平台统计
            platform = ua_info["platform"]
            stats["by_platform"][platform] = stats["by_platform"].get(platform, 0) + 1

            # 按TLS版本统计
            tls_ver = profile.tls_config.max_version
            stats["by_tls_version"][tls_ver] = stats["by_tls_version"].get(tls_ver, 0) + 1

            # HTTP/2支持统计
            if "h2" in profile.tls_config.alpn_protocols:
                stats["with_http2"] += 1

        return stats


# 便捷函数
def load_random_chrome_profile() -> Optional[BrowserProfile]:
    """快速加载一个随机Chrome指纹"""
    return TlsDbConverter().get_random_profile(browser_type="chrome")


def load_random_firefox_profile() -> Optional[BrowserProfile]:
    """快速加载一个随机Firefox指纹"""
    return TlsDbConverter().get_random_profile(browser_type="firefox")


def load_profile_by_hash(ja3_hash: str) -> Optional[BrowserProfile]:
    """根据JA3哈希加载指纹"""
    return TlsDbConverter().get_profile_by_ja3_hash(ja3_hash)


if __name__ == "__main__":
    # 命令行使用示例
    import sys

    converter = TlsDbConverter()

    print("=" * 60)
    print("TLS指纹数据库转换器")
    print("=" * 60)

    # 显示统计信息
    print("\n📊 指纹库统计:")
    stats = converter.get_statistics()
    print(f"  总数: {stats['total_count']}")
    print(f"  HTTP/2支持: {stats['with_http2']}")
    print(f"\n  按浏览器:")
    for browser, count in sorted(stats["by_browser"].items(), key=lambda x: -x[1]):
        print(f"    {browser}: {count}")
    print(f"\n  按平台:")
    for platform, count in sorted(stats["by_platform"].items(), key=lambda x: -x[1]):
        print(f"    {platform}: {count}")

    # 示例：随机获取Chrome指纹
    print("\n" + "=" * 60)
    print("📱 随机Chrome指纹示例:")
    profile = converter.get_random_profile(browser_type="chrome")
    if profile:
        print(f"  名称: {profile.name}")
        print(f"  UA: {profile.user_agent[:60]}...")
        print(f"  JA3: {profile.ja3_fingerprint}")
        print(f"  TLS版本: {profile.tls_config.max_version}")

    profiles = converter.load_all_profiles()
    print("加载所有指纹库数据")

    # 按条件筛选
    chrome_profiles = converter.find_profiles(
        filter=FingerprintFilter(browser_type="chrome", tls_version="1.3")
    )

    # 随机获取一个Chrome指纹
    profile = converter.get_random_profile(browser_type="chrome")

    client = BrowserClient(
        profile
    )
    print("选用profile: {}".format(profile.name))
    #resp = client.get("https://tls.123408.xyz/")
    resp = client.get("https://tls.peet.ws/api/all")
    with open("./tls1.html", "w", encoding="utf-8") as f:
        f.write(resp.text)

