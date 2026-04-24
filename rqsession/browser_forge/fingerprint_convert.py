"""
浏览器指纹收集工具
用于从真实浏览器中提取完整的指纹信息
"""
import json
import sys
from pathlib import Path

# 添加browser_forge到路径
sys.path.insert(0, '/mnt/user-data/outputs')

from browser_forge.profiles.models import (
    BrowserProfile, TlsConfig, H2Settings,
    HeaderProfile, BehaviorProfile
)


class BrowserFingerprintCollector:
    """浏览器指纹收集器"""

    # TLS检测API
    DETECTION_APIS = [
        "https://tls.peet.ws/api/all",
        "https://tls.browserleaks.com/json",
        "https://www.howsmyssl.com/a/check",
    ]

    @staticmethod
    def load_from_tls_peet(json_file: str) -> BrowserProfile:
        """
        从 tls.peet.ws 的JSON数据生成BrowserProfile

        使用步骤：
        1. 在真机浏览器访问 https://tls.peet.ws/api/all
        2. 复制整个JSON响应
        3. 保存为文件（如 chrome_real.json）
        4. 运行此函数

        Args:
            json_file: JSON文件路径

        Returns:
            BrowserProfile对象
        """
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 提取TLS信息
        tls_data = data.get('tls', {})
        http_data = data.get('http', {})
        http2_data = data.get('http2', {})

        # 提取user agent
        user_agent = http_data.get('headers', {}).get('User-Agent', '')

        # 生成浏览器名称
        browser_name = BrowserFingerprintCollector._generate_browser_name(user_agent)

        # 构建TLS配置
        tls_config = TlsConfig(
            min_version=BrowserFingerprintCollector._parse_tls_version(
                tls_data.get('version', 'TLS 1.3'), is_min=True
            ),
            max_version=BrowserFingerprintCollector._parse_tls_version(
                tls_data.get('version', 'TLS 1.3'), is_min=False
            ),
            cipher_suites=BrowserFingerprintCollector._parse_ciphers(
                tls_data.get('ciphers', [])
            ),
            extensions=BrowserFingerprintCollector._parse_extensions(
                tls_data.get('extensions', [])
            ),
            curves=BrowserFingerprintCollector._parse_curves(
                tls_data.get('supported_groups', [])
            ),
            signature_algorithms=BrowserFingerprintCollector._parse_sigalgs(
                tls_data.get('signature_algorithms', [])
            ),
            alpn_protocols=tls_data.get('alpn', ['h2', 'http/1.1']),
        )

        # 构建HTTP/2配置
        h2_settings = H2Settings(
            header_table_size=http2_data.get('settings', {}).get('SETTINGS_HEADER_TABLE_SIZE', 65536),
            enable_push=http2_data.get('settings', {}).get('SETTINGS_ENABLE_PUSH', 0) == 1,
            max_concurrent_streams=http2_data.get('settings', {}).get('SETTINGS_MAX_CONCURRENT_STREAMS', 1000),
            initial_window_size=http2_data.get('settings', {}).get('SETTINGS_INITIAL_WINDOW_SIZE', 6291456),
            max_frame_size=http2_data.get('settings', {}).get('SETTINGS_MAX_FRAME_SIZE', 16777215),
            max_header_list_size=http2_data.get('settings', {}).get('SETTINGS_MAX_HEADER_LIST_SIZE'),
        )

        # 构建Header配置
        headers = http_data.get('headers', {})
        header_profile = HeaderProfile(
            accept=headers.get('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            accept_encoding=headers.get('Accept-Encoding', 'gzip, deflate, br'),
            accept_language=headers.get('Accept-Language', 'en-US,en;q=0.9'),
            cache_control=headers.get('Cache-Control'),
            sec_ch_ua=headers.get('Sec-Ch-Ua'),
            sec_ch_ua_mobile=headers.get('Sec-Ch-Ua-Mobile'),
            sec_ch_ua_platform=headers.get('Sec-Ch-Ua-Platform'),
            sec_fetch_dest=headers.get('Sec-Fetch-Dest'),
            sec_fetch_mode=headers.get('Sec-Fetch-Mode'),
            sec_fetch_site=headers.get('Sec-Fetch-Site'),
            sec_fetch_user=headers.get('Sec-Fetch-User'),
            upgrade_insecure_requests=headers.get('Upgrade-Insecure-Requests'),
            order=BrowserFingerprintCollector._extract_header_order(headers),
        )

        # 默认行为配置
        behavior = BehaviorProfile()

        # 创建完整profile
        profile = BrowserProfile(
            name=browser_name,
            user_agent=user_agent,
            tls_config=tls_config,
            h2_settings=h2_settings,
            headers=header_profile,
            behavior=behavior,
            ja3_fingerprint=tls_data.get('ja3'),
            ja4_fingerprint=tls_data.get('ja4'),
        )

        return profile

    @staticmethod
    def _generate_browser_name(user_agent: str) -> str:
        """从User-Agent生成浏览器名称"""
        ua_lower = user_agent.lower()

        # 检测浏览器类型和版本
        if 'chrome' in ua_lower and 'edg' not in ua_lower:
            # Chrome
            import re
            match = re.search(r'chrome/(\d+)', ua_lower)
            if match:
                version = match.group(1)
                if 'windows' in ua_lower:
                    return f"chrome_{version}_windows"
                elif 'mac' in ua_lower:
                    return f"chrome_{version}_macos"
                elif 'linux' in ua_lower:
                    return f"chrome_{version}_linux"
            return "chrome_custom"

        elif 'firefox' in ua_lower:
            # Firefox
            import re
            match = re.search(r'firefox/(\d+)', ua_lower)
            if match:
                version = match.group(1)
                if 'windows' in ua_lower:
                    return f"firefox_{version}_windows"
                elif 'mac' in ua_lower:
                    return f"firefox_{version}_macos"
            return "firefox_custom"

        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            # Safari
            import re
            match = re.search(r'version/(\d+)', ua_lower)
            if match:
                version = match.group(1)
                return f"safari_{version}_macos"
            return "safari_custom"

        elif 'edg' in ua_lower:
            # Edge
            import re
            match = re.search(r'edg/(\d+)', ua_lower)
            if match:
                version = match.group(1)
                return f"edge_{version}_windows"
            return "edge_custom"

        return "custom_browser"

    @staticmethod
    def _parse_tls_version(version_str: str, is_min: bool = False) -> str:
        """解析TLS版本"""
        if '1.3' in version_str or 'TLSv1.3' in version_str:
            return "1.3"
        elif '1.2' in version_str or 'TLSv1.2' in version_str:
            return "1.2"
        elif '1.1' in version_str:
            return "1.1"
        else:
            return "1.2" if is_min else "1.3"

    @staticmethod
    def _parse_ciphers(ciphers: list) -> list:
        """解析cipher suites"""
        # tls.peet.ws返回的是cipher名称列表
        if not ciphers:
            return []

        # 如果是字符串列表，直接返回
        if isinstance(ciphers[0], str):
            return ciphers

        # 如果是字典，提取name字段
        return [c.get('name', c) if isinstance(c, dict) else c for c in ciphers]

    @staticmethod
    def _parse_extensions(extensions: list) -> list:
        """解析TLS extensions"""
        if not extensions:
            return []

        # 如果是整数列表，直接返回
        if isinstance(extensions[0], int):
            return extensions

        # 如果是字典，提取id
        result = []
        for ext in extensions:
            if isinstance(ext, dict):
                ext_id = ext.get('id') or ext.get('type')
                if ext_id is not None:
                    result.append(int(ext_id))
            elif isinstance(ext, int):
                result.append(ext)

        return result

    @staticmethod
    def _parse_curves(curves: list) -> list:
        """解析supported groups (curves)"""
        if not curves:
            return ["x25519", "secp256r1", "secp384r1"]

        # 映射常见的curve ID到名称
        CURVE_MAP = {
            29: "x25519",
            23: "secp256r1",
            24: "secp384r1",
            25: "secp521r1",
            256: "ffdhe2048",
            257: "ffdhe3072",
        }

        result = []
        for curve in curves:
            if isinstance(curve, str):
                result.append(curve)
            elif isinstance(curve, int):
                result.append(CURVE_MAP.get(curve, f"curve_{curve}"))
            elif isinstance(curve, dict):
                name = curve.get('name') or CURVE_MAP.get(curve.get('id'))
                if name:
                    result.append(name)

        return result

    @staticmethod
    def _parse_sigalgs(sigalgs: list) -> list:
        """解析signature algorithms"""
        if not sigalgs:
            return [
                "rsa_pss_rsae_sha256",
                "ecdsa_secp256r1_sha256",
                "rsa_pkcs1_sha256",
            ]

        # 如果是字符串列表，直接返回
        if isinstance(sigalgs[0], str):
            return sigalgs

        # 如果是字典，提取name
        return [s.get('name', s) if isinstance(s, dict) else s for s in sigalgs]

    @staticmethod
    def _extract_header_order(headers: dict) -> list:
        """提取header顺序"""
        # 常见的header顺序
        common_order = [
            "cache-control",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
        ]

        # 返回存在的headers
        return [h for h in common_order if headers.get(h.title().replace('-', '-'))]

    @staticmethod
    def save_profile_to_presets(profile: BrowserProfile, output_file: str = None):
        """
        将profile保存为Python代码格式，可以直接添加到presets.py

        Args:
            profile: BrowserProfile对象
            output_file: 输出文件路径（可选）
        """
        code = f'''
# {profile.name}
{profile.name.replace('-', '_').replace('.', '_')} = BrowserProfile(
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
        order={repr(profile.headers.order)},
    ),
    behavior=BehaviorProfile(
        connection_timeout={profile.behavior.connection_timeout},
        read_timeout={profile.behavior.read_timeout},
        max_connections_per_host={profile.behavior.max_connections_per_host},
        tcp_nodelay={profile.behavior.tcp_nodelay},
        tcp_keepalive={profile.behavior.tcp_keepalive},
        gzip={profile.behavior.gzip},
        brotli={profile.behavior.brotli},
        deflate={profile.behavior.deflate},
    ),
    ja3_fingerprint={repr(profile.ja3_fingerprint)},
    ja4_fingerprint={repr(profile.ja4_fingerprint)},
)
'''

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(code)
            print(f"✓ Profile saved to {output_file}")
        else:
            print(code)

        return code


def main():
    """使用示例"""
    print("=" * 60)
    print("Browser Fingerprint Collector")
    print("=" * 60)

    print("\n📋 使用步骤：")
    print("1. 在真机浏览器访问 https://tls.peet.ws/api/all")
    print("2. 复制整个JSON响应")
    print("3. 保存为文件（如 my_browser.json）")
    print("4. 运行此脚本")

    # 示例：从文件加载
    import sys
    if len(sys.argv) >= 0:
        # json_file = sys.argv[1]
        # output_file = sys.argv[2] if len(sys.argv) > 2 else None
        json_file = r"fp_collector.json"
        json_file = r"tor_firefox_collector.json"
        output_file = r"tor_fp_collector-output.txt"

        print(f"\n📂 读取文件: {json_file}")

        try:
            collector = BrowserFingerprintCollector()
            profile = collector.load_from_tls_peet(json_file)

            print(f"\n✓ 成功生成profile: {profile.name}")
            print(f"  User-Agent: {profile.user_agent[:50]}...")
            print(f"  JA3 Hash: {profile.ja3_fingerprint}")
            print(f"  Ciphers: {len(profile.tls_config.cipher_suites)} suites")

            # 保存为Python代码
            if output_file:
                collector.save_profile_to_presets(profile, output_file)
                print(f"\n✓ 代码已保存到: {output_file}")
                print("  可以复制到 presets.py 中使用")
            else:
                print("\n" + "=" * 60)
                print("生成的Python代码：")
                print("=" * 60)
                collector.save_profile_to_presets(profile)

            # 保存为JSON（用于测试）
            json_output = json_file.replace('.json', '_profile.json')
            profile.to_json(json_output)
            print(f"\n✓ JSON配置已保存到: {json_output}")

        except FileNotFoundError:
            print(f"\n✗ 文件不存在: {json_file}")
            print("  请先保存浏览器指纹JSON数据")
        except Exception as e:
            print(f"\n✗ 错误: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n用法:")
        print("  python fingerprint_collector.py <json_file> [output_file]")
        print("\n示例:")
        print("  python fingerprint_collector.py my_chrome.json chrome_profile.py")


if __name__ == "__main__":
    main()