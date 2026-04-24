# rqsession/test_session.py
"""快速功能测试"""
import requests
from rqsession.enhanced_request_session import EnhancedRequestSession


def test_rust_backend():
    """测试Rust后端"""
    try:
        response = requests.get("http://127.0.0.1:5005/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def run_tests():
    """运行测试套件"""
    print("🧪 RequestSession Functionality Tests")
    print("=" * 40)

    # 测试基础会话
    print("1. Testing basic session...")
    try:
        session = EnhancedRequestSession(enable_tls_fingerprinting=False)
        response = session.get("https://httpbin.org/get", timeout=10)
        print(f"   ✅ Basic session: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Basic session failed: {e}")

    # 测试Rust后端
    print("2. Testing Rust backend...")
    if test_rust_backend():
        print("   ✅ Rust backend is running")

        # 测试增强会话
        try:
            session = EnhancedRequestSession(enable_tls_fingerprinting=True)
            response = session.get("https://httpbin.org/get", timeout=10)
            fingerprint = session.get_fingerprint_info()

            if fingerprint and fingerprint.ja3_hash:
                print(f"   ✅ Enhanced session with fingerprinting")
                print(f"   📝 JA3 Hash: {fingerprint.ja3_hash[:16]}...")
            else:
                print("   ⚠️ Enhanced session working, but no fingerprint data")
        except Exception as e:
            print(f"   ❌ Enhanced session failed: {e}")
    else:
        print("   ⚠️ Rust backend not running")
        print("   💡 Start with: rqsession-server")

    print("\n✨ Tests completed!")
    return 0