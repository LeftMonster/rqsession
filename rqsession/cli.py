# rqsession/cli.py
"""命令行工具"""
import os
import sys
import subprocess
import argparse
from pathlib import Path


def start_rust_server():
    """启动Rust后端服务"""
    print("🚀 Starting RequestSession Rust Backend Server...")

    # 查找Rust代码位置
    package_dir = Path(__file__).parent.parent
    rust_dir = package_dir / "rust"

    if not rust_dir.exists():
        print("❌ Rust backend not found. Please install with: pip install rqsession[rust]")
        return 1

    try:
        # 检查是否已构建
        target_dir = rust_dir / "target" / "release"
        binary_name = "rust_proxy_tls.exe" if os.name == "nt" else "rust_proxy_tls"
        binary_path = target_dir / binary_name

        if not binary_path.exists():
            print("🔨 Building Rust backend...")
            subprocess.run(["cargo", "build", "--release"],
                           cwd=rust_dir, check=True)

        print("✅ Starting server on http://127.0.0.1:5005")
        subprocess.run([str(binary_path)], cwd=rust_dir)

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start server: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
        return 0


def main():
    """主CLI入口"""
    parser = argparse.ArgumentParser(description="RequestSession CLI Tools")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 启动服务器命令
    server_parser = subparsers.add_parser("server", help="Start Rust backend server")

    # 测试命令
    test_parser = subparsers.add_parser("test", help="Run functionality tests")

    args = parser.parse_args()

    if args.command == "server":
        return start_rust_server()
    elif args.command == "test":
        from .test_session import run_tests
        return run_tests()
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())