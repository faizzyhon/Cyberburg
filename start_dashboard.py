#!/usr/bin/env python3
"""
Cyberburg Dashboard Launcher
Run this to open the local web dashboard on http://localhost:5000

Usage:
  python start_dashboard.py
  python start_dashboard.py --port 8080
"""

import sys
import os
import argparse
import webbrowser
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def open_browser(port: int):
    time.sleep(1.5)
    webbrowser.open(f"http://127.0.0.1:{port}")


def main():
    parser = argparse.ArgumentParser(description="Cyberburg Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    try:
        from dashboard.app import run_dashboard
    except ImportError as e:
        print(f"Error: {e}")
        print("Install dependencies: pip install flask requests beautifulsoup4")
        sys.exit(1)

    if not args.no_browser:
        t = threading.Thread(target=open_browser, args=(args.port,), daemon=True)
        t.start()

    run_dashboard(port=args.port)


if __name__ == "__main__":
    main()
