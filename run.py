#!/usr/bin/env python3
"""BugCopilot launcher — run this to start the app."""

import os
import sys
import subprocess
import webbrowser
import time
from pathlib import Path

def check_env():
    env_file = Path(".env")
    if not env_file.exists():
        example = Path(".env.example")
        if example.exists():
            print("⚠  No .env file found. Copying from .env.example ...")
            env_file.write_text(example.read_text())
            print("   Edit .env and add your LLM_API_KEY, then restart.\n")
        else:
            print("⚠  No .env file found. Create one from .env.example.\n")

def check_deps():
    try:
        import fastapi, uvicorn, sqlmodel, httpx, openai
    except ImportError:
        print("📦 Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed.\n")

def main():
    print("╔══════════════════════════════════════╗")
    print("║        BugCopilot  v1.0              ║")
    print("║  AI-Assisted Bug Bounty Research     ║")
    print("╚══════════════════════════════════════╝\n")

    check_env()
    check_deps()

    port = int(os.getenv("APP_PORT", "8000"))
    url = f"http://localhost:{port}"
    print(f"🚀 Starting BugCopilot at {url}\n")

    # Open browser after short delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(url)

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=port,
        reload=False,
        log_level="warning",
    )

if __name__ == "__main__":
    main()
