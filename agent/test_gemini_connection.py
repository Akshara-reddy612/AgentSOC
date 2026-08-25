"""
agent/test_gemini_connection.py

One-off script: confirms GEMINI_API_KEY loads correctly and the SDK can
reach the API. Not a permanent part of the pipeline — delete or move to
tests/ once Phase 3's real client wrapper exists.
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

def main():
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        print("FAIL: GEMINI_API_KEY not found in environment. Check .env exists "
              "at project root and load_dotenv() found it.")
        sys.exit(1)

    try:
        from google import genai
    except ImportError:
        print("FAIL: 'google-genai' not installed. Run: pip install google-genai")
        sys.exit(1)

    client = genai.Client(api_key=key)

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents="Reply with exactly one word: OK",
        )
        print(f"SUCCESS: model responded: {response.text.strip()!r}")
    except Exception as e:
        print(f"FAIL: API call raised an exception: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

