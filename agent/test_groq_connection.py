"""
agent/test_groq_connection.py

One-off script: confirms GROQ_API_KEY loads correctly and the OpenAI SDK can
reach the Groq API.
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

key = os.environ.get("GROQ_API_KEY")
if not key:
    print("FAIL: GROQ_API_KEY not found in environment. Check .env exists "
          "at project root and load_dotenv() found it.")
    sys.exit(1)

try:
    from openai import OpenAI
except ImportError:
    print("FAIL: 'openai' not installed. Run: pip install openai")
    sys.exit(1)

client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=key,
)

try:
    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[{"role": "user", "content": "Reply with exactly one word: OK"}],
    )
    res_text = response.choices[0].message.content.strip()
    print(f"SUCCESS: model responded: {res_text!r}")
except Exception as e:
    print(f"FAIL: API call raised an exception: {type(e).__name__}: {e}")
    sys.exit(1)
