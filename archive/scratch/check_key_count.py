"""Check key count without printing actual values."""
import os
from dotenv import load_dotenv
load_dotenv()

keys_str = os.environ.get("GEMINI_API_KEYS", "")
if keys_str:
    keys = [k.strip() for k in keys_str.split(",") if k.strip()]
    print(f"{len(keys)} keys loaded from GEMINI_API_KEYS")
    for i, k in enumerate(keys):
        # Print only first 4 and last 4 chars for identity confirmation
        print(f"  Key index {i}: {k[:4]}...{k[-4:]} (length={len(k)})")
else:
    singular = os.environ.get("GEMINI_API_KEY", "")
    if singular:
        print(f"1 key loaded from GEMINI_API_KEY (singular)")
    else:
        print("NO KEYS FOUND")
