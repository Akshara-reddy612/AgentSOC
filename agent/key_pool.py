"""
agent/key_pool.py

Manages a rotating pool of API keys for rate limit mitigation.
"""
from __future__ import annotations

import os
from dotenv import load_dotenv


class KeyPool:
    def __init__(self, keys: list[str]):
        self.keys = [k.strip() for k in keys if k.strip()]
        self.index = 0
        self.tried_count = 0

    def current(self) -> str:
        if not self.keys:
            raise ValueError("Key pool is empty")
        return self.keys[self.index]

    def current_index(self) -> int:
        return self.index

    def rotate(self) -> int:
        if not self.keys:
            return 0
        self.index = (self.index + 1) % len(self.keys)
        self.tried_count += 1
        return self.index

    def reset_tried(self) -> None:
        self.tried_count = 0

    def exhausted_this_round(self) -> bool:
        return self.tried_count >= len(self.keys)


def load_gemini_pool() -> KeyPool:
    load_dotenv()
    keys_str = os.environ.get("GEMINI_API_KEYS")
    if keys_str:
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
    else:
        singular = os.environ.get("GEMINI_API_KEY")
        keys = [singular] if singular else []
    return KeyPool(keys)


def load_groq_pool() -> KeyPool:
    load_dotenv()
    keys_str = os.environ.get("GROQ_API_KEYS")
    if keys_str:
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
    else:
        singular = os.environ.get("GROQ_API_KEY")
        keys = [singular] if singular else []
    return KeyPool(keys)
