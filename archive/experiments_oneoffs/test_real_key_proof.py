"""
experiments/test_real_key_proof.py

Real key proof: each worker makes one tiny REAL request and logs the key
fingerprint (last 4 characters only) as seen INSIDE the child, next to
the parent's key_index.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.key_pool import load_gemini_pool
from experiments.run_paired_clean_eval_B_parallel import _call_with_timeout


def _real_tiny_request():
    """Make a minimal Gemini API call inside the child and return which key
    the child's pool has at index 0 (last 4 chars) and the full key list
    fingerprints."""
    from agent.key_pool import load_gemini_pool
    import google.genai as genai
    import os

    pool = load_gemini_pool()
    active_key = pool.current()
    fingerprint = active_key[-4:]

    # Actually make a tiny call to prove the key works
    client = genai.Client(api_key=active_key)
    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents="Reply with exactly one word: hello",
    )
    reply = response.text.strip()[:20]

    # Also check deduplication
    all_fps = [k[-4:] for k in pool.keys]
    unique_fps = list(dict.fromkeys(all_fps))  # preserve order, dedupe

    return {
        "child_key_last4": fingerprint,
        "child_response": reply,
        "child_all_keys_last4": all_fps,
        "child_unique_keys": unique_fps,
        "deduped": len(all_fps) == len(unique_fps),
    }


def main():
    pool = load_gemini_pool()
    print(f"Parent key pool: {len(pool.keys)} keys")
    print(f"Parent fingerprints: {[k[-4:] for k in pool.keys]}")
    print()

    for i, key in enumerate(pool.keys):
        print(f"--- Worker {i} (parent key_index={i}, parent key=...{key[-4:]}) ---")
        try:
            # _call_with_timeout returns (value, child_key_last4)
            result, _child_last4 = _call_with_timeout(
                _real_tiny_request,
                active_key=key,
                all_keys=list(pool.keys),
                timeout=30,
            )
            print(f"  Child key_last4: {result['child_key_last4']}")
            print(f"  Child response:  {result['child_response']}")
            print(f"  Child all keys:  {result['child_all_keys_last4']}")
            print(f"  Deduped:         {result['deduped']}")
            match = result["child_key_last4"] == key[-4:]
            print(f"  Key match:       {match}")
            if not match:
                print(f"  ERROR: child used key ...{result['child_key_last4']} "
                      f"but parent assigned ...{key[-4:]}")
        except Exception as exc:
            print(f"  ERROR: {type(exc).__name__}: {exc}")
        print()


if __name__ == "__main__":
    main()
