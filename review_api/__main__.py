"""
Serve the review API locally:

    python -m review_api --case-store <path to cases.sqlite> [--host 127.0.0.1] [--port 8000]

Analyst tokens come from AGENTSOC_ANALYST_TOKENS (environment or .env):
"alice:<token>,bob:<token>", each token at least 24 random characters, e.g.
    python -c "import secrets; print(secrets.token_urlsafe(32))"
The server binds to 127.0.0.1 by default; for remote use put it behind a
reverse proxy with TLS.  API reference: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentSOC review API (analyst review loop)")
    ap.add_argument("--case-store", required=True, help="the SOC loop's case store (cases.sqlite)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    if not Path(args.case_store).exists():
        sys.exit(f"no case store at {args.case_store} (the SOC loop creates it)")

    import uvicorn
    from dotenv import load_dotenv

    from perception.case_store import CaseStore
    from review_api.app import create_app, load_tokens

    load_dotenv()
    try:
        tokens = load_tokens(os.environ.get("AGENTSOC_ANALYST_TOKENS", ""))
    except ValueError as e:
        sys.exit(str(e))
    uvicorn.run(create_app(CaseStore(args.case_store), tokens), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
