"""
tools/ui_check.py

Look at the demo frontend the way a person would (M5 check, 2026-10-19): sign in, visit pages,
optionally click buttons by their text, save full-page screenshots and print any JavaScript
errors.  The browser plumbing is tools/browser.py.

    python tools/ui_check.py OUT_DIR "PAGES" PASSWORD_FILE [USERNAME] [APP_URL] [BROWSER_EXE]
    PAGES: comma-separated, each "path" or "path|Button text;Other button"
    e.g.  python tools/ui_check.py shots "/,/cases/case-20|Claim;malicious,/knowledge" pw.txt demo-admin

In Git Bash set MSYS_NO_PATHCONV=1 so "/" is not rewritten into a Windows path.
The password is read from a file and never printed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser import Browser  # noqa: E402

USER = sys.argv[4] if len(sys.argv) > 4 else "demo-admin"
APP = sys.argv[5] if len(sys.argv) > 5 else "http://127.0.0.1:8000"
EXE = sys.argv[6] if len(sys.argv) > 6 else None
OUT = Path(sys.argv[1])
PAGES = [p.split("|") for p in sys.argv[2].split(",")]
PW = Path(sys.argv[3]).read_text().strip()
OUT.mkdir(parents=True, exist_ok=True)

with Browser(APP, EXE) as b:
    print("signed in:", b.sign_in(USER, PW))
    for item in PAGES:
        path, clicks = item[0], (item[1].split(";") if len(item) > 1 else [])
        b.goto(path)
        for label in clicks:
            print(f"   click {label!r}: {'clicked' if b.click(label) else 'missing'}")
        name = (path.strip("/").replace("/", "_") or "live") + ".png"
        h = b.screenshot(OUT / name)
        print(f"{path:22s} -> {name}  height {h}px  js errors: {len(b.errors)}")
        for e in b.errors[:6]:
            print("    ", e)
