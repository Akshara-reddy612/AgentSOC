"""
tools/ui_check.py

Look at the demo frontend the way a person would (M5 check, 2026-10-19): drive a
headless Edge / Chrome over the DevTools protocol with its own temporary profile,
sign in, visit pages, optionally click buttons by their text, save full-page
screenshots and print any JavaScript errors.

    python tools/ui_check.py OUT_DIR "PAGES" PASSWORD_FILE [USERNAME] [APP_URL] [BROWSER_EXE]
    PAGES: comma-separated, each "path" or "path|Button text;Other button"
    e.g.  python tools/ui_check.py shots "/,/cases/case-20|Claim;malicious,/knowledge" pw.txt demo-admin

In Git Bash set MSYS_NO_PATHCONV=1 so "/" is not rewritten into a Windows path.
The password is read from a file and never printed.
"""
import base64
import itertools
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

USER = sys.argv[4] if len(sys.argv) > 4 else "demo-admin"
APP = sys.argv[5] if len(sys.argv) > 5 else "http://127.0.0.1:8000"
EDGE = sys.argv[6] if len(sys.argv) > 6 else r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
OUT = Path(sys.argv[1])
PAGES = [p.split("|") for p in sys.argv[2].split(",")]
PW = Path(sys.argv[3]).read_text().strip()
OUT.mkdir(parents=True, exist_ok=True)
profile = tempfile.mkdtemp(prefix="edge-shoot-")
proc = subprocess.Popen([EDGE, "--headless=new", "--remote-debugging-port=9333", f"--user-data-dir={profile}",
                         "--window-size=1440,1000", "--disable-gpu", "--no-first-run", "about:blank"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            targets = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json"))
            page = next(t for t in targets if t["type"] == "page")
            break
        except Exception:
            time.sleep(0.2)
    ws = connect(page["webSocketDebuggerUrl"], max_size=50_000_000)
    ids = itertools.count(1)
    errors = []

    def cmd(method, **params):
        i = next(ids)
        ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            m = json.loads(ws.recv())
            if m.get("method") == "Runtime.exceptionThrown":
                errors.append(m["params"]["exceptionDetails"].get("exception", {}).get("description", "exception")[:300])
            elif m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] in ("error", "warning"):
                errors.append(" ".join(str(a.get("value", a.get("description", ""))) for a in m["params"]["args"])[:300])
            elif m.get("method") == "Log.entryAdded" and m["params"]["entry"]["level"] == "error":
                errors.append(m["params"]["entry"].get("text", "")[:300])
            if m.get("id") == i:
                return m.get("result", {})

    def settle(seconds):
        end = time.time() + seconds
        while time.time() < end:
            cmd("Runtime.evaluate", expression="1")
            time.sleep(0.25)

    cmd("Page.enable"); cmd("Runtime.enable"); cmd("Log.enable")
    cmd("Emulation.setDeviceMetricsOverride", width=1440, height=1000, deviceScaleFactor=1, mobile=False)
    cmd("Page.navigate", url=APP + "/")
    settle(2)
    login = ("fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},"
             f"body:JSON.stringify({{username:{json.dumps(USER)},password:{json.dumps(PW)}}})}})"
             ".then(r=>r.json()).then(j=>{sessionStorage.setItem('agentsoc.token', j.token); return !!j.token})")
    ok = cmd("Runtime.evaluate", expression=login, awaitPromise=True)
    print("signed in:", ok.get("result", {}).get("value"))
    for item in PAGES:
        path, clicks = item[0], (item[1].split(";") if len(item) > 1 else [])
        errors.clear()
        cmd("Page.navigate", url=APP + path)
        settle(4)
        for label in clicks:
            js = ("(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === "
                  + json.dumps(label) + " && !x.disabled); if (!b) return 'missing'; b.click(); return 'clicked'; })()")
            r = cmd("Runtime.evaluate", expression=js)
            print(f"   click {label!r}: {r.get('result', {}).get('value')}")
            settle(3)
        metrics = cmd("Page.getLayoutMetrics")
        size = metrics["cssContentSize"]
        h = max(min(int(size["height"]), 6000), 1000)
        # a viewport as tall as the page (capturing beyond the viewport shifted fixed layouts)
        cmd("Emulation.setDeviceMetricsOverride", width=1440, height=h, deviceScaleFactor=1, mobile=False)
        settle(1)
        shot = cmd("Page.captureScreenshot", format="png")
        cmd("Emulation.setDeviceMetricsOverride", width=1440, height=1000, deviceScaleFactor=1, mobile=False)
        name = (path.strip("/").replace("/", "_") or "live") + ".png"
        (OUT / name).write_bytes(base64.b64decode(shot["data"]))
        print(f"{path:22s} -> {name}  height {h}px  js errors: {len(errors)}")
        for e in errors[:6]:
            print("    ", e)
    ws.close()
finally:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    time.sleep(1)
    shutil.rmtree(profile, ignore_errors=True)
