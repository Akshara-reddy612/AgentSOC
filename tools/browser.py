"""
tools/browser.py

A small headless-browser driver for looking at the console the way a person
would: Edge or Chrome over the DevTools protocol, with its own temporary
profile.  Sign in through the API, open pages, click buttons by their text,
read the page, save screenshots, and collect JavaScript errors.

Used by tools/ui_check.py (screenshots) and tools/e2e_check.py (the
end-to-end check).  Needs the `websockets` package (already in the
environment for the server) and an installed Edge, Chrome or Chromium.
"""
from __future__ import annotations

import base64
import itertools
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from websockets.sync.client import connect

CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]


def find_browser(explicit: str | None = None) -> str:
    """Edge / Chrome / Chromium: the given path, $BROWSER, a usual install path, or one on PATH."""
    for c in (explicit, os.environ.get("BROWSER"), *CANDIDATES):
        if c and Path(c).exists():
            return c
    for name in ("msedge", "google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit("no Edge / Chrome / Chromium found: pass its path (or set BROWSER)")


class Browser:
    """One headless browser page. Use as a context manager."""

    def __init__(self, app: str, exe: str | None = None, port: int = 9333, width: int = 1440, height: int = 1000) -> None:
        self.app, self.width, self.height = app.rstrip("/"), width, height
        self.errors: list[str] = []
        self._ids = itertools.count(1)
        self._profile = tempfile.mkdtemp(prefix="agentsoc-browser-")
        self._proc = subprocess.Popen(
            [find_browser(exe), "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={self._profile}",
             f"--window-size={width},{height}", "--disable-gpu", "--no-first-run", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        page = None
        for _ in range(100):
            try:
                page = next(t for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json")) if t["type"] == "page")
                break
            except Exception:
                time.sleep(0.2)
        if page is None:
            self.close()
            raise SystemExit("the browser did not start")
        self._ws = connect(page["webSocketDebuggerUrl"], max_size=50_000_000)
        for m in ("Page.enable", "Runtime.enable", "Log.enable"):
            self.cmd(m)
        self.cmd("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=False)

    def __enter__(self) -> "Browser":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._ws.close()
        except Exception:
            pass
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self._proc.pid)], capture_output=True)
        else:
            self._proc.kill()
        time.sleep(1)
        shutil.rmtree(self._profile, ignore_errors=True)

    # -- protocol ---------------------------------------------------------------------------

    def cmd(self, method: str, **params) -> dict:
        i = next(self._ids)
        self._ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            m = json.loads(self._ws.recv())
            if m.get("method") == "Runtime.exceptionThrown":
                self.errors.append(m["params"]["exceptionDetails"].get("exception", {}).get("description", "exception")[:300])
            elif m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] in ("error", "warning"):
                self.errors.append(" ".join(str(a.get("value", a.get("description", ""))) for a in m["params"]["args"])[:300])
            elif m.get("method") == "Log.entryAdded" and m["params"]["entry"]["level"] == "error":
                self.errors.append(m["params"]["entry"].get("text", "")[:300])
            if m.get("id") == i:
                return m.get("result", {})

    def eval(self, js: str, await_promise: bool = False):
        r = self.cmd("Runtime.evaluate", expression=js, awaitPromise=await_promise, returnByValue=True)
        return r.get("result", {}).get("value")

    def settle(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.eval("1")
            time.sleep(0.25)

    # -- what a user does -------------------------------------------------------------------

    def sign_in(self, user: str, password: str) -> bool:
        """Sign in through the API and keep the session token where the app keeps it."""
        self.goto("/", wait=2)
        js = ("fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},"
              f"body:JSON.stringify({{username:{json.dumps(user)},password:{json.dumps(password)}}})}})"
              ".then(r=>r.json()).then(j=>{if(j.token){sessionStorage.setItem('agentsoc.token', j.token)}; return !!j.token})")
        return bool(self.eval(js, await_promise=True))

    def api(self, path: str):
        """GET an API path with the session token (JSON), as the app would."""
        js = ("fetch('/api" + path + "',{headers:{Authorization:'Bearer '+sessionStorage.getItem('agentsoc.token')}})"
              ".then(r=>r.ok?r.json():null)")
        return self.eval(js, await_promise=True)

    def goto(self, path: str, wait: float = 4) -> None:
        self.errors.clear()
        self.cmd("Page.navigate", url=self.app + path)
        self.settle(wait)

    def click(self, label: str) -> bool:
        js = ("(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === "
              + json.dumps(label) + " && !x.disabled); if (!b) return false; b.click(); return true; })()")
        ok = bool(self.eval(js))
        self.settle(3)
        return ok

    def text(self) -> str:
        return self.eval("document.body.innerText") or ""

    def screenshot(self, path: Path, max_height: int = 6000) -> int:
        """Full-page PNG (the viewport is stretched to the page: capturing beyond it shifted fixed layouts)."""
        size = self.cmd("Page.getLayoutMetrics")["cssContentSize"]
        h = max(min(int(size["height"]), max_height), self.height)
        self.cmd("Emulation.setDeviceMetricsOverride", width=self.width, height=h, deviceScaleFactor=1, mobile=False)
        self.settle(1)
        shot = self.cmd("Page.captureScreenshot", format="png")
        self.cmd("Emulation.setDeviceMetricsOverride", width=self.width, height=self.height, deviceScaleFactor=1, mobile=False)
        Path(path).write_bytes(base64.b64decode(shot["data"]))
        return h
